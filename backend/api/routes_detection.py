"""
Routes API pour la détection en temps réel.
"""

import asyncio
import logging
import time
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List
import numpy as np

from backend.core.config import get_settings
from backend.database.connection import async_session_factory
from backend.database import repository
from backend.services import alert_service, capture_service, detection_service

logger = logging.getLogger(__name__)
settings = get_settings()

# ---- Configuration du module ----
router = APIRouter(prefix="/api/detection", tags=["Detection"])
_init_attempted = False
_capture_task: Optional[asyncio.Task] = None

# Configuration initiale de la capture (au chargement du module)
capture_service.configure_capture(
    interface=settings.capture_interface,
    buffer_size=settings.capture_buffer_size,
    flow_timeout=settings.capture_flow_timeout,
)


def ensure_detection_ready() -> bool:
    """
    Vérifie et initialise le service de détection (Lazy Loading).
    Évite de bloquer le démarrage de l'app si les modèles sont lourds.
    """
    global _init_attempted
    if not detection_service.is_ready() and not _init_attempted:
        _init_attempted = True
        detection_service.initialize()
    return detection_service.is_ready()


class DetectionRequest(BaseModel):
    """Modèle de requête pour l'endpoint /analyze."""
    features: List[float] # Vecteur de features brut
    ip_reputation: float = 0.0 # Score externe optionnel


class DetectionResponse(BaseModel):
    """Modèle de réponse standardisée pour une détection."""
    decision: str # normal, suspicious, confirmed_attack
    severity: str # low, medium, high, critical
    threat_score: float # 0.0 à 1.0
    attack_type: Optional[str] # Type d'attaque si identifié
    supervised_confidence: float # Confiance du modèle classifieur
    anomaly_score: float # Score d'anomalie normalisé
    is_anomaly: bool # True si seuil dépassé
    priority: int # 1 (critique) à 5 (info)
    reasoning: str # Explication textuelle


class CaptureInterfaceRequest(BaseModel):
    interface: str


def _build_reasoning(decision: dict) -> str:
    """Formate une explication lisible de la décision prise."""
    details = decision.get("details", {})
    return (
        f"decision={decision.get('decision', 'unknown')}; "
        f"severity={decision.get('severity', 'unknown')}; "
        f"is_attack={details.get('is_attack', False)}; "
        f"is_anomaly={details.get('is_anomaly', False)}"
    )


def _build_flow_data(flow) -> dict:
    """Convertit un objet Flow interne en dictionnaire pour la DB."""
    flow_dict = flow.to_dict()
    total_packets = max(1, flow.total_packets)
    duration = max(flow.duration, 0.0)
    total_bytes = float(
        sum(p.get("ip_len", 0) for p in (flow.fwd_packets + flow.bwd_packets))
    )

    return {
        "timestamp": datetime.utcnow(),
        "src_ip": flow_dict["src_ip"],
        "dst_ip": flow_dict["dst_ip"],
        "src_port": flow_dict["src_port"],
        "dst_port": flow_dict["dst_port"],
        "protocol": flow_dict["protocol"],
        "duration": duration,
        "total_fwd_packets": flow.total_fwd_packets,
        "total_bwd_packets": flow.total_bwd_packets,
        "flow_bytes_per_s": (total_bytes / duration) if duration > 0 else total_bytes,
        "flow_packets_per_s": (total_packets / duration) if duration > 0 else float(total_packets),
        "raw_features": None, # On ne stocke pas les raw features en DB pour gagner de la place (optionnel)
    }


async def _persist_flow_only(flow) -> None:
    """Enregistre un flux sans analyse (si erreur ou service non prêt)."""
    async with async_session_factory() as db:
        try:
            await repository.create_flow(db, _build_flow_data(flow))
            await db.commit()
        except Exception as e:
            await db.rollback()
            logger.error(f"Erreur persistance flow: {e}")


async def _persist_flow_result(flow, result: dict) -> None:
    """
    Enregistre le flux ET les résultats de son analyse (Prédictions, Anomalies, Alertes).
    Tout est fait dans une transaction atomique.
    """
    decision = result.get("decision", {})
    supervised = result.get("supervised", {})
    unsupervised = result.get("unsupervised", {})

    async with async_session_factory() as db:
        try:
            # 1. Création du Flux
            created_flow = await repository.create_flow(db, _build_flow_data(flow))

            # 2. Enregistrement Prédiction Supervisée
            await repository.create_prediction(
                db,
                {
                    "flow_id": created_flow.id,
                    "timestamp": datetime.utcnow(),
                    "model_version": "latest",
                    "predicted_label": supervised.get("attack_type") or "BENIGN",
                    "confidence": float(supervised.get("probability", 0.0)),
                    "class_probabilities": supervised.get("class_probabilities"),
                },
            )

            # 3. Enregistrement Score Anomalie
            await repository.create_anomaly(
                db,
                {
                    "flow_id": created_flow.id,
                    "timestamp": datetime.utcnow(),
                    "reconstruction_error": float(unsupervised.get("reconstruction_error", 0.0)),
                    "anomaly_score": float(unsupervised.get("anomaly_score", 0.0)),
                    "threshold_used": float(unsupervised.get("threshold", 0.0)),
                    "is_anomaly": bool(unsupervised.get("is_anomaly", False)),
                },
            )

            # 4. Création d'Alerte si nécessaire
            if decision.get("decision") and decision.get("decision") != "normal":
                alert_payload = await alert_service.create_alert(
                    flow_id=created_flow.id,
                    decision={
                        "severity": decision.get("severity", "low"),
                        "attack_type": decision.get("attack_type"),
                        "threat_score": float(decision.get("final_risk_score", 0.0)),
                        "decision": decision.get("decision", "normal"),
                        "priority": decision.get("priority", 5),
                        "reasoning": _build_reasoning(decision),
                        "supervised_confidence": float(decision.get("probability", 0.0)),
                        "anomaly_score": float(decision.get("anomaly_score", 0.0)),
                    },
                    flow_metadata=result.get("flow_metadata", {}),
                )
                await repository.create_alert(db, alert_payload)

            # 5. MAJ Score Global de Menace
            await alert_service.update_threat_score(float(decision.get("final_risk_score", 0.0)))
            await db.commit()
        except Exception as e:
            await db.rollback()
            logger.error(f"Erreur persistance flow/result: {e}")


async def _persist_completed_flows(flows: list) -> None:
    """Traite un lot de flux terminés : analyse et persistance."""
    if detection_service.is_ready():
        for flow in flows:
            result = detection_service.analyze_flow(flow)
            if "error" in result:
                await _persist_flow_only(flow)
            else:
                await _persist_flow_result(flow, result)
    else:
        # Fallback si le service d'IA n'est pas prêt
        for flow in flows:
            await _persist_flow_only(flow)


async def _capture_loop() -> None:
    """
    Boucle principale de capture en arrière-plan.
    Récupère les paquets, construit les flux, et les envoie à l'analyse par lots.
    """
    logger.info("Boucle de capture démarrée")
    ensure_detection_ready()
    last_force_flush = time.time()

    while capture_service.is_running():
        try:
            # Récupération des flux terminés (timeout ou fin TCP)
            completed_flows = capture_service.process_captured_packets()

            # Flush forcé toutes les 5s pour éviter que des flux restent coincés
            now = time.time()
            if now - last_force_flush >= 5:
                completed_flows.extend(capture_service.force_complete_all())
                last_force_flush = now

            if not completed_flows:
                await asyncio.sleep(1)
                continue

            # Traitement async des flux
            await _persist_completed_flows(completed_flows)
        except Exception as e:
            logger.error(f"Erreur boucle capture: {e}")

        await asyncio.sleep(1)

    # Flush final à l'arrêt
    try:
        remaining = capture_service.force_complete_all()
        if remaining:
            await _persist_completed_flows(remaining)
    except Exception as e:
        logger.error(f"Erreur flush final capture: {e}")

    logger.info("Boucle de capture arrêtée")


@router.post("/analyze", response_model=DetectionResponse)
async def analyze_features(request: DetectionRequest):
    """
    Analyse un vecteur de features via le pipeline hybride.
    Endpoint utilisé principalement pour le replay ou les tests unitaires.
    """
    if not ensure_detection_ready():
        raise HTTPException(status_code=503, detail="Modèles non chargés")

    features = np.array(request.features, dtype=np.float32)
    result = detection_service.analyze_features(features, request.ip_reputation)

    if "error" in result or "decision" not in result:
        raise HTTPException(status_code=503, detail=result.get("error", "Service d'inférence indisponible"))

    decision = result["decision"]
    return DetectionResponse(
        decision=decision["decision"],
        severity=decision["severity"],
        threat_score=decision.get("final_risk_score", 0.0),
        attack_type=decision.get("attack_type"),
        supervised_confidence=decision.get("probability", 0.0),
        anomaly_score=decision["anomaly_score"],
        is_anomaly=decision.get("details", {}).get("is_anomaly", False),
        priority=decision.get("priority", 5),
        reasoning=_build_reasoning(decision),
    )


@router.get("/status")
async def detection_status():
    """Retourne l'état complet du service de détection (modèles chargés, statut...)."""
    ensure_detection_ready()
    status_data = detection_service.get_status()
    return {
        "status": "running" if status_data.get("is_ready") else "degraded",
        "models_loaded": status_data.get("is_ready", False),
        "artifacts": status_data.get("artifacts", {}),
        "message": (
            "Service de détection opérationnel"
            if status_data.get("is_ready")
            else "Service démarré, modèles non chargés"
        ),
    }


@router.post("/capture/start")
async def start_capture():
    """
    Démarre la capture réseau en arrière-plan.
    Lance la tâche asynchrone _capture_loop.
    """
    global _capture_task

    if capture_service.is_running():
        return {"status": "already_running", "message": "Capture réseau déjà active"}

    # Tentative de démarrage (avec fallback auto)
    capture_service.start_capture_with_fallback()
    await asyncio.sleep(0.5)

    if not capture_service.is_running():
        status = capture_service.get_status()
        return {
            "status": "error",
            "message": (
                "Impossible de démarrer la capture. Vérifiez CAPTURE_INTERFACE "
                f"(actuel: {settings.capture_interface})."
            ),
            "details": {
                "last_error": status.get("last_error"),
                "available_interfaces": status.get("available_interfaces", []),
            },
        }

    _capture_task = asyncio.create_task(_capture_loop())
    status = capture_service.get_status()
    return {
        "status": "started",
        "message": "Capture réseau démarrée",
        "interface": status.get("interface"),
    }


@router.post("/capture/stop")
async def stop_capture():
    """Arrête la capture réseau et la tâche de fond associée."""
    global _capture_task

    capture_service.stop_capture()

    if _capture_task and not _capture_task.done():
        try:
            await asyncio.wait_for(_capture_task, timeout=5)
        except asyncio.TimeoutError:
            _capture_task.cancel()

    _capture_task = None
    return {"status": "stopped", "message": "Capture réseau arrêtée"}


@router.get("/capture/status")
async def capture_status():
    """Retourne l'état de la capture (paquets, buffer, flux actifs...)."""
    status = capture_service.get_status()
    return {
        **status,
        "models_ready": detection_service.is_ready(),
    }


@router.get("/capture/interfaces")
async def capture_interfaces():
    """Liste les interfaces réseau disponibles sur la machine hôte."""
    status = capture_service.get_status()
    return {
        "configured_interface": capture_service.get_interface(),
        "available_interfaces": status.get("available_interfaces", []),
    }


@router.post("/capture/interface")
async def set_capture_interface(request: CaptureInterfaceRequest):
    """Change l'interface de capture (nécessite un arrêt/relance)."""
    if capture_service.is_running():
        return {
            "status": "error",
            "message": "Arrêtez la capture avant de changer d'interface",
        }

    new_interface = (request.interface or "auto").strip() or "auto"
    capture_service.set_interface(new_interface)

    return {
        "status": "updated",
        "message": "Interface de capture mise à jour",
        "interface": capture_service.get_interface(),
    }
