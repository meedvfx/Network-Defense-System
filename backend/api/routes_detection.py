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

router = APIRouter(prefix="/api/detection", tags=["Detection"])
_init_attempted = False
_capture_task: Optional[asyncio.Task] = None

capture_service.configure_capture(
    interface=settings.capture_interface,
    buffer_size=settings.capture_buffer_size,
    flow_timeout=settings.capture_flow_timeout,
)


def ensure_detection_ready() -> bool:
    """Initialise le service de détection à la demande."""
    global _init_attempted
    if not detection_service.is_ready() and not _init_attempted:
        _init_attempted = True
        detection_service.initialize()
    return detection_service.is_ready()


class DetectionRequest(BaseModel):
    """Requête de détection sur un vecteur de features."""
    features: List[float]
    ip_reputation: float = 0.0


class DetectionResponse(BaseModel):
    """Réponse de détection."""
    decision: str
    severity: str
    threat_score: float
    attack_type: Optional[str]
    supervised_confidence: float
    anomaly_score: float
    is_anomaly: bool
    priority: int
    reasoning: str


class CaptureInterfaceRequest(BaseModel):
    interface: str


def _build_reasoning(decision: dict) -> str:
    details = decision.get("details", {})
    return (
        f"decision={decision.get('decision', 'unknown')}; "
        f"severity={decision.get('severity', 'unknown')}; "
        f"is_attack={details.get('is_attack', False)}; "
        f"is_anomaly={details.get('is_anomaly', False)}"
    )


def _build_flow_data(flow) -> dict:
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
        "raw_features": None,
    }


async def _persist_flow_only(flow) -> None:
    async with async_session_factory() as db:
        try:
            await repository.create_flow(db, _build_flow_data(flow))
            await db.commit()
        except Exception as e:
            await db.rollback()
            logger.error(f"Erreur persistance flow: {e}")


async def _persist_flow_result(flow, result: dict) -> None:
    decision = result.get("decision", {})
    supervised = result.get("supervised", {})
    unsupervised = result.get("unsupervised", {})

    async with async_session_factory() as db:
        try:
            created_flow = await repository.create_flow(db, _build_flow_data(flow))

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

            await alert_service.update_threat_score(float(decision.get("final_risk_score", 0.0)))
            await db.commit()
        except Exception as e:
            await db.rollback()
            logger.error(f"Erreur persistance flow/result: {e}")


async def _persist_completed_flows(flows: list) -> None:
    if detection_service.is_ready():
        for flow in flows:
            result = detection_service.analyze_flow(flow)
            if "error" in result:
                await _persist_flow_only(flow)
            else:
                await _persist_flow_result(flow, result)
    else:
        for flow in flows:
            await _persist_flow_only(flow)


async def _capture_loop() -> None:
    logger.info("Boucle de capture démarrée")
    ensure_detection_ready()
    last_force_flush = time.time()

    while capture_service.is_running():
        try:
            completed_flows = capture_service.process_captured_packets()

            now = time.time()
            if now - last_force_flush >= 5:
                completed_flows.extend(capture_service.force_complete_all())
                last_force_flush = now

            if not completed_flows:
                await asyncio.sleep(1)
                continue

            await _persist_completed_flows(completed_flows)
        except Exception as e:
            logger.error(f"Erreur boucle capture: {e}")

        await asyncio.sleep(1)

    # Flush final
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
    Utile pour les tests et l'intégration.
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
    """Retourne l'état du service de détection."""
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
    """Démarre la capture réseau."""
    global _capture_task

    if capture_service.is_running():
        return {"status": "already_running", "message": "Capture réseau déjà active"}

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
    """Arrête la capture réseau."""
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
    """Retourne l'état de la capture."""
    status = capture_service.get_status()
    return {
        **status,
        "models_ready": detection_service.is_ready(),
    }


@router.get("/capture/interfaces")
async def capture_interfaces():
    """Retourne la liste des interfaces réseau détectées."""
    status = capture_service.get_status()
    return {
        "configured_interface": capture_service.get_interface(),
        "available_interfaces": status.get("available_interfaces", []),
    }


@router.post("/capture/interface")
async def set_capture_interface(request: CaptureInterfaceRequest):
    """Configure l'interface de capture réseau (hors exécution)."""
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
