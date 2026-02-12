"""
Routes API pour la détection en temps réel.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List
import numpy as np

from backend.services.detection_service import DetectionService

router = APIRouter(prefix="/api/detection", tags=["Detection"])
_detection_service = DetectionService()
_init_attempted = False


def get_detection_service() -> DetectionService:
    """Retourne une instance prête du service de détection (lazy init)."""
    global _init_attempted
    if not _detection_service.is_ready() and not _init_attempted:
        _init_attempted = True
        _detection_service.initialize()
    return _detection_service


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


@router.post("/analyze", response_model=DetectionResponse)
async def analyze_features(
    request: DetectionRequest,
    service: DetectionService = Depends(get_detection_service),
):
    """
    Analyse un vecteur de features via le pipeline hybride.
    Utile pour les tests et l'intégration.
    """
    if not service.is_ready():
        raise HTTPException(status_code=503, detail="Modèles non chargés")

    features = np.array(request.features, dtype=np.float32)
    result = service.analyze_features(features, request.ip_reputation)

    if "error" in result or "decision" not in result:
        raise HTTPException(status_code=503, detail=result.get("error", "Service d'inférence indisponible"))

    decision = result["decision"]
    return DetectionResponse(
        decision=decision["decision"],
        severity=decision["severity"],
        threat_score=decision["threat_score"],
        attack_type=decision.get("attack_type"),
        supervised_confidence=decision["supervised_confidence"],
        anomaly_score=decision["anomaly_score"],
        is_anomaly=decision["is_anomaly"],
        priority=decision.get("priority", 5),
        reasoning=decision.get("reasoning", ""),
    )


@router.get("/status")
async def detection_status():
    """Retourne l'état du service de détection."""
    service = get_detection_service()
    status_data = service.get_status()
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
    return {"status": "started", "message": "Capture réseau démarrée"}


@router.post("/capture/stop")
async def stop_capture():
    """Arrête la capture réseau."""
    return {"status": "stopped", "message": "Capture réseau arrêtée"}


@router.get("/capture/status")
async def capture_status():
    """Retourne l'état de la capture."""
    return {
        "is_running": False,
        "packets_captured": 0,
        "active_flows": 0,
        "buffer_usage": 0.0,
    }
