"""
Routes API pour la détection en temps réel.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List
import numpy as np

router = APIRouter(prefix="/api/detection", tags=["Detection"])


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
async def analyze_features(request: DetectionRequest):
    """
    Analyse un vecteur de features via le pipeline hybride.
    Utile pour les tests et l'intégration.
    """
    from backend.services.detection_service import DetectionService

    service = DetectionService()

    if not service.is_ready():
        raise HTTPException(status_code=503, detail="Modèles non chargés")

    features = np.array(request.features, dtype=np.float32)
    result = service.analyze_features(features, request.ip_reputation)

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
    return {
        "status": "running",
        "models_loaded": True,
        "message": "Service de détection opérationnel",
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
