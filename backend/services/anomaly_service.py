"""
Service d'anomalies : interface entre le prédicteur non-supervisé et le backend.
"""

import logging
from typing import Dict, Any, Optional

from ai.inference import unsupervised_predictor

logger = logging.getLogger(__name__)

_predictor: Optional[Dict[str, Any]] = None

def set_predictor(predictor: Optional[Dict[str, Any]]) -> None:
    global _predictor
    _predictor = predictor

def check_anomaly(features) -> Dict[str, Any]:
    """Vérifie si un flux est anormal."""
    if not _predictor:
        return {"error": "Predictor non chargé", "is_anomaly": False}
    return unsupervised_predictor.predict(_predictor, features)

def get_threshold_info() -> Dict[str, Any]:
    """Retourne les informations du seuil actuel."""
    if not _predictor:
        return {}
    return unsupervised_predictor.get_info(_predictor)

def update_threshold_k(new_k: float) -> Dict[str, Any]:
    """Met à jour le multiplicateur de seuil."""
    if _predictor:
        unsupervised_predictor.update_threshold_k(_predictor, new_k)
        logger.info(f"Seuil mis à jour : k={new_k}")
    return get_threshold_info()
