"""
Service d'anomalies : interface entre le prédicteur non-supervisé et le backend.
"""

import logging
from typing import Dict, Any, Optional

from ai.inference.unsupervised_predictor import UnsupervisedPredictor

logger = logging.getLogger(__name__)

_predictor: Optional[UnsupervisedPredictor] = None

def set_predictor(predictor: Optional[UnsupervisedPredictor]) -> None:
    global _predictor
    _predictor = predictor

def check_anomaly(features) -> Dict[str, Any]:
    """Vérifie si un flux est anormal."""
    if not _predictor:
        return {"error": "Predictor non chargé", "is_anomaly": False}
    return _predictor.predict(features)

def get_threshold_info() -> Dict[str, Any]:
    """Retourne les informations du seuil actuel."""
    if not _predictor:
        return {}
    return _predictor.get_info()

def update_threshold_k(new_k: float) -> Dict[str, Any]:
    """Met à jour le multiplicateur de seuil."""
    if _predictor:
        _predictor.update_threshold_k(new_k)
        logger.info(f"Seuil mis à jour : k={new_k}")
    return get_threshold_info()
