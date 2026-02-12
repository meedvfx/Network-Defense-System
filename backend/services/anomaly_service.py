"""
Service d'anomalies : interface entre le prédicteur non-supervisé et le backend.
"""

import logging
from typing import Dict, Any, Optional

from ai.inference.unsupervised_predictor import UnsupervisedPredictor

logger = logging.getLogger(__name__)


class AnomalyService:
    """Service pour la détection d'anomalies non-supervisée."""

    def __init__(self, predictor: Optional[UnsupervisedPredictor] = None):
        self.predictor = predictor

    def check_anomaly(self, features) -> Dict[str, Any]:
        """Vérifie si un flux est anormal."""
        if not self.predictor:
            return {"error": "Predictor non chargé", "is_anomaly": False}
        return self.predictor.predict(features)

    def get_threshold_info(self) -> Dict[str, Any]:
        """Retourne les informations du seuil actuel."""
        if not self.predictor:
            return {}
        return self.predictor.get_info()

    def update_threshold_k(self, new_k: float) -> Dict[str, Any]:
        """Met à jour le multiplicateur de seuil."""
        if self.predictor:
            self.predictor.update_threshold_k(new_k)
            logger.info(f"Seuil mis à jour : k={new_k}")
        return self.get_threshold_info()
