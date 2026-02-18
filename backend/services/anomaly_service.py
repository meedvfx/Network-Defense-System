"""
Service d'anomalies : interface entre le prédicteur non-supervisé et le backend.
"""

import logging
from typing import Dict, Any, Optional

from ai.inference import unsupervised_predictor

logger = logging.getLogger(__name__)

# ---- Global State ----
_predictor: Optional[Dict[str, Any]] = None


def set_predictor(predictor: Optional[Dict[str, Any]]) -> None:
    """
    Définit l'instance du prédicteur non-supervisé utilisée par le service.
    Appelé lors de l'initialisation du detection_service.
    """
    global _predictor
    _predictor = predictor


def check_anomaly(features) -> Dict[str, Any]:
    """
    Vérifie si un vecteur de features correspond à une anomalie.
    Utilise l'autoencoder pour calculer l'erreur de reconstruction.
    
    Returns:
        Dict: Contient 'is_anomaly', 'anomaly_score', et 'reconstruction_error'.
    """
    if not _predictor:
        return {"error": "Predictor non chargé", "is_anomaly": False}
    return unsupervised_predictor.predict(_predictor, features)


def get_threshold_info() -> Dict[str, Any]:
    """
    Retourne les méta-informations sur le seuil de détection actuel.
    Inclut la moyenne et l'écart-type de l'erreur de reconstruction sur le jeu d'entraînement.
    """
    if not _predictor:
        return {}
    return unsupervised_predictor.get_info(_predictor)


def update_threshold_k(new_k: float) -> Dict[str, Any]:
    """
    Met à jour dynamiquement le facteur de sensibilité 'k' (Seuil = Mean + k * Std).
    Permet d'ajuster la sensibilité sans redémarrer le service.
    
    Args:
        new_k: Nouveau multiplicateur (ex: 3.0). Un k plus élevé réduit les faux positifs mais peut manquer des attaques subtiles.
    """
    if _predictor:
        unsupervised_predictor.update_threshold_k(_predictor, new_k)
        logger.info(f"Seuil mis à jour : k={new_k}")
    return get_threshold_info()
