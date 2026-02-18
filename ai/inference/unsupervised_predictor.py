"""
Prédicteur non-supervisé pour la détection d'anomalies réseau.
Utilise un autoencoder pré-entraîné sur le trafic BENIGN.

Principe : l'autoencoder reconstruit bien le trafic normal.
Si l'erreur de reconstruction est élevée → anomalie.
Seuil adaptatif =μ + kσ (calibré pendant l'entraînement).
"""

import logging
from typing import Dict, Any, List

import numpy as np
import joblib

from ai.config.model_config import inference_config, artifact_paths

logger = logging.getLogger(__name__)


def create_predictor(model) -> Dict[str, Any]:
    """
    Initialise le prédicteur non-supervisé (Autoencoder).
    Charge les statistiques seuils (moyenne/écart-type de l'erreur bénigne) pour la détection d'anomalies.
    """
    predictor = {
        "model": model,
        "threshold_k": inference_config.anomaly_threshold_k,
        "baseline_mean": 0.0,
        "baseline_std": 1.0,
        "threshold": 0.0,
    }
    _load_threshold_stats(predictor)
    return predictor


def _to_2d(features: np.ndarray) -> np.ndarray:
    if features.ndim == 1:
        return features.reshape(1, -1)
    return features


def _set_default_threshold(predictor: Dict[str, Any]) -> None:
    """Configure des valeurs par défaut si le fichier de stats est manquant."""
    predictor["baseline_mean"] = 0.01
    predictor["baseline_std"] = 0.005
    predictor["threshold"] = predictor["baseline_mean"] + predictor["threshold_k"] * predictor["baseline_std"]


def _load_threshold_stats(predictor: Dict[str, Any]) -> None:
    """Charge les statistiques d'erreur de reconstruction depuis l'entraînement."""
    threshold_path = artifact_paths.base_dir / "threshold_stats.pkl"
    if threshold_path.exists():
        try:
            stats = joblib.load(str(threshold_path))
            predictor["baseline_mean"] = stats.get("mean", 0.0)
            predictor["baseline_std"] = stats.get("std", 1.0)
            predictor["threshold"] = stats.get(
                "threshold",
                predictor["baseline_mean"] + predictor["threshold_k"] * predictor["baseline_std"],
            )
            logger.info(
                "✓ Seuil d'anomalie chargé : "
                f"μ={predictor['baseline_mean']:.6f}, "
                f"σ={predictor['baseline_std']:.6f}, "
                f"threshold={predictor['threshold']:.6f}"
            )
            return
        except Exception as e:
            logger.warning(f"⚠ Impossible de charger threshold_stats.pkl : {e}")

    logger.warning("⚠ threshold_stats.pkl introuvable, seuil par défaut utilisé")
    _set_default_threshold(predictor)


def _compute_reconstruction_error(predictor: Dict[str, Any], features: np.ndarray) -> np.ndarray:
    """
    Calcule l'erreur de reconstruction (MSE expliquée) pour chaque échantillon.
    L'autoencoder tente de reproduire l'entrée ; une erreur élevée indique une donnée jamais vue (anomalie).
    """
    reconstructed = predictor["model"].predict(features, verbose=0)
    return np.mean(np.square(features - reconstructed), axis=1)


def _score_from_error(predictor: Dict[str, Any], error_value: float) -> Dict[str, float]:
    """
    Convertit l'erreur MSE brute en un score d'anomalie normalisé (0-1) et un Z-score.
    """
    baseline_std = predictor["baseline_std"]
    baseline_mean = predictor["baseline_mean"]
    threshold_k = predictor["threshold_k"]

    if baseline_std > 0:
        # Z-score : combien d'écarts-types au-dessus de la moyenne ?
        z_score = (error_value - baseline_mean) / baseline_std
        # Normalisation empirique pour avoir un score ~0.5 au seuil critique
        anomaly_score = min(1.0, max(0.0, z_score / (threshold_k * 2)))
    else:
        z_score = 0.0
        anomaly_score = 0.0

    return {
        "z_score": z_score,
        "anomaly_score": anomaly_score,
    }


def predict(predictor: Dict[str, Any], features: np.ndarray) -> Dict[str, Any]:
    """
    Effectue une détection d'anomalie sur un échantillon.
    
    Returns:
        anomaly_score: Score normalisé (0=Normal, 1=Anomalie extrême).
        is_anomaly: True si l'erreur dépasse le seuil (μ + kσ).
        reconstruction_error: Erreur MSE brute.
    """
    features = _to_2d(features)
    reconstruction_error = _compute_reconstruction_error(predictor, features)
    error_value = float(reconstruction_error[0])
    scored = _score_from_error(predictor, error_value)

    return {
        "anomaly_score": round(scored["anomaly_score"], 6),
        "is_anomaly": error_value > predictor["threshold"],
        "reconstruction_error": round(error_value, 8),
        "threshold": round(predictor["threshold"], 8),
        "z_score": round(scored["z_score"], 4),
    }


def predict_batch(predictor: Dict[str, Any], features: np.ndarray) -> List[Dict[str, Any]]:
    """Version batch de predict() pour le traitement par lots."""
    features = _to_2d(features)
    errors = _compute_reconstruction_error(predictor, features)
    results = []

    for error_value in errors:
        ev = float(error_value)
        scored = _score_from_error(predictor, ev)
        results.append({
            "anomaly_score": round(scored["anomaly_score"], 6),
            "is_anomaly": ev > predictor["threshold"],
            "reconstruction_error": round(ev, 8),
        })

    return results


def update_threshold_k(predictor: Dict[str, Any], new_k: float) -> None:
    """Permet d'ajuster dynamiquement la sensibilité de la détection."""
    predictor["threshold_k"] = new_k
    predictor["threshold"] = predictor["baseline_mean"] + new_k * predictor["baseline_std"]
    logger.info(f"Seuil mis à jour : k={new_k}, threshold={predictor['threshold']:.6f}")


def get_info(predictor: Dict[str, Any]) -> Dict[str, Any]:
    """Retourne les paramètres actuels pour le monitoring."""
    return {
        "baseline_mean": predictor["baseline_mean"],
        "baseline_std": predictor["baseline_std"],
        "threshold": predictor["threshold"],
        "threshold_k": predictor["threshold_k"],
    }
