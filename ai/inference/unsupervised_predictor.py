"""
Prédicteur non-supervisé pour la détection d'anomalies réseau.
Utilise un autoencoder pré-entraîné sur le trafic BENIGN.

Principe : l'autoencoder reconstruit bien le trafic normal.
Si l'erreur de reconstruction est élevée → anomalie.
Seuil adaptatif =μ + kσ (calibré pendant l'entraînement).
"""

import logging
from typing import Dict, Any, Optional, List

import numpy as np
import joblib

from ai.config.model_config import inference_config, artifact_paths

logger = logging.getLogger(__name__)


class UnsupervisedPredictor:
    """
    Détecte les anomalies réseau via un autoencoder.
    Les attaques 0-day et comportements inconnus sont repérés
    par une erreur de reconstruction élevée.
    """

    def __init__(self, model):
        """
        Args:
            model: Autoencoder Keras chargé.
        """
        self.model = model
        self.threshold_k = inference_config.anomaly_threshold_k

        # Statistiques de calibration (chargées depuis un fichier ou par défaut)
        self.baseline_mean: float = 0.0
        self.baseline_std: float = 1.0
        self.threshold: float = 0.0

        self._load_threshold_stats()

    def _load_threshold_stats(self):
        """Charge les statistiques de seuil depuis un fichier pkl si disponible."""
        threshold_path = artifact_paths.base_dir / "threshold_stats.pkl"
        if threshold_path.exists():
            try:
                stats = joblib.load(str(threshold_path))
                self.baseline_mean = stats.get("mean", 0.0)
                self.baseline_std = stats.get("std", 1.0)
                self.threshold = stats.get("threshold", self.baseline_mean + self.threshold_k * self.baseline_std)
                logger.info(
                    f"✓ Seuil d'anomalie chargé : "
                    f"μ={self.baseline_mean:.6f}, σ={self.baseline_std:.6f}, "
                    f"threshold={self.threshold:.6f}"
                )
            except Exception as e:
                logger.warning(f"⚠ Impossible de charger threshold_stats.pkl : {e}")
                self._set_default_threshold()
        else:
            logger.warning("⚠ threshold_stats.pkl introuvable, seuil par défaut utilisé")
            self._set_default_threshold()

    def _set_default_threshold(self):
        """Valeurs par défaut si les stats ne sont pas disponibles."""
        self.baseline_mean = 0.01
        self.baseline_std = 0.005
        self.threshold = self.baseline_mean + self.threshold_k * self.baseline_std

    def _compute_reconstruction_error(self, features: np.ndarray) -> np.ndarray:
        """Calcule l'erreur de reconstruction MSE."""
        reconstructed = self.model.predict(features, verbose=0)
        mse = np.mean(np.square(features - reconstructed), axis=1)
        return mse

    def predict(self, features: np.ndarray) -> Dict[str, Any]:
        """
        Évalue l'anomalie d'un échantillon.

        Args:
            features: Features préprocessées, shape (1, n_features).

        Returns:
            Dict avec anomaly_score, is_anomaly, et détails.
        """
        if features.ndim == 1:
            features = features.reshape(1, -1)

        # Calcul de l'erreur de reconstruction
        reconstruction_error = self._compute_reconstruction_error(features)
        error_value = float(reconstruction_error[0])

        # Score d'anomalie normalisé (0 = normal, 1 = très anormal)
        if self.baseline_std > 0:
            z_score = (error_value - self.baseline_mean) / self.baseline_std
            anomaly_score = min(1.0, max(0.0, z_score / (self.threshold_k * 2)))
        else:
            anomaly_score = 0.0

        is_anomaly = error_value > self.threshold

        return {
            "anomaly_score": round(anomaly_score, 6),
            "is_anomaly": is_anomaly,
            "reconstruction_error": round(error_value, 8),
            "threshold": round(self.threshold, 8),
            "z_score": round(z_score if self.baseline_std > 0 else 0.0, 4),
        }

    def predict_batch(self, features: np.ndarray) -> List[Dict[str, Any]]:
        """
        Évalue l'anomalie pour un batch.

        Args:
            features: Shape (n_samples, n_features).

        Returns:
            Liste de résultats d'anomalie.
        """
        if features.ndim == 1:
            features = features.reshape(1, -1)

        errors = self._compute_reconstruction_error(features)
        results = []

        for error_value in errors:
            ev = float(error_value)
            if self.baseline_std > 0:
                z_score = (ev - self.baseline_mean) / self.baseline_std
                anomaly_score = min(1.0, max(0.0, z_score / (self.threshold_k * 2)))
            else:
                z_score = 0.0
                anomaly_score = 0.0

            results.append({
                "anomaly_score": round(anomaly_score, 6),
                "is_anomaly": ev > self.threshold,
                "reconstruction_error": round(ev, 8),
            })

        return results

    def update_threshold_k(self, new_k: float):
        """Met à jour le multiplicateur de seuil dynamiquement."""
        self.threshold_k = new_k
        self.threshold = self.baseline_mean + new_k * self.baseline_std
        logger.info(f"Seuil mis à jour : k={new_k}, threshold={self.threshold:.6f}")

    def get_info(self) -> Dict[str, Any]:
        """Retourne les informations du seuil pour le monitoring."""
        return {
            "baseline_mean": self.baseline_mean,
            "baseline_std": self.baseline_std,
            "threshold": self.threshold,
            "threshold_k": self.threshold_k,
        }
