"""
Pipeline de preprocessing pour l'inférence en production.
Charge les objets de preprocessing pré-entraînés (scaler, feature_selector)
et les applique séquentiellement aux features réseau brutes.

Flux : features brutes → validation → scaling → feature selection → prêt pour inférence.
"""

import logging
from typing import Dict, Any, Optional, List

import numpy as np
import joblib

from ai.preprocessing.data_validator import DataValidator, DataValidationError
from ai.config.model_config import artifact_paths

logger = logging.getLogger(__name__)


class FeaturePipeline:
    """
    Pipeline de prétraitement des features pour l'inférence.
    Charge le scaler et le feature_selector depuis les artifacts pré-entraînés
    et les applique dans l'ordre correct.
    """

    def __init__(self):
        self.scaler = None
        self.feature_selector = None
        self.encoder = None
        self.validator = DataValidator(allow_negative=True)
        self._is_loaded = False
        self._n_features_in: Optional[int] = None
        self._n_features_out: Optional[int] = None
        self._class_names: Optional[List[str]] = None

    def load(self) -> bool:
        """
        Charge les objets de preprocessing depuis les artifacts.

        Returns:
            True si tous les artifacts sont chargés avec succès.
        """
        try:
            # Charger le scaler
            scaler_path = artifact_paths.scaler
            if scaler_path.exists():
                self.scaler = joblib.load(str(scaler_path))
                logger.info(f"✓ Scaler chargé depuis {scaler_path.name}")
            else:
                logger.error(f"✗ Scaler introuvable : {scaler_path}")
                return False

            # Charger le feature selector
            selector_path = artifact_paths.feature_selector
            if selector_path.exists():
                self.feature_selector = joblib.load(str(selector_path))
                logger.info(f"✓ Feature selector chargé depuis {selector_path.name}")
            else:
                logger.warning(f"⚠ Feature selector introuvable : {selector_path} (optionnel)")

            # Charger l'encoder (pour le mapping label → nom d'attaque)
            encoder_path = artifact_paths.encoder
            if encoder_path.exists():
                self.encoder = joblib.load(str(encoder_path))
                # Extraire les noms de classes
                if hasattr(self.encoder, 'classes_'):
                    self._class_names = list(self.encoder.classes_)
                elif hasattr(self.encoder, 'class_names'):
                    self._class_names = self.encoder.class_names
                logger.info(f"✓ Encoder chargé depuis {encoder_path.name}")
                if self._class_names:
                    logger.info(f"  Classes : {self._class_names}")
            else:
                logger.warning(f"⚠ Encoder introuvable : {encoder_path} (optionnel)")

            # Détecter les dimensions
            if hasattr(self.scaler, 'n_features_in_'):
                self._n_features_in = self.scaler.n_features_in_
            if self.feature_selector and hasattr(self.feature_selector, 'n_features_'):
                self._n_features_out = self.feature_selector.n_features_
            elif hasattr(self.scaler, 'n_features_in_'):
                self._n_features_out = self.scaler.n_features_in_

            self._is_loaded = True
            logger.info(
                f"✓ Pipeline de preprocessing chargé "
                f"(in={self._n_features_in}, out={self._n_features_out})"
            )
            return True

        except Exception as e:
            logger.error(f"✗ Erreur de chargement du pipeline : {e}")
            self._is_loaded = False
            return False

    @property
    def is_loaded(self) -> bool:
        return self._is_loaded

    @property
    def class_names(self) -> Optional[List[str]]:
        return self._class_names

    @property
    def num_classes(self) -> int:
        return len(self._class_names) if self._class_names else 0

    def transform(self, features: np.ndarray) -> np.ndarray:
        """
        Applique le pipeline complet de preprocessing.

        Args:
            features: Features brutes (1D ou 2D array).

        Returns:
            Features transformées prêtes pour l'inférence.

        Raises:
            DataValidationError: Si les features sont invalides.
            RuntimeError: Si le pipeline n'est pas chargé.
        """
        if not self._is_loaded:
            raise RuntimeError("Pipeline non chargé. Appelez load() avant transform().")

        # 1. Validation et nettoyage
        cleaned = self.validator.validate_strict(features)

        # 2. Feature selection (si disponible, appliqué AVANT le scaling)
        if self.feature_selector is not None:
            try:
                cleaned = self.feature_selector.transform(cleaned)
            except Exception as e:
                logger.warning(f"Feature selection échouée, features brutes utilisées : {e}")

        # 3. Scaling
        try:
            transformed = self.scaler.transform(cleaned)
        except Exception as e:
            raise RuntimeError(f"Erreur de scaling : {e}")

        return transformed.astype(np.float32)

    def decode_label(self, label_index: int) -> str:
        """Convertit un index de classe en nom d'attaque lisible."""
        if self._class_names and 0 <= label_index < len(self._class_names):
            return self._class_names[label_index]
        return f"Unknown_{label_index}"

    def decode_probabilities(self, probabilities: np.ndarray) -> Dict[str, float]:
        """Convertit un vecteur de probabilités en dict {classe: proba}."""
        if self._class_names and len(probabilities) == len(self._class_names):
            return {
                name: float(prob)
                for name, prob in zip(self._class_names, probabilities)
            }
        return {f"class_{i}": float(p) for i, p in enumerate(probabilities)}

    def get_info(self) -> Dict[str, Any]:
        """Retourne les infos du pipeline pour le monitoring."""
        return {
            "is_loaded": self._is_loaded,
            "n_features_in": self._n_features_in,
            "n_features_out": self._n_features_out,
            "has_scaler": self.scaler is not None,
            "has_feature_selector": self.feature_selector is not None,
            "has_encoder": self.encoder is not None,
            "class_names": self._class_names,
            "num_classes": self.num_classes,
        }
