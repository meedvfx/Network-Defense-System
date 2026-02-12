"""
Validation des données d'entrée pour l'inférence.
Vérifie types, dimensions, NaN/Inf, et ranges avant le passage au pipeline.
"""

import logging
from typing import Tuple, List, Optional

import numpy as np

logger = logging.getLogger(__name__)


class DataValidationError(Exception):
    """Erreur levée quand les données d'entrée sont invalides."""
    pass


class DataValidator:
    """
    Valide les features réseau brutes avant le preprocessing.
    Garantit la cohérence des données en production.
    """

    def __init__(
        self,
        expected_features: Optional[int] = None,
        allow_negative: bool = True,
        max_value: float = 1e12,
    ):
        """
        Args:
            expected_features: Nombre de features attendues (None = pas de vérif).
            allow_negative: Autoriser les valeurs négatives.
            max_value: Valeur maximale acceptable.
        """
        self.expected_features = expected_features
        self.allow_negative = allow_negative
        self.max_value = max_value

    def validate(self, features: np.ndarray) -> Tuple[bool, np.ndarray, List[str]]:
        """
        Valide et nettoie un vecteur de features.

        Args:
            features: Array de features brutes (1D ou 2D).

        Returns:
            Tuple (is_valid, cleaned_features, warnings).
        """
        warnings = []

        # 1. Conversion en numpy
        if not isinstance(features, np.ndarray):
            try:
                features = np.array(features, dtype=np.float64)
            except (ValueError, TypeError) as e:
                raise DataValidationError(f"Impossible de convertir en array: {e}")

        # 2. Assurer la bonne dimension (1D → 2D)
        if features.ndim == 1:
            features = features.reshape(1, -1)
        elif features.ndim != 2:
            raise DataValidationError(
                f"Dimensions invalides: attendu 1D ou 2D, reçu {features.ndim}D"
            )

        # 3. Vérifier le nombre de features
        if self.expected_features and features.shape[1] != self.expected_features:
            raise DataValidationError(
                f"Nombre de features invalide: attendu {self.expected_features}, "
                f"reçu {features.shape[1]}"
            )

        # 4. Détecter et traiter NaN
        nan_count = np.isnan(features).sum()
        if nan_count > 0:
            warnings.append(f"{nan_count} valeurs NaN remplacées par 0")
            features = np.nan_to_num(features, nan=0.0)

        # 5. Détecter et traiter Inf
        inf_count = np.isinf(features).sum()
        if inf_count > 0:
            warnings.append(f"{inf_count} valeurs Inf remplacées par max_value")
            features = np.nan_to_num(features, posinf=self.max_value, neginf=-self.max_value)

        # 6. Vérifier les valeurs négatives
        if not self.allow_negative:
            neg_count = (features < 0).sum()
            if neg_count > 0:
                warnings.append(f"{neg_count} valeurs négatives clippées à 0")
                features = np.clip(features, 0, None)

        # 7. Clip des valeurs extrêmes
        extreme_count = (np.abs(features) > self.max_value).sum()
        if extreme_count > 0:
            warnings.append(f"{extreme_count} valeurs extrêmes clippées")
            features = np.clip(features, -self.max_value, self.max_value)

        # Log les warnings
        for w in warnings:
            logger.warning(f"DataValidator: {w}")

        is_valid = len(warnings) == 0
        return is_valid, features, warnings

    def validate_strict(self, features: np.ndarray) -> np.ndarray:
        """
        Validation stricte : lève une exception si les données ont des problèmes.
        Retourne les features nettoyées si elles sont valides.
        """
        is_valid, cleaned, warnings = self.validate(features)
        if not is_valid:
            logger.warning(f"Features validées avec {len(warnings)} warnings")
        return cleaned
