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
    Valide les fonctionnalités (features) réseau brutes avant qu'elles n'entrent dans le pipeline de prétraitement.
    Cette étape est cruciale pour garantir la stabilité et la fiabilité des prédictions en production,
    en évitant que des données corrompues ou aberrantes ne faussent les résultats du modèle.
    """

    def __init__(
        self,
        expected_features: Optional[int] = None,
        allow_negative: bool = True,
        max_value: float = 1e12,
    ):
        """
        Initialise le validateur avec des contraintes spécifiques.

        Args:
            expected_features (int, optional): Le nombre exact de fonctionnalités attendues dans le vecteur d'entrée.
                Si None, aucune vérification de dimensionnalité n'est effectuée sur le nombre de colonnes.
            allow_negative (bool): Si False, toutes les valeurs négatives seront considérées comme invalides et clippées à 0.
                Utile pour des métriques comme la taille des paquets ou la durée qui ne peuvent être négatives.
            max_value (float): La valeur maximale absolue autorisée. Toute valeur dépassant ce seuil (en positif ou négatif)
                sera clippée à cette limite pour éviter les problèmes de dépassement ou d'échelle excessive.
        """
        self.expected_features = expected_features
        self.allow_negative = allow_negative
        self.max_value = max_value

    def validate(self, features: np.ndarray) -> Tuple[bool, np.ndarray, List[str]]:
        """
        Valide, nettoie et formate un vecteur de fonctionnalités.
        Effectue une série de vérifications et de corrections automatiques.

        Args:
            features (np.ndarray): Tableau de fonctionnalités brutes (1D ou 2D).

        Returns:
            Tuple[bool, np.ndarray, List[str]]:
                - is_valid (bool): True si aucune modification majeure n'a été nécessaire (pas d'erreurs bloquantes).
                - cleaned_features (np.ndarray): Le tableau de fonctionnalités nettoyé et prêt pour le traitement.
                - warnings (List[str]): Liste des avertissements générés lors du nettoyage (ex: "NaN remplacés par 0").
        """
        warnings = []

        # 1. Conversion en tableau NumPy pour assurer la compatibilité des opérations vectorielles
        if not isinstance(features, np.ndarray):
            try:
                features = np.array(features, dtype=np.float64)
            except (ValueError, TypeError) as e:
                raise DataValidationError(f"Impossible de convertir les données d'entrée en tableau NumPy: {e}")

        # 2. Normalisation des dimensions : Force une structure 2D (n_samples, n_features)
        # Même pour un seul échantillon, Scikit-Learn attend un tableau 2D.
        if features.ndim == 1:
            features = features.reshape(1, -1)
        elif features.ndim != 2:
            raise DataValidationError(
                f"Dimensions des données invalides: attendu 1D ou 2D, mais reçu {features.ndim}D"
            )

        # 3. Vérification du nombre de fonctionnalités (colonnes)
        if self.expected_features and features.shape[1] != self.expected_features:
            raise DataValidationError(
                f"Nombre de fonctionnalités incorrect: attendu {self.expected_features}, "
                f"mais reçu {features.shape[1]}"
            )

        # 4. Détection et traitement des valeurs manquantes (NaN)
        # Les modèles ne peuvent pas traiter les NaN, on les remplace par 0.0.
        nan_count = np.isnan(features).sum()
        if nan_count > 0:
            warnings.append(f"{nan_count} valeurs NaN détectées et remplacées par 0")
            features = np.nan_to_num(features, nan=0.0)

        # 5. Détection et traitement des valeurs infinies (Inf)
        # Les valeurs infinies causent des erreurs de calcul, on les remplace par la valeur max définie.
        inf_count = np.isinf(features).sum()
        if inf_count > 0:
            warnings.append(f"{inf_count} valeurs infinies détectées et remplacées par {self.max_value}")
            features = np.nan_to_num(features, posinf=self.max_value, neginf=-self.max_value)

        # 6. Vérification et correction des valeurs négatives (si non autorisées)
        if not self.allow_negative:
            neg_count = (features < 0).sum()
            if neg_count > 0:
                warnings.append(f"{neg_count} valeurs négatives détectées et clippées à 0")
                features = np.clip(features, 0, None)

        # 7. Écrêtage (Clipping) des valeurs extrêmes
        # Empêche les valeurs aberrantes d'influencer excessivement la normalisation ultérieure.
        extreme_count = (np.abs(features) > self.max_value).sum()
        if extreme_count > 0:
            warnings.append(f"{extreme_count} valeurs extrêmes détectées et clippées à +/- {self.max_value}")
            features = np.clip(features, -self.max_value, self.max_value)

        # Enregistrement des avertissements dans les logs pour audit
        for w in warnings:
            logger.warning(f"DataValidator: {w}")

        # Considéré valide s'il n'y a pas eu d'erreurs critiques (ici warnings n'est pas bloquant, donc toujours True sauf exception levée plus haut)
        # Mais on pourrait définir is_valid = len(warnings) == 0 pour être strict.
        is_valid = len(warnings) == 0
        return is_valid, features, warnings

    def validate_strict(self, features: np.ndarray) -> np.ndarray:
        """
        Effectue une validation stricte et retourne uniquement les fonctionnalités nettoyées.
        Lève une DataValidationError si les dimensions sont incorrectes (géré par validate).
        Log les avertissements mais ne bloque pas l'exécution pour des corrections mineures (NaN, Inf).

        Args:
            features (np.ndarray): Les données brutes.

        Returns:
            np.ndarray: Les données nettoyées.
        """
        is_valid, cleaned, warnings = self.validate(features)
        if not is_valid:
            logger.warning(f"Validation terminée avec {len(warnings)} avertissements, mais les données ont été corrigées.")
        return cleaned
