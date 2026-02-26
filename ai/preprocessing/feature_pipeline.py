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
    Gère le pipeline complet de prétraitement des fonctionnalités pour l'inférence en production.
    Cette classe est responsable de charger les artefacts de prétraitement (scaler, sélecteur)
    et de les appliquer séquentiellement aux données brutes pour les préparer à être consommées par les modèles d'IA.
    
    Elle assure la cohérence entre les transformations appliquées lors de l'entraînement et celles appliquées en production.
    """

    def __init__(self):
        """Initialise le pipeline avec des composants vides."""
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
        Charge les objets de prétraitement (scaler, sélecteur, encodeur) depuis les fichiers artefacts sur le disque.
        Cette méthode doit être appelée avant toute tentative de transformation.

        Returns:
            bool: True si tous les artefacts essentiels ont été chargés avec succès, False sinon.
        """
        try:
            # 1. Charger le Scaler (StandardScaler)
            # Indispensable pour normaliser les données (moyenne=0, écart-type=1).
            scaler_path = artifact_paths.scaler
            if scaler_path.exists():
                self.scaler = joblib.load(str(scaler_path))
                logger.info(f"✓ Scaler chargé depuis {scaler_path.name}")
            else:
                logger.error(f"✗ Scaler introuvable : {scaler_path}")
                return False

            # 2. Charger le Feature Selector (Optionnel mais recommandé)
            # Réduit la dimensionnalité en ne gardant que les fonctionnalités les plus pertinentes.
            selector_path = artifact_paths.feature_selector
            if selector_path.exists():
                self.feature_selector = joblib.load(str(selector_path))
                logger.info(f"✓ Feature selector chargé depuis {selector_path.name}")
            else:
                logger.warning(f"⚠ Feature selector introuvable : {selector_path} (optionnel)")

            # 3. Charger l'Encoder (LabelEncoder)
            # Permet de mapper les prédictions numériques (0, 1, 2...) vers des noms d'attaques lisibles (DDoS, Botnet...).
            encoder_path = artifact_paths.encoder
            if encoder_path.exists():
                self.encoder = joblib.load(str(encoder_path))
                # Extraire les noms de classes pour un accès rapide
                if hasattr(self.encoder, 'classes_'):
                    self._class_names = list(self.encoder.classes_)
                elif hasattr(self.encoder, 'class_names'):
                    self._class_names = self.encoder.class_names
                logger.info(f"✓ Encoder chargé depuis {encoder_path.name}")
                if self._class_names:
                    logger.info(f"  Classes : {self._class_names}")
            else:
                logger.warning(f"⚠ Encoder introuvable : {encoder_path} (optionnel)")

            # 4. Déduire les dimensions d'entrée et de sortie attendues
            # Utile pour le débogage et la validation.
            if hasattr(self.scaler, 'n_features_in_'):
                self._n_features_in = self.scaler.n_features_in_
            if self.feature_selector and hasattr(self.feature_selector, 'n_features_'):
                self._n_features_out = self.feature_selector.n_features_
            elif hasattr(self.scaler, 'n_features_in_'):
                self._n_features_out = self.scaler.n_features_in_

            self._is_loaded = True
            logger.info(
                f"✓ Pipeline de preprocessing chargé "
                f"(entrée={self._n_features_in}, sortie={self._n_features_out})"
            )
            return True

        except Exception as e:
            logger.error(f"✗ Erreur critique lors du chargement du pipeline : {e}")
            self._is_loaded = False
            return False

    @property
    def is_loaded(self) -> bool:
        """Indique si le pipeline est prêt à être utilisé."""
        return self._is_loaded

    @property
    def class_names(self) -> Optional[List[str]]:
        """Retourne la liste des noms des classes d'attaques connues."""
        return self._class_names

    @property
    def num_classes(self) -> int:
        """Retourne le nombre total de classes d'attaques."""
        return len(self._class_names) if self._class_names else 0

    def transform(self, features: np.ndarray) -> np.ndarray:
        """
        Applique la chaîne complète de transformations aux données brutes.
        
        Séquence :
        1. Validation stricte (nettoyage NaN/Inf)
        2. Mise à l'échelle (Scaling)
        3. Sélection de fonctionnalités (si activée)

        Args:
            features (np.ndarray): Tableau de features brutes (1D ou 2D).

        Returns:
            np.ndarray: Le tableau transformé, prêt pour l'inférence par le modèle.

        Raises:
            RuntimeError: Si le pipeline n'est pas chargé.
            DataValidationError: Si les données sont invalides.
        """
        if not self._is_loaded:
            raise RuntimeError("Pipeline non chargé. Appelez load() avant transform().")

        # 1. Validation et nettoyage des données brutes
        cleaned = self.validator.validate_strict(features)

        # 2. Application du Scaler (Normalisation) — AVANT la sélection
        # Le scaler a été entraîné sur TOUTES les features brutes.
        # Le feature selector a été entraîné sur les features SCALÉES.
        # Ordre correct : scale → select (cohérent avec le pipeline d'entraînement).
        try:
            cleaned = self.scaler.transform(cleaned)
        except Exception as e:
            raise RuntimeError(f"Erreur de scaling : {e}. Vérifiez que le nombre de features correspond à l'entraînement.")

        # 3. Application du Feature Selector (si disponible) — APRÈS le scaling
        if self.feature_selector is not None:
            try:
                cleaned = self.feature_selector.transform(cleaned)
            except Exception as e:
                logger.warning(f"Feature selection échouée, utilisation des features scalées : {e}")

        # Conversion explicite en float32 pour optimiser l'inférence TensorFlow
        return cleaned.astype(np.float32)

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
