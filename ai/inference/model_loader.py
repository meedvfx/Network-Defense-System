"""
Chargeur centralisé de tous les artifacts AI.
Charge les modèles Keras et les objets de preprocessing au démarrage.

Usage:
    loader = ModelLoader()
    if loader.load_all():
        # les modèles sont prêts pour l'inférence
"""

import logging
from typing import Dict, Any, Optional

import numpy as np

from ai.config.model_config import artifact_paths, inference_config
from ai.preprocessing.feature_pipeline import FeaturePipeline

logger = logging.getLogger(__name__)


class ModelLoader:
    """
    Charge et gère tous les artifacts AI pour l'inférence en production.
    Aucun entraînement : uniquement chargement de fichiers pré-entraînés.
    """

    def __init__(self):
        self.supervised_model = None
        self.unsupervised_model = None
        self.pipeline = FeaturePipeline()
        self._is_ready = False

    def load_all(self) -> bool:
        """
        Charge tous les artifacts : modèles Keras + pipeline preprocessing.

        Returns:
            True si tous les composants critiques sont chargés.
        """
        logger.info("=" * 60)
        logger.info("  Chargement des artifacts AI")
        logger.info("=" * 60)

        # Vérification préalable
        missing = artifact_paths.missing_artifacts()
        if missing:
            logger.error(f"✗ Artifacts manquants : {missing}")
            logger.error(
                "  → Entraînez les modèles dans Google Colab et déposez-les dans ai/artifacts/"
            )
            return False

        success = True

        # 1. Charger le pipeline de preprocessing
        if not self.pipeline.load():
            logger.error("✗ Échec du chargement du pipeline de preprocessing")
            success = False

        # 2. Charger le modèle supervisé
        try:
            import tensorflow as tf
            self.supervised_model = tf.keras.models.load_model(
                str(artifact_paths.supervised_model),
                compile=False,   # Pas besoin de l'optimizer en inférence
            )
            logger.info(f"✓ Modèle supervisé chargé : {artifact_paths.supervised_model.name}")
            logger.info(f"  Input shape: {self.supervised_model.input_shape}")
            logger.info(f"  Output shape: {self.supervised_model.output_shape}")
        except Exception as e:
            logger.error(f"✗ Erreur chargement modèle supervisé : {e}")
            success = False

        # 3. Charger le modèle non-supervisé (autoencoder)
        try:
            import tensorflow as tf
            self.unsupervised_model = tf.keras.models.load_model(
                str(artifact_paths.unsupervised_model),
                compile=False,
            )
            logger.info(f"✓ Modèle non-supervisé chargé : {artifact_paths.unsupervised_model.name}")
            logger.info(f"  Input shape: {self.unsupervised_model.input_shape}")
        except Exception as e:
            logger.error(f"✗ Erreur chargement modèle non-supervisé : {e}")
            success = False

        # 4. Warm-up (pré-charge le graphe TensorFlow)
        if success and inference_config.warmup_on_load:
            self._warmup()

        self._is_ready = success

        if success:
            logger.info("=" * 60)
            logger.info("  ✓ Tous les artifacts AI chargés avec succès")
            logger.info("=" * 60)
        else:
            logger.warning("⚠ Chargement partiel — certains composants manquent")

        return success

    def _warmup(self):
        """Pré-charge les graphes TF avec un sample factice."""
        try:
            if self.supervised_model:
                input_shape = self.supervised_model.input_shape[1:]
                dummy = np.zeros((1, *input_shape), dtype=np.float32)
                self.supervised_model.predict(dummy, verbose=0)
                logger.info("  ✓ Warm-up supervisé OK")

            if self.unsupervised_model:
                input_shape = self.unsupervised_model.input_shape[1:]
                dummy = np.zeros((1, *input_shape), dtype=np.float32)
                self.unsupervised_model.predict(dummy, verbose=0)
                logger.info("  ✓ Warm-up non-supervisé OK")
        except Exception as e:
            logger.warning(f"⚠ Warm-up échoué (non bloquant) : {e}")

    @property
    def is_ready(self) -> bool:
        return self._is_ready

    def get_status(self) -> Dict[str, Any]:
        """Retourne le statut détaillé de tous les artifacts."""
        return {
            "is_ready": self._is_ready,
            "artifacts": {
                "supervised_model": {
                    "loaded": self.supervised_model is not None,
                    "path": str(artifact_paths.supervised_model),
                    "exists": artifact_paths.supervised_model.exists(),
                },
                "unsupervised_model": {
                    "loaded": self.unsupervised_model is not None,
                    "path": str(artifact_paths.unsupervised_model),
                    "exists": artifact_paths.unsupervised_model.exists(),
                },
                "scaler": {
                    "loaded": self.pipeline.scaler is not None,
                    "path": str(artifact_paths.scaler),
                    "exists": artifact_paths.scaler.exists(),
                },
                "encoder": {
                    "loaded": self.pipeline.encoder is not None,
                    "path": str(artifact_paths.encoder),
                    "exists": artifact_paths.encoder.exists(),
                },
                "feature_selector": {
                    "loaded": self.pipeline.feature_selector is not None,
                    "path": str(artifact_paths.feature_selector),
                    "exists": artifact_paths.feature_selector.exists(),
                },
            },
            "pipeline": self.pipeline.get_info(),
            "missing": artifact_paths.missing_artifacts(),
        }
