"""
Service de détection principal.
Orchestre le pipeline complet : features → preprocessing → AI → decision.

Architecture production : chargement des modèles pré-entraînés, inférence only.
"""

import logging
from typing import Dict, Any, Optional, List

import numpy as np

from ai.inference.model_loader import ModelLoader
from ai.inference.supervised_predictor import SupervisedPredictor
from ai.inference.unsupervised_predictor import UnsupervisedPredictor
from ai.inference.hybrid_decision_engine import HybridDecisionEngine
from capture.feature_extractor import FeatureExtractor
from capture.flow_builder import NetworkFlow

logger = logging.getLogger(__name__)


class DetectionService:
    """
    Service central de détection qui orchestre le pipeline complet.
    Charge les modèles pré-entraînés et fait de l'inférence temps réel.
    """

    def __init__(self):
        self.loader = ModelLoader()
        self.supervised: Optional[SupervisedPredictor] = None
        self.unsupervised: Optional[UnsupervisedPredictor] = None
        self.decision_engine = HybridDecisionEngine()
        self.feature_extractor = FeatureExtractor()
        self._is_ready = False

    def is_ready(self) -> bool:
        """Vérifie si les modèles sont chargés et prêts."""
        return self._is_ready

    def initialize(self) -> bool:
        """
        Charge tous les artifacts AI et initialise les prédicteurs.
        Appelé au démarrage de l'application.

        Returns:
            True si l'initialisation est réussie.
        """
        if self._is_ready:
            return True

        logger.info("Initialisation du service de détection...")

        # Charger tous les artifacts
        if not self.loader.load_all():
            logger.warning(
                "⚠ Artifacts AI non disponibles. Le service fonctionnera sans AI. "
                "Placez les modèles pré-entraînés dans ai/artifacts/"
            )
            return False

        # Créer les prédicteurs
        self.supervised = SupervisedPredictor(
            model=self.loader.supervised_model,
            class_names=self.loader.pipeline.class_names,
        )

        self.unsupervised = UnsupervisedPredictor(
            model=self.loader.unsupervised_model,
        )

        self._is_ready = True
        logger.info("✓ Service de détection initialisé avec succès")
        return True

    def analyze_flow(
        self,
        flow: NetworkFlow,
        ip_reputation: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Analyse un flux réseau complet via le pipeline hybride.

        Pipeline :
        1. Extraire les features du flux
        2. Preprocessing (validation → scaling → selection)
        3. Inférence supervisée → classification
        4. Inférence non-supervisée → anomalie
        5. Fusion hybride → décision finale

        Args:
            flow: Flux réseau construit par FlowBuilder.
            ip_reputation: Score de réputation IP source [0,1].

        Returns:
            Résultat structuré avec attack_type, probability,
            anomaly_score, final_risk_score, severity, decision.
        """
        if not self.is_ready():
            return {"error": "Service non initialisé", "decision": "unknown"}

        # 1. Extraire les features
        features = self.feature_extractor.extract(flow)
        metadata = self.feature_extractor.get_flow_metadata(flow)

        # 2. Preprocessing
        try:
            processed = self.loader.pipeline.transform(features)
        except Exception as e:
            logger.error(f"Erreur de preprocessing : {e}")
            return {"error": str(e), "decision": "error"}

        # 3-5. Inférence + décision
        result = self._run_inference(processed, ip_reputation)
        result["flow_metadata"] = metadata

        return result

    def analyze_features(
        self,
        features: np.ndarray,
        ip_reputation: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Analyse un vecteur de features directement (déjà extrait).
        Utile pour les tests et le batch processing.
        """
        if not self.is_ready():
            return {"error": "Service non initialisé"}

        # Preprocessing
        try:
            processed = self.loader.pipeline.transform(features)
        except Exception as e:
            logger.error(f"Erreur de preprocessing : {e}")
            return {"error": str(e)}

        return self._run_inference(processed, ip_reputation)

    def _run_inference(
        self,
        processed_features: np.ndarray,
        ip_reputation: float = 0.0,
    ) -> Dict[str, Any]:
        """Exécute l'inférence supervisée + non-supervisée + fusion."""
        if not self.supervised or not self.unsupervised:
            return {"error": "Prédicteurs non initialisés"}

        # Supervisé
        supervised_result = self.supervised.predict(processed_features)

        # Non-supervisé
        unsupervised_result = self.unsupervised.predict(processed_features)

        # Fusion hybride
        decision = self.decision_engine.decide(
            supervised_result=supervised_result,
            unsupervised_result=unsupervised_result,
            ip_reputation=ip_reputation,
        )

        return {
            "supervised": supervised_result,
            "unsupervised": unsupervised_result,
            "decision": decision,
        }

    def analyze_batch(
        self,
        flows: List[NetworkFlow],
    ) -> List[Dict[str, Any]]:
        """Analyse un batch de flux."""
        return [self.analyze_flow(flow) for flow in flows]

    def get_status(self) -> Dict[str, Any]:
        """Retourne le statut complet du service."""
        return {
            "is_ready": self._is_ready,
            "artifacts": self.loader.get_status() if self.loader else {},
        }
