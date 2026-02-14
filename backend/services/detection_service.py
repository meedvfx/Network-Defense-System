"""
Service de détection principal.
Orchestre le pipeline complet : features → preprocessing → AI → decision.

Architecture production : chargement des modèles pré-entraînés, inférence only.
"""

import logging
from typing import Dict, Any, Optional, List

import numpy as np

from ai.inference.model_loader import ModelLoader
from ai.inference import supervised_predictor
from ai.inference import unsupervised_predictor
from ai.inference import hybrid_decision_engine
from capture.feature_extractor import FeatureExtractor
from capture.flow_builder import NetworkFlow

logger = logging.getLogger(__name__)

_loader = ModelLoader()
_supervised: Optional[Dict[str, Any]] = None
_unsupervised: Optional[Dict[str, Any]] = None
_decision_engine = hybrid_decision_engine.create_engine()
_feature_extractor = FeatureExtractor()
_is_ready = False


def is_ready() -> bool:
    return _is_ready


def initialize() -> bool:
    """Charge tous les artifacts AI et initialise les prédicteurs."""
    global _supervised, _unsupervised, _is_ready

    if _is_ready:
        return True

    logger.info("Initialisation du service de détection...")

    if not _loader.load_all():
        logger.warning(
            "⚠ Artifacts AI non disponibles. Le service fonctionnera sans AI. "
            "Placez les modèles pré-entraînés dans ai/artifacts/"
        )
        return False

    _supervised = supervised_predictor.create_predictor(
        model=_loader.supervised_model,
        class_names=_loader.pipeline.class_names,
    )
    _unsupervised = unsupervised_predictor.create_predictor(model=_loader.unsupervised_model)

    _is_ready = True
    logger.info("✓ Service de détection initialisé avec succès")
    return True


def analyze_flow(flow: NetworkFlow, ip_reputation: float = 0.0) -> Dict[str, Any]:
    """Analyse un flux réseau complet via le pipeline hybride."""
    if not is_ready():
        return {"error": "Service non initialisé", "decision": "unknown"}

    features = _feature_extractor.extract(flow)
    metadata = _feature_extractor.get_flow_metadata(flow)

    try:
        processed = _loader.pipeline.transform(features)
    except Exception as e:
        logger.error(f"Erreur de preprocessing : {e}")
        return {"error": str(e), "decision": "error"}

    result = _run_inference(processed, ip_reputation)
    result["flow_metadata"] = metadata
    return result


def analyze_features(features: np.ndarray, ip_reputation: float = 0.0) -> Dict[str, Any]:
    """Analyse un vecteur de features directement (déjà extrait)."""
    if not is_ready():
        return {"error": "Service non initialisé"}

    try:
        processed = _loader.pipeline.transform(features)
    except Exception as e:
        logger.error(f"Erreur de preprocessing : {e}")
        return {"error": str(e)}

    return _run_inference(processed, ip_reputation)


def _run_inference(processed_features: np.ndarray, ip_reputation: float = 0.0) -> Dict[str, Any]:
    """Exécute l'inférence supervisée + non-supervisée + fusion."""
    if not _supervised or not _unsupervised:
        return {"error": "Prédicteurs non initialisés"}

    supervised_result = supervised_predictor.predict(_supervised, processed_features)
    unsupervised_result = unsupervised_predictor.predict(_unsupervised, processed_features)

    decision = hybrid_decision_engine.decide(
        engine=_decision_engine,
        supervised_result=supervised_result,
        unsupervised_result=unsupervised_result,
        ip_reputation=ip_reputation,
    )

    return {
        "supervised": supervised_result,
        "unsupervised": unsupervised_result,
        "decision": decision,
    }


def analyze_batch(flows: List[NetworkFlow]) -> List[Dict[str, Any]]:
    return [analyze_flow(flow) for flow in flows]


def get_status() -> Dict[str, Any]:
    return {
        "is_ready": _is_ready,
        "artifacts": _loader.get_status() if _loader else {},
    }
