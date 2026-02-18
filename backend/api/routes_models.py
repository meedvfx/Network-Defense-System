"""
Routes pour le statut des modèles AI.
En mode production, les modèles sont figés (pas de versioning dynamique).
"""

from fastapi import APIRouter
from typing import Dict, Any

from ai.config.model_config import artifact_paths, inference_config

router = APIRouter(prefix="/api/models", tags=["Models"])


@router.get("/status")
async def get_models_status() -> Dict[str, Any]:
    """
    Vérifie la présence et l'intégrité des fichiers modèles (artifacts).
    Retourne l'état de chaque composant (scaler, encoder, modèles Keras).
    """
    return {
        "artifacts_dir": str(artifact_paths.base_dir),
        "all_artifacts_present": artifact_paths.all_exist(),
        "missing_artifacts": artifact_paths.missing_artifacts(),
        "artifacts": {
            "model_supervised.keras": artifact_paths.supervised_model.exists(),
            "model_unsupervised.keras": artifact_paths.unsupervised_model.exists(),
            "scaler.pkl": artifact_paths.scaler.exists(),
            "encoder.pkl": artifact_paths.encoder.exists(),
            "feature_selector.pkl": artifact_paths.feature_selector.exists(),
        },
    }


@router.get("/config")
async def get_inference_config() -> Dict[str, Any]:
    """
    Expose la configuration d'inférence chargée en mémoire.
    Permet au frontend d'afficher les seuils et pondérations utilisés par l'IA.
    """
    return {
        "anomaly_threshold_k": inference_config.anomaly_threshold_k,
        "min_classification_confidence": inference_config.min_classification_confidence,
        "weights": {
            "supervised": inference_config.weight_supervised,
            "unsupervised": inference_config.weight_unsupervised,
            "reputation": inference_config.weight_reputation,
        },
        "thresholds": {
            "attack": inference_config.threshold_attack,
            "suspicious": inference_config.threshold_suspicious,
        },
        "batch_size": inference_config.batch_size,
        "warmup_on_load": inference_config.warmup_on_load,
    }
