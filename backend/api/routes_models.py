"""
Routes pour le statut des modèles AI.
En mode production, les modèles sont figés (pas de versioning dynamique).
Inclut les endpoints de healthcheck : fichiers, chargement, inférence, compatibilité.
"""

import asyncio
import logging
from fastapi import APIRouter
from typing import Dict, Any

from ai.config.model_config import artifact_paths, inference_config

router = APIRouter(prefix="/api/models", tags=["Models"])
logger = logging.getLogger(__name__)


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


# =========================================================================
#  HEALTHCHECK ENDPOINTS — Diagnostic complet des modèles IA
# =========================================================================

@router.get("/healthcheck/files")
async def check_model_files() -> Dict[str, Any]:
    """
    Vérifie l'existence, la taille et la date de modification de chaque artifact.
    """
    from ai.healthcheck.model_checker import check_all_artifacts
    return await asyncio.to_thread(check_all_artifacts)


@router.get("/healthcheck/loading")
async def check_model_loading() -> Dict[str, Any]:
    """
    Teste le chargement runtime de chaque composant (modèles Keras + objets pickle).
    Attention : charge les modèles Keras (peut être lent).
    """
    try:
        from ai.healthcheck.inference_tester import test_loading
        return await asyncio.to_thread(test_loading)
    except Exception as e:
        logger.error(f"Healthcheck loading failed: {e}")
        return {"all_loaded": False, "error": str(e)}


@router.post("/healthcheck/inference")
async def run_inference_test() -> Dict[str, Any]:
    """
    Exécute un test d'inférence complet avec des données fictives.
    Teste le pipeline preprocessing + classification + anomaly score.
    """
    try:
        from ai.healthcheck.inference_tester import test_inference
        return await asyncio.to_thread(test_inference)
    except Exception as e:
        logger.error(f"Healthcheck inference failed: {e}")
        return {"success": False, "error": str(e)}


@router.get("/healthcheck/compatibility")
async def check_compatibility() -> Dict[str, Any]:
    """
    Vérifie la compatibilité entre tous les composants du pipeline :
    scaler, feature_selector, encoder, modèles Keras.
    Attention : charge les modèles Keras (peut être lent).
    """
    try:
        from ai.healthcheck.compatibility_validator import validate_compatibility
        return await asyncio.to_thread(validate_compatibility)
    except Exception as e:
        logger.error(f"Healthcheck compatibility failed: {e}")
        return {"compatible": False, "error": str(e)}


@router.get("/healthcheck/full")
async def full_healthcheck() -> Dict[str, Any]:
    """
    Diagnostic complet : fichiers + chargement pickle + compatibilité pickle.
    Exclut le chargement des modèles Keras (trop lourd) — utiliser les
    endpoints /loading et /compatibility séparément pour un diagnostic Keras.
    """
    from ai.healthcheck.model_checker import check_all_artifacts
    from ai.healthcheck.inference_tester import test_loading_pickle_only
    from ai.healthcheck.compatibility_validator import validate_compatibility_light

    files_result = {"error": "check failed"}
    loading_result = {"error": "check failed"}
    compat_result = {"error": "check failed"}

    try:
        files_result = await asyncio.to_thread(check_all_artifacts)
    except Exception as e:
        logger.error(f"Healthcheck files failed: {e}")
        files_result = {"all_required_present": False, "error": str(e)}

    try:
        loading_result = await asyncio.to_thread(test_loading_pickle_only)
    except Exception as e:
        logger.error(f"Healthcheck loading failed: {e}")
        loading_result = {"all_loaded": False, "error": str(e)}

    try:
        compat_result = await asyncio.to_thread(validate_compatibility_light)
    except Exception as e:
        logger.error(f"Healthcheck compatibility failed: {e}")
        compat_result = {"compatible": False, "error": str(e)}

    overall_healthy = (
        files_result.get("all_required_present", False)
        and loading_result.get("all_loaded", False)
        and compat_result.get("compatible", False)
    )

    return {
        "overall_healthy": overall_healthy,
        "files": files_result,
        "loading": loading_result,
        "compatibility": compat_result,
    }
