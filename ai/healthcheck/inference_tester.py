"""
Test d'inférence des modèles IA.
Vérifie que les modèles peuvent être chargés et produisent des résultats valides
avec des données fictives de test.
"""

import logging
import time
import traceback
from typing import Dict, Any, Optional

import numpy as np

from ai.config.model_config import artifact_paths, inference_config

logger = logging.getLogger(__name__)


def _try_load_pickle(path) -> Dict[str, Any]:
    """Tente de charger un fichier pickle/joblib."""
    result = {
        "status": "not_tested",
        "loaded": False,
        "error": None,
        "load_time_ms": None,
        "object_type": None,
    }

    if not path.exists():
        result["status"] = "missing"
        result["error"] = f"Fichier introuvable : {path.name}"
        return result

    try:
        import joblib
        start = time.time()
        obj = joblib.load(str(path))
        elapsed = (time.time() - start) * 1000
        result["status"] = "loaded"
        result["loaded"] = True
        result["load_time_ms"] = round(elapsed, 2)
        result["object_type"] = type(obj).__name__
        return result
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        logger.error(f"Erreur chargement {path.name} : {e}")
        return result


def _try_load_keras(path) -> Dict[str, Any]:
    """Tente de charger un modèle Keras."""
    result = {
        "status": "not_tested",
        "loaded": False,
        "error": None,
        "load_time_ms": None,
        "input_shape": None,
        "output_shape": None,
        "param_count": None,
    }

    if not path.exists():
        result["status"] = "missing"
        result["error"] = f"Fichier introuvable : {path.name}"
        return result

    try:
        import tensorflow as tf
        start = time.time()
        model = tf.keras.models.load_model(str(path), compile=False)
        elapsed = (time.time() - start) * 1000
        result["status"] = "loaded"
        result["loaded"] = True
        result["load_time_ms"] = round(elapsed, 2)
        result["input_shape"] = str(model.input_shape)
        result["output_shape"] = str(model.output_shape)
        result["param_count"] = int(model.count_params())
        return result
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        logger.error(f"Erreur chargement modèle Keras {path.name} : {e}")
        return result


def test_loading() -> Dict[str, Any]:
    """
    Teste le chargement runtime de tous les artifacts.
    Ne garde pas les modèles en mémoire — uniquement un test de chargement.

    Returns:
        Dict avec le statut de chargement de chaque composant.
    """
    results = {}

    # Modèles Keras
    results["model_supervised"] = _try_load_keras(artifact_paths.supervised_model)
    results["model_unsupervised"] = _try_load_keras(artifact_paths.unsupervised_model)

    # Objets pickle
    results["scaler"] = _try_load_pickle(artifact_paths.scaler)
    results["encoder"] = _try_load_pickle(artifact_paths.encoder)
    results["feature_selector"] = _try_load_pickle(artifact_paths.feature_selector)

    all_loaded = all(r["loaded"] for r in results.values())
    loaded_count = sum(1 for r in results.values() if r["loaded"])
    total_count = len(results)
    errors = {k: v["error"] for k, v in results.items() if v["error"]}

    return {
        "all_loaded": all_loaded,
        "loaded_count": loaded_count,
        "total_count": total_count,
        "components": results,
        "errors": errors if errors else None,
    }


def test_loading_pickle_only() -> Dict[str, Any]:
    """
    Version légère : teste uniquement le chargement des objets pickle (scaler, encoder, feature_selector).
    N'essaie PAS de charger les modèles Keras (trop lourd / risque crash TF multi-thread).
    Vérifie simplement l'existence des fichiers Keras.

    Returns:
        Dict avec le statut de chargement de chaque composant.
    """
    results = {}

    # Modèles Keras — vérification d'existence seulement (pas de chargement)
    for name, path in [
        ("model_supervised", artifact_paths.supervised_model),
        ("model_unsupervised", artifact_paths.unsupervised_model),
    ]:
        if path.exists():
            results[name] = {
                "status": "found",
                "loaded": True,
                "error": None,
                "load_time_ms": None,
                "note": "Existence vérifiée (chargement Keras non testé pour performance)",
            }
        else:
            results[name] = {
                "status": "missing",
                "loaded": False,
                "error": f"Fichier introuvable : {path.name}",
                "load_time_ms": None,
            }

    # Objets pickle — chargement réel (léger)
    results["scaler"] = _try_load_pickle(artifact_paths.scaler)
    results["encoder"] = _try_load_pickle(artifact_paths.encoder)
    results["feature_selector"] = _try_load_pickle(artifact_paths.feature_selector)

    all_loaded = all(r["loaded"] for r in results.values())
    pickle_keys = {"scaler", "encoder", "feature_selector"}
    keras_keys = {"model_supervised", "model_unsupervised"}
    pickle_all_loaded = all(r["loaded"] for k, r in results.items() if k in pickle_keys)
    keras_all_found = all(r["loaded"] for k, r in results.items() if k in keras_keys)
    loaded_count = sum(1 for r in results.values() if r["loaded"])
    total_count = len(results)
    errors = {k: v["error"] for k, v in results.items() if v["error"]}

    return {
        "all_loaded": all_loaded,
        "pickle_all_loaded": pickle_all_loaded,
        "keras_all_found": keras_all_found,
        "loaded_count": loaded_count,
        "total_count": total_count,
        "components": results,
        "errors": errors if errors else None,
    }


def test_inference() -> Dict[str, Any]:
    """
    Exécute un test d'inférence complet avec des données fictives.
    
    Étapes :
    1. Charge tous les artifacts
    2. Génère un vecteur de features factice
    3. Applique le pipeline de preprocessing
    4. Teste le modèle supervisé (classification)
    5. Teste le modèle non-supervisé (anomaly score)

    Returns:
        Dict avec les résultats d'inférence ou les erreurs rencontrées.
    """
    result = {
        "success": False,
        "supervised_test": None,
        "unsupervised_test": None,
        "pipeline_test": None,
        "total_time_ms": None,
        "error": None,
    }

    total_start = time.time()

    try:
        import tensorflow as tf
        import joblib

        # 1. Charger les composants
        scaler_path = artifact_paths.scaler
        if not scaler_path.exists():
            result["error"] = "Scaler introuvable — impossible de tester l'inférence"
            return result

        scaler = joblib.load(str(scaler_path))

        feature_selector = None
        if artifact_paths.feature_selector.exists():
            feature_selector = joblib.load(str(artifact_paths.feature_selector))

        encoder = None
        if artifact_paths.encoder.exists():
            encoder = joblib.load(str(artifact_paths.encoder))

        # 2. Déterminer le nombre de features attendues par le scaler
        n_features_in = getattr(scaler, 'n_features_in_', None)
        if n_features_in is None:
            result["error"] = "Impossible de déterminer le nombre de features attendu par le scaler"
            return result

        # 3. Générer des données fictives
        dummy_features = np.random.randn(1, n_features_in).astype(np.float32)

        # 4. Tester le pipeline de preprocessing
        pipeline_result = {"status": "not_tested"}
        try:
            start = time.time()
            scaled = scaler.transform(dummy_features)
            if feature_selector is not None:
                processed = feature_selector.transform(scaled)
            else:
                processed = scaled
            processed = processed.astype(np.float32)
            pipeline_elapsed = (time.time() - start) * 1000
            pipeline_result = {
                "status": "success",
                "input_shape": list(dummy_features.shape),
                "output_shape": list(processed.shape),
                "time_ms": round(pipeline_elapsed, 2),
            }
        except Exception as e:
            pipeline_result = {
                "status": "error",
                "error": str(e),
            }
            result["pipeline_test"] = pipeline_result
            result["error"] = f"Échec pipeline preprocessing : {e}"
            return result

        result["pipeline_test"] = pipeline_result

        # 5. Tester le modèle supervisé
        sup_result = {"status": "not_tested"}
        if artifact_paths.supervised_model.exists():
            try:
                model_sup = tf.keras.models.load_model(
                    str(artifact_paths.supervised_model), compile=False
                )
                start = time.time()
                prediction = model_sup.predict(processed, verbose=0)
                sup_elapsed = (time.time() - start) * 1000

                predicted_class = int(np.argmax(prediction[0]))
                confidence = float(np.max(prediction[0]))
                class_label = f"class_{predicted_class}"
                if encoder and hasattr(encoder, 'classes_'):
                    if predicted_class < len(encoder.classes_):
                        class_label = str(encoder.classes_[predicted_class])

                sup_result = {
                    "status": "success",
                    "predicted_class": predicted_class,
                    "class_label": class_label,
                    "confidence": round(confidence, 6),
                    "output_shape": list(prediction.shape),
                    "num_classes": int(prediction.shape[-1]),
                    "time_ms": round(sup_elapsed, 2),
                }
            except Exception as e:
                sup_result = {
                    "status": "error",
                    "error": str(e),
                }
        else:
            sup_result["status"] = "missing"
            sup_result["error"] = "Modèle supervisé introuvable"

        result["supervised_test"] = sup_result

        # 6. Tester le modèle non-supervisé (autoencoder)
        unsup_result = {"status": "not_tested"}
        if artifact_paths.unsupervised_model.exists():
            try:
                model_unsup = tf.keras.models.load_model(
                    str(artifact_paths.unsupervised_model), compile=False
                )
                start = time.time()
                reconstruction = model_unsup.predict(processed, verbose=0)
                unsup_elapsed = (time.time() - start) * 1000

                # Calcul de l'erreur de reconstruction (MSE)
                mse = float(np.mean((processed - reconstruction) ** 2))

                # Charger les stats de seuil si disponibles
                threshold_stats_path = artifact_paths.base_dir / "threshold_stats.pkl"
                threshold = None
                is_anomaly = None
                if threshold_stats_path.exists():
                    stats = joblib.load(str(threshold_stats_path))
                    baseline_mean = stats.get("mean", 0.01)
                    baseline_std = stats.get("std", 0.005)
                    threshold = baseline_mean + inference_config.anomaly_threshold_k * baseline_std
                    is_anomaly = mse > threshold

                unsup_result = {
                    "status": "success",
                    "reconstruction_error": round(mse, 8),
                    "threshold": round(threshold, 8) if threshold is not None else None,
                    "is_anomaly": is_anomaly,
                    "output_shape": list(reconstruction.shape),
                    "time_ms": round(unsup_elapsed, 2),
                }
            except Exception as e:
                unsup_result = {
                    "status": "error",
                    "error": str(e),
                }
        else:
            unsup_result["status"] = "missing"
            unsup_result["error"] = "Modèle non-supervisé introuvable"

        result["unsupervised_test"] = unsup_result

        # Succès global
        all_tested = [
            pipeline_result.get("status") == "success",
            sup_result.get("status") in ("success", "missing"),
            unsup_result.get("status") in ("success", "missing"),
        ]
        result["success"] = all(all_tested) and sup_result.get("status") != "missing"

    except ImportError as e:
        result["error"] = f"Dépendance manquante : {e}"
    except Exception as e:
        result["error"] = f"Erreur inattendue : {e}"
        logger.error(f"Erreur test d'inférence : {traceback.format_exc()}")

    result["total_time_ms"] = round((time.time() - total_start) * 1000, 2)
    return result
