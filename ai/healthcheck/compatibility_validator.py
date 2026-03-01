"""
Vérification de la compatibilité entre les composants du pipeline AI.
Vérifie la cohérence des dimensions (features) entre :
- Scaler ↔ Modèles
- Feature Selector ↔ Modèles
- Encoder ↔ Modèle supervisé
"""

import logging
from typing import Dict, Any, List, Optional

from ai.config.model_config import artifact_paths

logger = logging.getLogger(__name__)


def validate_compatibility() -> Dict[str, Any]:
    """
    Effectue une vérification complète de compatibilité entre tous les composants.

    Vérifie :
    1. Cohérence nombre de features : scaler.n_features_in_ vs modèle input_shape
    2. Cohérence feature_selector : entrée/sortie compatible avec scaler et modèles
    3. Cohérence encoder : nombre de classes vs output shape du modèle supervisé

    Returns:
        Dict avec les résultats de compatibilité et les éventuels warnings.
    """
    result = {
        "compatible": True,
        "checks": [],
        "warnings": [],
        "errors": [],
        "dimensions": {},
    }

    try:
        import joblib

        # 1. Charger le scaler
        scaler = None
        scaler_n_features = None
        if artifact_paths.scaler.exists():
            try:
                scaler = joblib.load(str(artifact_paths.scaler))
                scaler_n_features = getattr(scaler, 'n_features_in_', None)
                result["dimensions"]["scaler_input_features"] = scaler_n_features
                result["checks"].append({
                    "check": "scaler_loaded",
                    "status": "pass",
                    "detail": f"Scaler chargé — attend {scaler_n_features} features en entrée",
                })
            except Exception as e:
                result["errors"].append(f"Erreur chargement scaler : {e}")
                result["compatible"] = False
                result["checks"].append({
                    "check": "scaler_loaded",
                    "status": "fail",
                    "detail": str(e),
                })
        else:
            result["errors"].append("Scaler introuvable")
            result["compatible"] = False
            result["checks"].append({
                "check": "scaler_loaded",
                "status": "fail",
                "detail": "Fichier scaler.pkl introuvable",
            })

        # 2. Charger le feature selector
        selector = None
        selector_n_features_in = None
        selector_n_features_out = None
        if artifact_paths.feature_selector.exists():
            try:
                selector = joblib.load(str(artifact_paths.feature_selector))
                selector_n_features_in = getattr(selector, 'n_features_in_', None)
                selector_n_features_out = getattr(selector, 'n_features_', None)
                if selector_n_features_out is None and hasattr(selector, 'get_support'):
                    selector_n_features_out = int(selector.get_support().sum())

                result["dimensions"]["selector_input_features"] = selector_n_features_in
                result["dimensions"]["selector_output_features"] = selector_n_features_out

                result["checks"].append({
                    "check": "feature_selector_loaded",
                    "status": "pass",
                    "detail": f"Feature selector chargé — {selector_n_features_in} → {selector_n_features_out} features",
                })

                # Vérifier cohérence scaler → selector
                if scaler_n_features and selector_n_features_in:
                    if scaler_n_features == selector_n_features_in:
                        result["checks"].append({
                            "check": "scaler_selector_compatibility",
                            "status": "pass",
                            "detail": f"Scaler ({scaler_n_features}) → Selector ({selector_n_features_in}) : compatible",
                        })
                    else:
                        result["errors"].append(
                            f"Incompatibilité scaler → selector : {scaler_n_features} ≠ {selector_n_features_in}"
                        )
                        result["compatible"] = False
                        result["checks"].append({
                            "check": "scaler_selector_compatibility",
                            "status": "fail",
                            "detail": f"Scaler produit {scaler_n_features} features mais selector attend {selector_n_features_in}",
                        })
            except Exception as e:
                result["warnings"].append(f"Erreur chargement feature selector : {e}")
                result["checks"].append({
                    "check": "feature_selector_loaded",
                    "status": "warning",
                    "detail": str(e),
                })
        else:
            result["warnings"].append("Feature selector introuvable (optionnel)")
            result["checks"].append({
                "check": "feature_selector_loaded",
                "status": "skipped",
                "detail": "feature_selector.pkl introuvable (optionnel)",
            })

        # 3. Charger l'encoder
        encoder = None
        encoder_n_classes = None
        if artifact_paths.encoder.exists():
            try:
                encoder = joblib.load(str(artifact_paths.encoder))
                if hasattr(encoder, 'classes_'):
                    encoder_n_classes = len(encoder.classes_)
                    result["dimensions"]["encoder_classes"] = encoder_n_classes
                    result["dimensions"]["class_names"] = list(encoder.classes_)
                result["checks"].append({
                    "check": "encoder_loaded",
                    "status": "pass",
                    "detail": f"Encoder chargé — {encoder_n_classes} classes",
                })
            except Exception as e:
                result["warnings"].append(f"Erreur chargement encoder : {e}")
                result["checks"].append({
                    "check": "encoder_loaded",
                    "status": "warning",
                    "detail": str(e),
                })
        else:
            result["warnings"].append("Encoder introuvable (optionnel)")
            result["checks"].append({
                "check": "encoder_loaded",
                "status": "skipped",
                "detail": "encoder.pkl introuvable (optionnel)",
            })

        # 4. Charger les modèles Keras et vérifier les dimensions
        try:
            import tensorflow as tf

            # Modèle supervisé
            if artifact_paths.supervised_model.exists():
                try:
                    model_sup = tf.keras.models.load_model(
                        str(artifact_paths.supervised_model), compile=False
                    )
                    sup_input_dim = model_sup.input_shape[-1]
                    sup_output_dim = model_sup.output_shape[-1]
                    result["dimensions"]["supervised_input_features"] = sup_input_dim
                    result["dimensions"]["supervised_output_classes"] = sup_output_dim

                    # Vérifier compatibilité pipeline → modèle supervisé
                    expected_input = selector_n_features_out if selector_n_features_out else scaler_n_features
                    if expected_input and sup_input_dim:
                        if expected_input == sup_input_dim:
                            result["checks"].append({
                                "check": "pipeline_supervised_compatibility",
                                "status": "pass",
                                "detail": f"Pipeline ({expected_input}) → Modèle supervisé ({sup_input_dim}) : compatible",
                            })
                        else:
                            result["errors"].append(
                                f"Incompatibilité pipeline → modèle supervisé : {expected_input} ≠ {sup_input_dim}"
                            )
                            result["compatible"] = False
                            result["checks"].append({
                                "check": "pipeline_supervised_compatibility",
                                "status": "fail",
                                "detail": f"Pipeline produit {expected_input} features mais modèle attend {sup_input_dim}",
                            })

                    # Vérifier encoder vs output
                    if encoder_n_classes and sup_output_dim:
                        if encoder_n_classes == sup_output_dim:
                            result["checks"].append({
                                "check": "encoder_supervised_compatibility",
                                "status": "pass",
                                "detail": f"Encoder ({encoder_n_classes} classes) = Modèle supervisé output ({sup_output_dim}) : compatible",
                            })
                        else:
                            result["errors"].append(
                                f"Incompatibilité encoder → modèle : {encoder_n_classes} classes vs {sup_output_dim} outputs"
                            )
                            result["compatible"] = False
                            result["checks"].append({
                                "check": "encoder_supervised_compatibility",
                                "status": "fail",
                                "detail": f"Encoder a {encoder_n_classes} classes mais modèle produit {sup_output_dim} outputs",
                            })

                except Exception as e:
                    result["errors"].append(f"Erreur chargement modèle supervisé : {e}")
                    result["compatible"] = False
                    result["checks"].append({
                        "check": "supervised_model_loaded",
                        "status": "fail",
                        "detail": str(e),
                    })
            else:
                result["errors"].append("Modèle supervisé introuvable")
                result["compatible"] = False
                result["checks"].append({
                    "check": "supervised_model_loaded",
                    "status": "fail",
                    "detail": "model_supervised.keras introuvable",
                })

            # Modèle non-supervisé
            if artifact_paths.unsupervised_model.exists():
                try:
                    model_unsup = tf.keras.models.load_model(
                        str(artifact_paths.unsupervised_model), compile=False
                    )
                    unsup_input_dim = model_unsup.input_shape[-1]
                    unsup_output_dim = model_unsup.output_shape[-1]
                    result["dimensions"]["unsupervised_input_features"] = unsup_input_dim
                    result["dimensions"]["unsupervised_output_features"] = unsup_output_dim

                    # Vérifier compatibilité pipeline → autoencoder
                    expected_input = selector_n_features_out if selector_n_features_out else scaler_n_features
                    if expected_input and unsup_input_dim:
                        if expected_input == unsup_input_dim:
                            result["checks"].append({
                                "check": "pipeline_unsupervised_compatibility",
                                "status": "pass",
                                "detail": f"Pipeline ({expected_input}) → Autoencoder ({unsup_input_dim}) : compatible",
                            })
                        else:
                            result["errors"].append(
                                f"Incompatibilité pipeline → autoencoder : {expected_input} ≠ {unsup_input_dim}"
                            )
                            result["compatible"] = False
                            result["checks"].append({
                                "check": "pipeline_unsupervised_compatibility",
                                "status": "fail",
                                "detail": f"Pipeline produit {expected_input} features mais autoencoder attend {unsup_input_dim}",
                            })

                    # Vérifier symétrie autoencoder (input == output)
                    if unsup_input_dim == unsup_output_dim:
                        result["checks"].append({
                            "check": "autoencoder_symmetry",
                            "status": "pass",
                            "detail": f"Autoencoder symétrique : entrée ({unsup_input_dim}) = sortie ({unsup_output_dim})",
                        })
                    else:
                        result["warnings"].append(
                            f"Autoencoder asymétrique : entrée ({unsup_input_dim}) ≠ sortie ({unsup_output_dim})"
                        )
                        result["checks"].append({
                            "check": "autoencoder_symmetry",
                            "status": "warning",
                            "detail": f"Entrée ({unsup_input_dim}) ≠ Sortie ({unsup_output_dim})",
                        })

                except Exception as e:
                    result["errors"].append(f"Erreur chargement modèle non-supervisé : {e}")
                    result["compatible"] = False
                    result["checks"].append({
                        "check": "unsupervised_model_loaded",
                        "status": "fail",
                        "detail": str(e),
                    })
            else:
                result["errors"].append("Modèle non-supervisé introuvable")
                result["compatible"] = False
                result["checks"].append({
                    "check": "unsupervised_model_loaded",
                    "status": "fail",
                    "detail": "model_unsupervised.keras introuvable",
                })

        except ImportError:
            result["warnings"].append("TensorFlow non installé — vérification modèles Keras ignorée")
            result["checks"].append({
                "check": "tensorflow_available",
                "status": "warning",
                "detail": "TensorFlow non disponible pour vérifier les modèles Keras",
            })

    except ImportError as e:
        result["errors"].append(f"Dépendance manquante : {e}")
        result["compatible"] = False

    except Exception as e:
        result["errors"].append(f"Erreur inattendue : {e}")
        result["compatible"] = False
        logger.error(f"Erreur validation compatibilité : {e}")

    return result


def validate_compatibility_light() -> Dict[str, Any]:
    """
    Version légère de la validation de compatibilité.
    Vérifie uniquement les objets pickle (scaler, feature_selector, encoder)
    SANS charger les modèles Keras (évite les crashs TF et les temps de chargement longs).

    Vérifie :
    1. Scaler chargeable et n_features_in_
    2. Feature selector compatible avec le scaler
    3. Encoder chargeable et nombre de classes
    4. Existence des fichiers Keras (sans les charger)
    """
    result = {
        "compatible": True,
        "checks": [],
        "warnings": [],
        "errors": [],
        "dimensions": {},
    }

    try:
        import joblib

        # 1. Scaler
        scaler = None
        scaler_n_features = None
        if artifact_paths.scaler.exists():
            try:
                scaler = joblib.load(str(artifact_paths.scaler))
                scaler_n_features = getattr(scaler, 'n_features_in_', None)
                result["dimensions"]["scaler_input_features"] = scaler_n_features
                result["checks"].append({
                    "check": "scaler_loaded",
                    "status": "pass",
                    "detail": f"Scaler chargé — attend {scaler_n_features} features en entrée",
                })
            except Exception as e:
                result["errors"].append(f"Erreur chargement scaler : {e}")
                result["compatible"] = False
                result["checks"].append({
                    "check": "scaler_loaded",
                    "status": "fail",
                    "detail": str(e),
                })
        else:
            result["errors"].append("Scaler introuvable")
            result["compatible"] = False
            result["checks"].append({
                "check": "scaler_loaded",
                "status": "fail",
                "detail": "Fichier scaler.pkl introuvable",
            })

        # 2. Feature selector
        selector_n_features_out = None
        if artifact_paths.feature_selector.exists():
            try:
                selector = joblib.load(str(artifact_paths.feature_selector))
                selector_n_features_in = getattr(selector, 'n_features_in_', None)
                selector_n_features_out = getattr(selector, 'n_features_', None)
                if selector_n_features_out is None and hasattr(selector, 'get_support'):
                    selector_n_features_out = int(selector.get_support().sum())

                result["dimensions"]["selector_input_features"] = selector_n_features_in
                result["dimensions"]["selector_output_features"] = selector_n_features_out
                result["checks"].append({
                    "check": "feature_selector_loaded",
                    "status": "pass",
                    "detail": f"Feature selector chargé — {selector_n_features_in} → {selector_n_features_out} features",
                })

                if scaler_n_features and selector_n_features_in:
                    if scaler_n_features == selector_n_features_in:
                        result["checks"].append({
                            "check": "scaler_selector_compatibility",
                            "status": "pass",
                            "detail": f"Scaler ({scaler_n_features}) → Selector ({selector_n_features_in}) : compatible",
                        })
                    else:
                        result["errors"].append(
                            f"Incompatibilité scaler → selector : {scaler_n_features} ≠ {selector_n_features_in}"
                        )
                        result["compatible"] = False
                        result["checks"].append({
                            "check": "scaler_selector_compatibility",
                            "status": "fail",
                            "detail": f"Scaler produit {scaler_n_features} features mais selector attend {selector_n_features_in}",
                        })
            except Exception as e:
                result["warnings"].append(f"Erreur chargement feature selector : {e}")
                result["checks"].append({
                    "check": "feature_selector_loaded",
                    "status": "warning",
                    "detail": str(e),
                })
        else:
            result["warnings"].append("Feature selector introuvable (optionnel)")
            result["checks"].append({
                "check": "feature_selector_loaded",
                "status": "skipped",
                "detail": "feature_selector.pkl introuvable (optionnel)",
            })

        # 3. Encoder
        if artifact_paths.encoder.exists():
            try:
                encoder = joblib.load(str(artifact_paths.encoder))
                if hasattr(encoder, 'classes_'):
                    encoder_n_classes = len(encoder.classes_)
                    result["dimensions"]["encoder_classes"] = encoder_n_classes
                    result["dimensions"]["class_names"] = list(encoder.classes_)
                result["checks"].append({
                    "check": "encoder_loaded",
                    "status": "pass",
                    "detail": f"Encoder chargé — {encoder_n_classes if hasattr(encoder, 'classes_') else '?'} classes",
                })
            except Exception as e:
                result["warnings"].append(f"Erreur chargement encoder : {e}")
                result["checks"].append({
                    "check": "encoder_loaded",
                    "status": "warning",
                    "detail": str(e),
                })
        else:
            result["warnings"].append("Encoder introuvable (optionnel)")
            result["checks"].append({
                "check": "encoder_loaded",
                "status": "skipped",
                "detail": "encoder.pkl introuvable (optionnel)",
            })

        # 4. Vérification existence Keras (sans chargement)
        for name, path in [
            ("model_supervised.keras", artifact_paths.supervised_model),
            ("model_unsupervised.keras", artifact_paths.unsupervised_model),
        ]:
            if path.exists():
                result["checks"].append({
                    "check": f"{name}_exists",
                    "status": "pass",
                    "detail": f"{name} trouvé (chargement Keras non testé — utiliser /healthcheck/loading)",
                })
            else:
                result["errors"].append(f"{name} introuvable")
                result["compatible"] = False
                result["checks"].append({
                    "check": f"{name}_exists",
                    "status": "fail",
                    "detail": f"{name} introuvable",
                })

        # Pipeline output dimension
        pipeline_output = selector_n_features_out if selector_n_features_out else scaler_n_features
        if pipeline_output:
            result["dimensions"]["pipeline_output_features"] = pipeline_output

    except ImportError as e:
        result["errors"].append(f"Dépendance manquante : {e}")
        result["compatible"] = False

    except Exception as e:
        result["errors"].append(f"Erreur inattendue : {e}")
        result["compatible"] = False
        logger.error(f"Erreur validation compatibilité light : {e}")

    return result
