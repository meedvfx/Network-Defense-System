"""
Prédicteur supervisé pour la classification d'attaques réseau.
Utilise un modèle Keras pré-entraîné (MLP ou CNN-1D).

Entrée : features préprocessées (scaled + selected).
Sortie : attack_type, probability, class_probabilities.
"""

import logging
from typing import Dict, Any, Optional, List

import numpy as np

from ai.config.model_config import inference_config

logger = logging.getLogger(__name__)

_BENIGN_LABELS = {"BENIGN", "NORMAL", "LEGITIMATE"}


def create_predictor(model, class_names: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Crée une instance de prédicteur supervisé encapsulant le modèle et sa configuration.

    Args:
        model: Le modèle Keras chargé.
        class_names: Liste des noms de classes correspondant aux sorties du modèle.

    Returns:
        Dictionnaire contenant le modèle et ses paramètres de configuration.
    """
    return {
        "model": model,
        "class_names": class_names or [],
        "min_confidence": inference_config.min_classification_confidence,
    }


def _is_benign_label(label: str) -> bool:
    """Vérifie si une étiquette donnée correspond à un trafic normal."""
    return label.upper() in _BENIGN_LABELS


def _to_2d(features: np.ndarray) -> np.ndarray:
    """Assure que les features sont au format 2D (batch, features)."""
    if features.ndim == 1:
        return features.reshape(1, -1)
    return features


def _resolve_class_name(class_names: List[str], predicted_index: int) -> str:
    """Récupère le nom de la classe à partir de son index, avec gestion d'erreur."""
    if class_names and predicted_index < len(class_names):
        return class_names[predicted_index]
    return f"class_{predicted_index}"


def predict(predictor: Dict[str, Any], features: np.ndarray) -> Dict[str, Any]:
    """
    Effectue une prédiction sur un vecteur de features unique.

    Args:
        predictor: L'instance du prédicteur créée par create_predictor.
        features: Le vecteur de features à analyser.

    Returns:
        Dictionnaire contenant :
        - attack_type : Nom de la classe prédite.
        - probability : Confiance de la prédiction (0-1).
        - is_attack : Booléen indiquant si c'est une attaque confirmée.
        - is_confident : Si la confiance dépasse le seuil minimal.
        - class_probabilities : Détail des probabilités pour toutes les classes.
    """
    features = _to_2d(features)
    model = predictor["model"]
    class_names = predictor["class_names"]
    min_confidence = predictor["min_confidence"]

    # Inférence rapide (verbose=0 pour éviter le spam logs)
    probabilities = model.predict(features, verbose=0)
    probs = probabilities[0] if probabilities.ndim > 1 else probabilities

    predicted_index = int(np.argmax(probs))
    confidence = float(probs[predicted_index])
    attack_type = _resolve_class_name(class_names, predicted_index)

    # Création du dictionnaire détaillé des probabilités
    class_probabilities = {
        _resolve_class_name(class_names, i): round(float(prob), 6)
        for i, prob in enumerate(probs)
    }

    is_benign = _is_benign_label(attack_type)
    
    # Une prédiction est considérée comme une attaque seulement si :
    # 1. Ce n'est pas "BENIGN"
    # 2. La confiance est suffisante (évite les faux positifs sur les cas limites)
    is_confident = confidence >= min_confidence

    return {
        "attack_type": attack_type,
        "probability": round(confidence, 6),
        "is_attack": not is_benign and is_confident,
        "is_confident": is_confident,
        "predicted_index": predicted_index,
        "class_probabilities": class_probabilities,
    }


def predict_batch(predictor: Dict[str, Any], features: np.ndarray) -> List[Dict[str, Any]]:
    """
    Effectue des prédictions sur un lot (batch) de features.
    Optimisé pour traiter plusieurs flux simultanément.

    Args:
        features: Array 2D (n_samples, n_features).

    Returns:
        Liste de dictionnaires de résultats.
    """
    features = _to_2d(features)
    model = predictor["model"]
    class_names = predictor["class_names"]
    min_confidence = predictor["min_confidence"]

    probabilities = model.predict(
        features,
        batch_size=inference_config.batch_size,
        verbose=0,
    )

    results = []
    for probs in probabilities:
        predicted_index = int(np.argmax(probs))
        confidence = float(probs[predicted_index])
        attack_type = _resolve_class_name(class_names, predicted_index)
        is_benign = _is_benign_label(attack_type)

        results.append({
            "attack_type": attack_type,
            "probability": round(confidence, 6),
            "is_attack": not is_benign and confidence >= min_confidence,
            "predicted_index": predicted_index,
        })

    return results


def get_top_k(predictor: Dict[str, Any], features: np.ndarray, k: int = 3) -> List[Dict[str, float]]:
    features = _to_2d(features)
    model = predictor["model"]
    class_names = predictor["class_names"]

    probabilities = model.predict(features, verbose=0)[0]
    top_indices = np.argsort(probabilities)[::-1][:k]

    return [
        {
            "class": _resolve_class_name(class_names, i),
            "probability": round(float(probabilities[i]), 6),
        }
        for i in top_indices
    ]
