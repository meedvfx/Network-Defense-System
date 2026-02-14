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
    return {
        "model": model,
        "class_names": class_names or [],
        "min_confidence": inference_config.min_classification_confidence,
    }


def _is_benign_label(label: str) -> bool:
    return label.upper() in _BENIGN_LABELS


def _to_2d(features: np.ndarray) -> np.ndarray:
    if features.ndim == 1:
        return features.reshape(1, -1)
    return features


def _resolve_class_name(class_names: List[str], predicted_index: int) -> str:
    if class_names and predicted_index < len(class_names):
        return class_names[predicted_index]
    return f"class_{predicted_index}"


def predict(predictor: Dict[str, Any], features: np.ndarray) -> Dict[str, Any]:
    features = _to_2d(features)
    model = predictor["model"]
    class_names = predictor["class_names"]
    min_confidence = predictor["min_confidence"]

    probabilities = model.predict(features, verbose=0)
    probs = probabilities[0] if probabilities.ndim > 1 else probabilities

    predicted_index = int(np.argmax(probs))
    confidence = float(probs[predicted_index])
    attack_type = _resolve_class_name(class_names, predicted_index)

    class_probabilities = {
        _resolve_class_name(class_names, i): round(float(prob), 6)
        for i, prob in enumerate(probs)
    }

    is_benign = _is_benign_label(attack_type)
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
