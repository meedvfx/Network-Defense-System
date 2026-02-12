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


class SupervisedPredictor:
    """
    Classifie les flux réseau en types d'attaques connus.
    Le modèle a été entraîné sur CIC-IDS2017/2018.
    """

    def __init__(self, model, class_names: Optional[List[str]] = None):
        """
        Args:
            model: Modèle Keras chargé (déjà compilé).
            class_names: Liste ordonnée des noms de classes.
        """
        self.model = model
        self.class_names = class_names or []
        self.min_confidence = inference_config.min_classification_confidence

    def predict(self, features: np.ndarray) -> Dict[str, Any]:
        """
        Prédit le type d'attaque pour un échantillon.

        Args:
            features: Features préprocessées, shape (1, n_features).

        Returns:
            Dict avec attack_type, probability, et détails.
        """
        if features.ndim == 1:
            features = features.reshape(1, -1)

        # Inférence
        probabilities = self.model.predict(features, verbose=0)

        if probabilities.ndim > 1:
            probs = probabilities[0]
        else:
            probs = probabilities

        # Classe prédite
        predicted_index = int(np.argmax(probs))
        confidence = float(probs[predicted_index])

        # Nom de la classe
        if self.class_names and predicted_index < len(self.class_names):
            attack_type = self.class_names[predicted_index]
        else:
            attack_type = f"class_{predicted_index}"

        # Probas par classe
        class_probabilities = {}
        for i, p in enumerate(probs):
            name = self.class_names[i] if i < len(self.class_names) else f"class_{i}"
            class_probabilities[name] = round(float(p), 6)

        # Déterminer si c'est une attaque ou du trafic normal
        is_benign = attack_type.upper() in ("BENIGN", "NORMAL", "LEGITIMATE")
        is_confident = confidence >= self.min_confidence

        return {
            "attack_type": attack_type,
            "probability": round(confidence, 6),
            "is_attack": not is_benign and is_confident,
            "is_confident": is_confident,
            "predicted_index": predicted_index,
            "class_probabilities": class_probabilities,
        }

    def predict_batch(self, features: np.ndarray) -> List[Dict[str, Any]]:
        """
        Prédit pour un batch de samples.

        Args:
            features: Shape (n_samples, n_features).

        Returns:
            Liste de résultats de prédiction.
        """
        if features.ndim == 1:
            features = features.reshape(1, -1)

        probabilities = self.model.predict(
            features,
            batch_size=inference_config.batch_size,
            verbose=0,
        )

        results = []
        for i in range(probabilities.shape[0]):
            probs = probabilities[i]
            predicted_index = int(np.argmax(probs))
            confidence = float(probs[predicted_index])

            if self.class_names and predicted_index < len(self.class_names):
                attack_type = self.class_names[predicted_index]
            else:
                attack_type = f"class_{predicted_index}"

            is_benign = attack_type.upper() in ("BENIGN", "NORMAL", "LEGITIMATE")

            results.append({
                "attack_type": attack_type,
                "probability": round(confidence, 6),
                "is_attack": not is_benign and confidence >= self.min_confidence,
                "predicted_index": predicted_index,
            })

        return results

    def get_top_k(self, features: np.ndarray, k: int = 3) -> List[Dict[str, float]]:
        """Retourne les top-k classes les plus probables."""
        if features.ndim == 1:
            features = features.reshape(1, -1)

        probabilities = self.model.predict(features, verbose=0)[0]
        top_indices = np.argsort(probabilities)[::-1][:k]

        return [
            {
                "class": self.class_names[i] if i < len(self.class_names) else f"class_{i}",
                "probability": round(float(probabilities[i]), 6),
            }
            for i in top_indices
        ]
