"""
Configuration centralisée pour le module AI.
Chemins des artifacts, paramètres d'inférence, seuils de décision.

Aucun paramètre d'entraînement ici : les modèles sont entraînés
séparément (Google Colab / Jupyter) puis déposés dans ai/artifacts/.
"""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict


# Racine du projet
PROJECT_ROOT = Path(__file__).parent.parent.parent

# Répertoire des artifacts AI pré-entraînés
ARTIFACTS_DIR = PROJECT_ROOT / "ai" / "artifacts"


@dataclass
class ArtifactPaths:
    """Chemins vers les fichiers de modèles et preprocessing pré-entraînés."""

    base_dir: Path = ARTIFACTS_DIR

    @property
    def supervised_model(self) -> Path:
        return self.base_dir / "model_supervised.keras"

    @property
    def unsupervised_model(self) -> Path:
        return self.base_dir / "model_unsupervised.keras"

    @property
    def scaler(self) -> Path:
        return self.base_dir / "scaler.pkl"

    @property
    def encoder(self) -> Path:
        return self.base_dir / "encoder.pkl"

    @property
    def feature_selector(self) -> Path:
        return self.base_dir / "feature_selector.pkl"

    def all_exist(self) -> bool:
        """Vérifie que tous les artifacts requis existent."""
        return all([
            self.supervised_model.exists(),
            self.unsupervised_model.exists(),
            self.scaler.exists(),
            self.encoder.exists(),
            self.feature_selector.exists(),
        ])

    def missing_artifacts(self) -> List[str]:
        """Retourne la liste des artifacts manquants."""
        missing = []
        for name, path in [
            ("model_supervised.keras", self.supervised_model),
            ("model_unsupervised.keras", self.unsupervised_model),
            ("scaler.pkl", self.scaler),
            ("encoder.pkl", self.encoder),
            ("feature_selector.pkl", self.feature_selector),
        ]:
            if not path.exists():
                missing.append(name)
        return missing


@dataclass
class InferenceConfig:
    """Paramètres d'inférence pour la production."""

    # Seuil d'anomalie (multiplicateur k pour μ + kσ)
    anomaly_threshold_k: float = 3.0

    # Seuil de confiance minimum pour classification supervisée
    min_classification_confidence: float = 0.5

    # Poids du moteur hybride
    weight_supervised: float = 0.50
    weight_unsupervised: float = 0.30
    weight_reputation: float = 0.20

    # Seuils de décision finale
    threshold_attack: float = 0.7      # > cette valeur → attaque confirmée
    threshold_suspicious: float = 0.4   # > cette valeur → suspect
    # <= threshold_suspicious → normal

    # Batch size pour inférence optimisée
    batch_size: int = 64

    # Warm-up au démarrage (pré-charge le graphe TF)
    warmup_on_load: bool = True


@dataclass
class SeverityConfig:
    """Mapping score → severity pour les alertes."""

    thresholds: Dict[str, float] = field(default_factory=lambda: {
        "critical": 0.85,   # score >= 0.85 → critical
        "high": 0.65,       # score >= 0.65 → high
        "medium": 0.40,     # score >= 0.40 → medium
        "low": 0.0,         # score < 0.40  → low
    })

    def get_severity(self, score: float) -> str:
        """Retourne le niveau de severity basé sur le score."""
        if score >= self.thresholds["critical"]:
            return "critical"
        elif score >= self.thresholds["high"]:
            return "high"
        elif score >= self.thresholds["medium"]:
            return "medium"
        return "low"


# ---- Instances globales ----
artifact_paths = ArtifactPaths()
inference_config = InferenceConfig()
severity_config = SeverityConfig()
