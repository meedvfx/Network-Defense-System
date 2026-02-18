"""
Configuration centralisée pour le module AI.
Ce module définit les chemins vers les artefacts du modèle (modèles entraînés, scalers, encodeurs)
ainsi que les paramètres de configuration pour l'inférence et la classification des menaces.

Il agit comme une source unique de vérité pour la configuration de l'IA, assurant que
les chemins et les seuils sont cohérents dans toute l'application.

Aucun paramètre d'entraînement n'est défini ici : les modèles sont entraînés
séparément (par exemple via Google Colab ou Jupyter) puis les artefacts résultants
sont déposés dans le répertoire `ai/artifacts/`.
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
    """
    Gère les chemins vers les fichiers de modèles et les objets de prétraitement pré-entraînés.
    Cette classe fournit des propriétés pour accéder facilement aux emplacements des fichiers .keras et .pkl
    nécessaires au pipeline d'inférence.
    """

    base_dir: Path = ARTIFACTS_DIR

    @property
    def supervised_model(self) -> Path:
        """Chemin vers le modèle de classification supervisée (.keras)."""
        return self.base_dir / "model_supervised.keras"

    @property
    def unsupervised_model(self) -> Path:
        """Chemin vers le modèle d'autoencodeur non supervisé (.keras)."""
        return self.base_dir / "model_unsupervised.keras"

    @property
    def scaler(self) -> Path:
        """Chemin vers le StandardScaler pré-adapté (.pkl)."""
        return self.base_dir / "scaler.pkl"

    @property
    def encoder(self) -> Path:
        """Chemin vers le LabelEncoder pour les types d'attaques (.pkl)."""
        return self.base_dir / "encoder.pkl"

    @property
    def feature_selector(self) -> Path:
        """Chemin vers le sélecteur de fonctionnalités (SelectKBest/RFE) (.pkl)."""
        return self.base_dir / "feature_selector.pkl"

    def all_exist(self) -> bool:
        """
        Vérifie que tous les artefacts requis existent sur le disque.
        Retourne True si tous les fichiers sont présents, False sinon.
        """
        return all([
            self.supervised_model.exists(),
            self.unsupervised_model.exists(),
            self.scaler.exists(),
            self.encoder.exists(),
            self.feature_selector.exists(),
        ])

    def missing_artifacts(self) -> List[str]:
        """
        Identifie et retourne la liste des noms des artefacts manquants.
        Utile pour le débogage et les vérifications de santé du système.
        """
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
    """
    Paramètres de configuration pour le pipeline d'inférence en production.
    Ces paramètres contrôlent la sensibilité de la détection et la logique de décision.
    """

    # Seuil d'anomalie : Multiplicateur k pour le seuil dynamique (μ + kσ).
    # Une valeur plus élevée rend la détection moins sensible aux variations mineures.
    anomaly_threshold_k: float = 3.0

    # Seuil de confiance minimum pour accepter une classification du modèle supervisé.
    # Si la probabilité est inférieure, la prédiction peut être considérée comme incertaine.
    min_classification_confidence: float = 0.5

    # Poids pour le moteur de décision hybride.
    # Détermine l'importance relative de chaque composant dans le score de risque final.
    weight_supervised: float = 0.50   # 50% de l'importance pour la classification connue
    weight_unsupervised: float = 0.30 # 30% pour la détection d'anomalies (0-day)
    weight_reputation: float = 0.20   # 20% pour la réputation IP (TI)

    # Seuils pour la décision finale basée sur le score de risque calculé.
    threshold_attack: float = 0.7      # Risque > 0.7 → Attaque confirmée
    threshold_suspicious: float = 0.4   # 0.4 < Risque <= 0.7 → Activité suspecte
    # Risque <= 0.4 → Trafic normal

    # Taille du lot (batch size) pour l'inférence optimisée.
    # Permet de traiter plusieurs flux simultanément pour améliorer le débit.
    batch_size: int = 64

    # Indicateur pour effectuer un "warm-up" (chauffage) du modèle au démarrage.
    # Exécute une inférence fictive pour charger le graphe TensorFlow en mémoire et éviter la latence à la première requête.
    warmup_on_load: bool = True


@dataclass
class SeverityConfig:
    """
    Configuration pour le mappage des scores de risque vers des niveaux de sévérité textuels.
    Utilisé pour l'affichage dans le dashboard et le tri des alertes.
    """

    # Seuils de score pour chaque niveau de sévérité.
    thresholds: Dict[str, float] = field(default_factory=lambda: {
        "critical": 0.85,   # Score >= 0.85 → Critique
        "high": 0.65,       # Score >= 0.65 → Élevé
        "medium": 0.40,     # Score >= 0.40 → Moyen
        "low": 0.0,         # Score < 0.40  → Faible
    })

    def get_severity(self, score: float) -> str:
        """
        Détermine le niveau de sévérité basé sur le score de risque donné.
        
        Args:
            score (float): Le score de risque calculé (entre 0.0 et 1.0).
            
        Returns:
            str: Le niveau de sévérité ('critical', 'high', 'medium', 'low').
        """
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
