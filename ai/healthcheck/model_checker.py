"""
Vérification des fichiers modèles sur le disque.
Vérifie l'existence, la taille et la date de modification de chaque artifact AI.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Dict, Any, List

from ai.config.model_config import artifact_paths

logger = logging.getLogger(__name__)

# Liste des artifacts à vérifier avec leur description
ARTIFACT_REGISTRY = [
    {
        "name": "model_supervised.keras",
        "description": "Modèle de classification supervisée (Keras)",
        "path_attr": "supervised_model",
        "required": True,
    },
    {
        "name": "model_unsupervised.keras",
        "description": "Modèle autoencoder non-supervisé (Keras)",
        "path_attr": "unsupervised_model",
        "required": True,
    },
    {
        "name": "scaler.pkl",
        "description": "StandardScaler pré-adapté",
        "path_attr": "scaler",
        "required": True,
    },
    {
        "name": "encoder.pkl",
        "description": "LabelEncoder pour les types d'attaques",
        "path_attr": "encoder",
        "required": True,
    },
    {
        "name": "feature_selector.pkl",
        "description": "Sélecteur de fonctionnalités (SelectKBest/RFE)",
        "path_attr": "feature_selector",
        "required": False,
    },
]


def _format_size(size_bytes: int) -> str:
    """Formate une taille en bytes vers une chaîne lisible."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def check_artifact(name: str, path_attr: str, description: str, required: bool) -> Dict[str, Any]:
    """
    Vérifie un artifact individuel sur le disque.

    Returns:
        Dict avec statut, taille, date de modification, etc.
    """
    path = getattr(artifact_paths, path_attr)
    result = {
        "name": name,
        "description": description,
        "path": str(path),
        "required": required,
        "found": False,
        "size": None,
        "size_formatted": None,
        "last_modified": None,
        "last_modified_iso": None,
    }

    try:
        if path.exists():
            stat = os.stat(path)
            result["found"] = True
            result["size"] = stat.st_size
            result["size_formatted"] = _format_size(stat.st_size)
            mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            result["last_modified"] = mtime.strftime("%Y-%m-%d %H:%M:%S UTC")
            result["last_modified_iso"] = mtime.isoformat()
        else:
            logger.warning(f"Artifact manquant : {name} ({path})")
    except Exception as e:
        logger.error(f"Erreur vérification artifact {name} : {e}")
        result["error"] = str(e)

    return result


def check_all_artifacts() -> Dict[str, Any]:
    """
    Vérifie tous les artifacts enregistrés.

    Returns:
        Dict contenant le statut global et le détail de chaque artifact.
    """
    results = []
    for artifact in ARTIFACT_REGISTRY:
        result = check_artifact(
            name=artifact["name"],
            path_attr=artifact["path_attr"],
            description=artifact["description"],
            required=artifact["required"],
        )
        results.append(result)

    total = len(results)
    found = sum(1 for r in results if r["found"])
    missing_required = [r["name"] for r in results if r["required"] and not r["found"]]

    return {
        "artifacts_dir": str(artifact_paths.base_dir),
        "total_artifacts": total,
        "found_count": found,
        "missing_count": total - found,
        "all_required_present": len(missing_required) == 0,
        "missing_required": missing_required,
        "artifacts": results,
    }
