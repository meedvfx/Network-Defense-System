"""
Exceptions métier personnalisées pour le backend.
"""


def nds_error(message: str, code: str = "NDS_ERROR") -> RuntimeError:
    """Construit une erreur métier standardisée."""
    return RuntimeError(f"[{code}] {message}")


def model_not_found_error(model_type: str, version: str) -> RuntimeError:
    return nds_error(
        message=f"Modèle '{model_type}' version '{version}' introuvable",
        code="MODEL_NOT_FOUND",
    )


def capture_error(message: str) -> RuntimeError:
    return nds_error(message=message, code="CAPTURE_ERROR")


def geolocation_error(ip: str, reason: str) -> RuntimeError:
    return nds_error(
        message=f"Géolocalisation impossible pour {ip}: {reason}",
        code="GEO_ERROR",
    )


def inference_error(message: str) -> RuntimeError:
    return nds_error(message=message, code="INFERENCE_ERROR")


def database_error(message: str) -> RuntimeError:
    return nds_error(message=message, code="DB_ERROR")


def retraining_error(message: str) -> RuntimeError:
    return nds_error(message=message, code="RETRAIN_ERROR")
