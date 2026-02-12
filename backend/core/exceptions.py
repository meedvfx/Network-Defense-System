"""
Exceptions métier personnalisées pour le backend.
"""


class NDSBaseException(Exception):
    """Exception de base pour Network Defense System."""

    def __init__(self, message: str, code: str = "NDS_ERROR"):
        self.message = message
        self.code = code
        super().__init__(self.message)


class ModelNotFoundError(NDSBaseException):
    """Modèle AI introuvable dans le registre."""

    def __init__(self, model_type: str, version: str):
        super().__init__(
            message=f"Modèle '{model_type}' version '{version}' introuvable",
            code="MODEL_NOT_FOUND"
        )


class CaptureError(NDSBaseException):
    """Erreur lors de la capture réseau."""

    def __init__(self, message: str):
        super().__init__(message=message, code="CAPTURE_ERROR")


class GeoLocationError(NDSBaseException):
    """Erreur lors de la géolocalisation d'une IP."""

    def __init__(self, ip: str, reason: str):
        super().__init__(
            message=f"Géolocalisation impossible pour {ip}: {reason}",
            code="GEO_ERROR"
        )


class InferenceError(NDSBaseException):
    """Erreur lors de l'inférence AI."""

    def __init__(self, message: str):
        super().__init__(message=message, code="INFERENCE_ERROR")


class DatabaseError(NDSBaseException):
    """Erreur d'accès à la base de données."""

    def __init__(self, message: str):
        super().__init__(message=message, code="DB_ERROR")


class RetrainingError(NDSBaseException):
    """Erreur lors du retraining d'un modèle."""

    def __init__(self, message: str):
        super().__init__(message=message, code="RETRAIN_ERROR")
