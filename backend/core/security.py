"""
Sécurité : CORS, rate limiting, validation API key.
"""

from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
from slowapi import Limiter
from slowapi.util import get_remote_address

from backend.core.config import get_settings

settings = get_settings()

# ---- API Key Header ----
# ---- API Key Header ----
# Définit le schéma de sécurité pour Swagger UI / OpenAPI
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    """
    Middleware de sécurité pour valider la clé API présente dans le header 'X-API-Key'.
    Compare la clé reçue avec celle définie dans la configuration.
    
    Raises:
        HTTPException(403): Si la clé est manquante ou incorrecte.
    
    Returns:
        str: La clé API valide.
    """
    if not api_key or api_key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Clé API invalide ou manquante. Accès refusé."
        )
    return api_key


# ---- Rate Limiter ----
# Initialise le limiteur de débit basé sur l'adresse IP du client.
limiter = Limiter(key_func=get_remote_address)


def get_cors_config() -> dict:
    """
    Génère la configuration CORS (Cross-Origin Resource Sharing) pour l'application FastAPI.
    Permet au frontend React (ou autres clients autorisés) d'interagir avec l'API.
    
    Returns:
        dict: Dictionnaire de configuration à passer à CORSMiddleware.
    """
    return {
        "allow_origins": settings.cors_origins_list,
        "allow_credentials": True, # Autorise les cookies et headers d'authentification
        "allow_methods": ["*"],    # Autorise toutes les méthodes HTTP (GET, POST, PUT, DELETE...)
        "allow_headers": ["*"],    # Autorise tous les headers
    }
