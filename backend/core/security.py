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
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    """Valide la clé API dans le header X-API-Key."""
    if not api_key or api_key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Clé API invalide ou manquante"
        )
    return api_key


# ---- Rate Limiter ----
limiter = Limiter(key_func=get_remote_address)


def get_cors_config() -> dict:
    """Retourne la configuration CORS."""
    return {
        "allow_origins": settings.cors_origins_list,
        "allow_credentials": True,
        "allow_methods": ["*"],
        "allow_headers": ["*"],
    }
