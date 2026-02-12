"""
Client Redis pour le cache temps réel et le pub/sub.
Utilisé pour le cache GeoIP, les alertes temps réel et les métriques.
"""

import json
from typing import Optional, Any

import redis.asyncio as aioredis

from backend.core.config import get_settings

settings = get_settings()

# ---- Client Redis Global ----
redis_client: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    """Retourne le client Redis (singleton)."""
    global redis_client
    if redis_client is None:
        redis_client = aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            max_connections=20,
        )
    return redis_client


async def close_redis():
    """Ferme la connexion Redis."""
    global redis_client
    if redis_client:
        await redis_client.close()
        redis_client = None


# ---- Helpers Cache ----

async def cache_set(key: str, value: Any, ttl: int = 3600) -> None:
    """Stocke une valeur en cache avec TTL."""
    r = await get_redis()
    if isinstance(value, (dict, list)):
        value = json.dumps(value)
    await r.set(key, value, ex=ttl)


async def cache_get(key: str) -> Optional[Any]:
    """Récupère une valeur du cache."""
    r = await get_redis()
    value = await r.get(key)
    if value:
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value
    return None


async def cache_delete(key: str) -> None:
    """Supprime une clé du cache."""
    r = await get_redis()
    await r.delete(key)


# ---- Pub/Sub pour alertes temps réel ----

ALERT_CHANNEL = "nds:alerts:realtime"


async def publish_alert(alert_data: dict) -> None:
    """Publie une alerte sur le canal Redis pour broadcast WebSocket."""
    r = await get_redis()
    await r.publish(ALERT_CHANNEL, json.dumps(alert_data))


async def get_alert_subscriber():
    """Crée un subscriber pour les alertes temps réel."""
    r = await get_redis()
    pubsub = r.pubsub()
    await pubsub.subscribe(ALERT_CHANNEL)
    return pubsub


# ---- Métriques temps réel ----

async def increment_metric(metric_name: str, amount: int = 1) -> None:
    """Incrémente un compteur de métrique."""
    r = await get_redis()
    await r.incrby(f"nds:metrics:{metric_name}", amount)


async def get_metric(metric_name: str) -> int:
    """Récupère la valeur d'une métrique."""
    r = await get_redis()
    value = await r.get(f"nds:metrics:{metric_name}")
    return int(value) if value else 0


async def set_threat_score(score: float) -> None:
    """Met à jour le score de menace global."""
    r = await get_redis()
    await r.set("nds:threat_score", str(score))


async def get_threat_score() -> float:
    """Récupère le score de menace global."""
    r = await get_redis()
    value = await r.get("nds:threat_score")
    return float(value) if value else 0.0
