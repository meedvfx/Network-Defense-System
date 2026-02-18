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
    """
    Retourne l'instance unique du client Redis (Singleton Pattern).
    Si elle n'existe pas, elle est créée avec les paramètres de connexion.
    Utilise 'aioredis' pour une gestion asynchrone non-bloquante.
    """
    global redis_client
    if redis_client is None:
        redis_client = aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            max_connections=20, # Pool de connexions
        )
    return redis_client


async def close_redis():
    """Ferme proprement la connexion Redis (à appeler lors de l'arrêt de l'application)."""
    global redis_client
    if redis_client:
        await redis_client.close()
        redis_client = None


# ---- Helpers Cache (TTL Storage) ----

async def cache_set(key: str, value: Any, ttl: int = 3600) -> None:
    """
    Stocke une valeur temporaire dans Redis avec une durée de vie (TTL).
    Gère automatiquement la sérialisation JSON pour les dict/list.
    
    Args:
        key: Clé d'accès.
        value: Donnée à stocker (str, int, float, dict, list).
        ttl: Durée en secondes avant expiration (défaut: 1h).
    """
    r = await get_redis()
    if isinstance(value, (dict, list)):
        value = json.dumps(value)
    await r.set(key, value, ex=ttl)


async def cache_get(key: str) -> Optional[Any]:
    """
    Récupère une valeur du cache si elle existe.
    Désérialise automatiquement le JSON si applicable.
    """
    r = await get_redis()
    value = await r.get(key)
    if value:
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value
    return None


async def cache_delete(key: str) -> None:
    """Invalide manuellement une entrée du cache."""
    r = await get_redis()
    await r.delete(key)


# ---- Pub/Sub pour alertes temps réel ----

ALERT_CHANNEL = "nds:alerts:realtime"


async def publish_alert(alert_data: dict) -> None:
    """
    Publie une nouvelle alerte sur le canal Redis.
    Le serveur WebSocket (abonné à ce canal) la diffusera ensuite aux clients connectés (Dashboard).
    """
    r = await get_redis()
    await r.publish(ALERT_CHANNEL, json.dumps(alert_data))


async def get_alert_subscriber():
    """
    Crée un abonné (Subscriber) pour écouter les alertes en temps réel.
    Retourne l'objet pubsub qui permet d'itérer sur les messages.
    """
    r = await get_redis()
    pubsub = r.pubsub()
    await pubsub.subscribe(ALERT_CHANNEL)
    return pubsub


# ---- Métriques temps réel (Counters & Gauges) ----

async def increment_metric(metric_name: str, amount: int = 1) -> None:
    """
    Incrémente un compteur atomique dans Redis.
    Utile pour suivre le nombre de paquets traités, d'attaques bloquées, etc.
    """
    r = await get_redis()
    await r.incrby(f"nds:metrics:{metric_name}", amount)


async def get_metric(metric_name: str) -> int:
    """Lit la valeur actuelle d'un compteur."""
    r = await get_redis()
    value = await r.get(f"nds:metrics:{metric_name}")
    return int(value) if value else 0


async def set_threat_score(score: float) -> None:
    """Met à jour l'indicateur global de niveau de menace (Threat Level)."""
    r = await get_redis()
    await r.set("nds:threat_score", str(score))


async def get_threat_score() -> float:
    """Récupère l'indicateur global de niveau de menace."""
    r = await get_redis()
    value = await r.get("nds:threat_score")
    return float(value) if value else 0.0
