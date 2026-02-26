"""
Point d'entrée FastAPI - Network Defense System.
Initialise l'application, monte les routes et les middleware.
"""

import logging
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text

from backend.core.config import get_settings
from backend.core.security import limiter, get_cors_config
from backend.database.connection import init_db, close_db
from backend.database.redis_client import get_redis, close_redis
from backend.services import data_retention_service

# ---- Routes ----
from backend.api.routes_detection import router as detection_router
from backend.api.routes_alerts import router as alerts_router
from backend.api.routes_geo import router as geo_router
from backend.api.routes_dashboard import router as dashboard_router
from backend.api.routes_models import router as models_router
from backend.api.routes_feedback import router as feedback_router
from backend.api.routes_reporting import router as reporting_router
from backend.api.websocket_handler import websocket_endpoint

settings = get_settings()

# ---- Logging ----
logging.basicConfig(
    level=logging.DEBUG if settings.app_debug else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("NDS")


# ---- Lifecycle ----
# ---- Cycle de Vie (Startup/Shutdown) ----
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gestionnaire de contexte pour le cycle de vie de l'application.
    S'exécute au démarrage (avant d'accepter des requêtes) et à l'arrêt.
    """
    logger.info("=" * 60)
    logger.info("  Network Defense System - Démarrage")
    logger.info("=" * 60)

    # 1. Connexion Base de Données
    try:
        await init_db()
        logger.info("✓ PostgreSQL connecté")
    except Exception as e:
        logger.warning(f"✗ PostgreSQL indisponible : {e}")

    # 2. Lien Redis
    try:
        redis = await get_redis()
        await redis.ping()
        logger.info("✓ Redis connecté")
    except Exception as e:
        logger.warning(f"✗ Redis indisponible : {e}")

    logger.info(f"✓ API prête sur http://{settings.app_host}:{settings.app_port}")
    logger.info(f"✓ Swagger UI : http://{settings.app_host}:{settings.app_port}/docs")

    # 3. Démarrage des tâches de fond (Scheduler de rétention)
    try:
        if data_retention_service.start_scheduler():
            logger.info("✓ Scheduler de rétention démarré")
    except Exception as e:
        logger.warning(f"✗ Scheduler de rétention indisponible : {e}")

    logger.info("=" * 60)

    yield # L'application tourne ici

    # ---- Phase d'Arrêt ----
    logger.info("Arrêt du système...")
    await data_retention_service.stop_scheduler()
    await close_db()
    await close_redis()
    logger.info("Network Defense System arrêté")


# ---- Initialisation FastAPI ----
app = FastAPI(
    title="Network Defense System",
    description=(
        "Plateforme SOC intelligente avec Deep Learning hybride "
        "pour la détection d'intrusions réseau."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---- Middleware ----
# Sécurité CORS (Cross-Origin Resource Sharing)
cors_config = get_cors_config()
app.add_middleware(
    CORSMiddleware,
    **cors_config,
)

# Protection Rate Limiting (Anti-Bruteforce / DOS applicatif)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---- Montage des Routes ----
app.include_router(detection_router)
app.include_router(alerts_router)
app.include_router(geo_router)
app.include_router(dashboard_router)
app.include_router(models_router)
app.include_router(feedback_router)
app.include_router(reporting_router)

# ---- WebSocket ----
app.websocket("/ws/alerts")(websocket_endpoint)


# ---- Endpoints Système ----
@app.get("/", tags=["System"])
async def root():
    """Endpoint racine - vérification rapide."""
    return {
        "name": settings.app_name,
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs",
    }


@app.get("/health", tags=["System"])
async def health_check():
    """
    Health check complet pour Kubernetes ou Docker Healthcheck.
    Vérifie la connectivité DB et Redis.
    """
    health = {
        "status": "healthy",
        "services": {
            "api": True,
            "database": False,
            "redis": False,
        },
    }

    async def _db_check() -> None:
        from backend.database.connection import engine
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

    try:
        await asyncio.wait_for(_db_check(), timeout=1.5)
        health["services"]["database"] = True
    except Exception:
        pass

    async def _redis_check() -> None:
        redis = await get_redis()
        await redis.ping()

    try:
        await asyncio.wait_for(_redis_check(), timeout=1.5)
        health["services"]["redis"] = True
    except Exception:
        pass

    return health
