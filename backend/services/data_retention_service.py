"""
Service de rétention des données.
Supprime périodiquement les flux anciens pour limiter la croissance DB.
"""

import asyncio
import logging
from typing import Dict, Any, Optional

from backend.core.config import get_settings
from backend.database.connection import async_session_factory
from backend.database import repository

logger = logging.getLogger(__name__)
settings = get_settings()

_task: Optional[asyncio.Task] = None
_stop_event: Optional[asyncio.Event] = None


def _is_enabled() -> bool:
    return bool(settings.retention_enabled and settings.retention_flows_days > 0)


async def run_cleanup_once() -> int:
    """Exécute un cycle complet de nettoyage en batches et retourne le nombre supprimé."""
    if not _is_enabled():
        return 0

    total_deleted = 0

    # Limite de sécurité pour éviter une boucle trop longue en un seul cycle
    for _ in range(20):
        async with async_session_factory() as db:
            try:
                deleted = await repository.delete_old_flows_batch(
                    db=db,
                    older_than_days=settings.retention_flows_days,
                    batch_size=settings.retention_delete_batch_size,
                    keep_alerted_flows=settings.retention_keep_alerted_flows,
                )
                await db.commit()
            except Exception:
                await db.rollback()
                raise

        if deleted <= 0:
            break

        total_deleted += deleted

        # Si le dernier batch n'est pas plein, on considère le cycle terminé
        if deleted < settings.retention_delete_batch_size:
            break

    return total_deleted


async def _retention_loop() -> None:
    interval_seconds = max(60, settings.retention_run_interval_minutes * 60)
    logger.info(
        "Rétention activée: %s jours, intervalle=%s min, batch=%s, keep_alerted=%s",
        settings.retention_flows_days,
        settings.retention_run_interval_minutes,
        settings.retention_delete_batch_size,
        settings.retention_keep_alerted_flows,
    )

    while _stop_event and not _stop_event.is_set():
        try:
            deleted = await run_cleanup_once()
            if deleted > 0:
                logger.info("Rétention: %s flux anciens supprimés", deleted)
        except Exception as e:
            logger.warning("Rétention: échec du nettoyage (%s)", e)

        try:
            await asyncio.wait_for(_stop_event.wait(), timeout=interval_seconds)
        except asyncio.TimeoutError:
            pass


def start_scheduler() -> bool:
    """Démarre la tâche périodique de rétention."""
    global _task, _stop_event

    if not _is_enabled():
        logger.info("Rétention désactivée")
        return False

    if _task and not _task.done():
        return True

    _stop_event = asyncio.Event()
    _task = asyncio.create_task(_retention_loop())
    return True


async def stop_scheduler() -> None:
    """Arrête la tâche périodique de rétention."""
    global _task, _stop_event

    if _stop_event:
        _stop_event.set()

    if _task and not _task.done():
        try:
            await asyncio.wait_for(_task, timeout=5)
        except asyncio.TimeoutError:
            _task.cancel()

    _task = None
    _stop_event = None


def get_status() -> Dict[str, Any]:
    return {
        "enabled": _is_enabled(),
        "running": bool(_task and not _task.done()),
        "flows_days": settings.retention_flows_days,
        "interval_minutes": settings.retention_run_interval_minutes,
        "batch_size": settings.retention_delete_batch_size,
        "keep_alerted_flows": settings.retention_keep_alerted_flows,
    }
