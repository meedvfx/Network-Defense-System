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


# ---- Configuration ----
# Rétention activée si enabled=True et durée > 0
def _is_enabled() -> bool:
    return bool(settings.retention_enabled and settings.retention_flows_days > 0)


async def run_cleanup_once() -> int:
    """
    Exécute un cycle de nettoyage unique.
    Supprime les flux plus vieux que 'retention_flows_days'.
    Procède par petits lots (batches) pour ne pas verrouiller la base de données.
    
    Returns:
        int: Nombre total de flux supprimés.
    """
    if not _is_enabled():
        return 0

    total_deleted = 0

    # Limite de sécurité pour éviter une boucle infinie si la DB réinsère plus vite qu'on supprime
    for _ in range(20):
        async with async_session_factory() as db:
            try:
                # Appel Repository pour suppression par lot
                deleted = await repository.delete_old_flows_batch(
                    db=db,
                    older_than_days=settings.retention_flows_days,
                    batch_size=settings.retention_delete_batch_size,
                    keep_alerted_flows=settings.retention_keep_alerted_flows,
                )
                await db.commit()
            except Exception:
                await db.rollback()
                raise # Remonte l'erreur pour logging

        if deleted <= 0:
            break # Plus rien à supprimer

        total_deleted += deleted

        # Si le dernier batch n'est pas plein, on considère que c'était le dernier
        if deleted < settings.retention_delete_batch_size:
            break

    return total_deleted


async def _retention_loop() -> None:
    """
    Boucle principale de la tâche de fond (Background Task).
    Attend l'intervalle configuré puis lance le nettoyage.
    """
    interval_seconds = max(60, settings.retention_run_interval_minutes * 60)
    logger.info(
        "Rétention activée: suppression flux > %s jours, intervalle=%s min, batch=%s, keep_alerted=%s",
        settings.retention_flows_days,
        settings.retention_run_interval_minutes,
        settings.retention_delete_batch_size,
        settings.retention_keep_alerted_flows,
    )

    while _stop_event and not _stop_event.is_set():
        try:
            logger.debug("Lancement du cycle de rétention...")
            deleted = await run_cleanup_once()
            if deleted > 0:
                logger.info("Rétention: %s flux anciens supprimés avec succès", deleted)
        except Exception as e:
            logger.warning("Rétention: échec du cycle de nettoyage (%s)", e)

        # Attente interruptible (pour arrêt propre)
        try:
            await asyncio.wait_for(_stop_event.wait(), timeout=interval_seconds)
        except asyncio.TimeoutError:
            pass # Timeout normal, on continue la boucle


def start_scheduler() -> bool:
    """
    Démarre la tâche périodique de rétention en arrière-plan (asyncio.create_task).
    Idempotent (ne fait rien si déjà démarré).
    """
    global _task, _stop_event

    if not _is_enabled():
        logger.info("Rétention désactivée par configuration")
        return False

    if _task and not _task.done():
        return True # Déjà en cours

    _stop_event = asyncio.Event()
    _task = asyncio.create_task(_retention_loop())
    logger.info("Scheduler de rétention démarré")
    return True


async def stop_scheduler() -> None:
    """
    Arrête proprement la tâche de rétention.
    Attend la fin du cycle en cours ou force l'annulation après timeout.
    """
    global _task, _stop_event

    if _stop_event:
        _stop_event.set() # Signale l'arrêt

    if _task and not _task.done():
        try:
            # Laisse 5s au cycle pour finir proprement
            await asyncio.wait_for(_task, timeout=5)
        except asyncio.TimeoutError:
            _task.cancel() # Force l'arrêt si trop long
            logger.warning("Scheduler de rétention arrêté de force (Timeout)")

    _task = None
    _stop_event = None


def get_status() -> Dict[str, Any]:
    """Retourne l'état actuel du service de rétention."""
    return {
        "enabled": _is_enabled(),
        "running": bool(_task and not _task.done()),
        "flows_days": settings.retention_flows_days,
        "interval_minutes": settings.retention_run_interval_minutes,
        "batch_size": settings.retention_delete_batch_size,
        "keep_alerted_flows": settings.retention_keep_alerted_flows,
    }
