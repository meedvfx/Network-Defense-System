"""
WebSocket handler pour broadcast temps réel des alertes.
"""

import json
import asyncio
import logging
from typing import Set

from fastapi import WebSocket, WebSocketDisconnect

from backend.database.redis_client import get_alert_subscriber

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Gère les connexions WebSocket des clients dashboard."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WebSocket connecté. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info(f"WebSocket déconnecté. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Envoie un message à tous les clients connectés."""
        disconnected = set()
        for ws in self.active_connections:
            try:
                await ws.send_json(message)
            except Exception:
                disconnected.add(ws)

        # Nettoyer les connexions mortes
        for ws in disconnected:
            self.active_connections.discard(ws)


manager = ConnectionManager()


async def websocket_endpoint(websocket: WebSocket):
    """Endpoint WebSocket pour le streaming d'alertes."""
    await manager.connect(websocket)

    try:
        # Listener Redis pub/sub
        subscriber = await get_alert_subscriber()

        # Tâche de réception Redis
        async def redis_listener():
            try:
                async for message in subscriber.listen():
                    if message["type"] == "message":
                        data = json.loads(message["data"])
                        await manager.broadcast(data)
            except Exception as e:
                logger.error(f"Erreur Redis listener: {e}")

        # Lancer le listener en arrière-plan
        listener_task = asyncio.create_task(redis_listener())

        # Garder la connexion ouverte et écouter les messages du client
        while True:
            try:
                data = await websocket.receive_text()
                # Les clients peuvent envoyer des commandes (ping, etc.)
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
            except WebSocketDisconnect:
                break

    except Exception as e:
        logger.error(f"Erreur WebSocket: {e}")
    finally:
        manager.disconnect(websocket)
        if 'listener_task' in locals():
            listener_task.cancel()
        if 'subscriber' in locals():
            try:
                await subscriber.unsubscribe()
                await subscriber.aclose()
            except Exception:
                pass
