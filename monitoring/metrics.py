"""
Métriques système pour le monitoring du NDS.
Compteurs, gauges, et health checks.
"""

import time
import psutil
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class SystemMetrics:
    """
    Collecteur centralisé de métriques pour le monitoring interne.
    Agrège les compteurs applicatifs (paquets, alertes) et l'état système (CPU, RAM).
    Singleton utilisé par le dashboard pour l'affichage temps réel.
    """

    def __init__(self):
        self._start_time = time.time()
        # Compteurs monotones croissants
        self.counters: Dict[str, int] = {
            "packets_processed": 0,
            "flows_analyzed": 0,
            "alerts_generated": 0,
            "predictions_made": 0,
            "anomalies_detected": 0,
        }
        # Gauges (valeurs qui montent et descendent)
        self.gauges: Dict[str, float] = {
            "current_threat_score": 0.0,
            "active_flows": 0,
            "buffer_usage": 0.0,
        }

    def increment(self, counter: str, value: int = 1):
        """Incrémente un compteur nommé de manière thread-safe (en Python, GIL aide)."""
        if counter in self.counters:
            self.counters[counter] += value

    def set_gauge(self, gauge: str, value: float):
        """Met à jour la valeur instantanée d'une jauge."""
        self.gauges[gauge] = value

    def get_system_health(self) -> Dict[str, Any]:
        """
        Capture l'état des ressources du serveur hôte via psutil.
        Retourne CPU, RAM, Disque et Uptime.
        """
        return {
            "cpu_percent": psutil.cpu_percent(interval=None), # Non-bloquant
            "memory": {
                "total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
                "used_gb": round(psutil.virtual_memory().used / (1024**3), 2),
                "percent": psutil.virtual_memory().percent,
            },
            "disk": {
                "total_gb": round(psutil.disk_usage("/").total / (1024**3), 2),
                "used_percent": psutil.disk_usage("/").percent,
            },
            "uptime_seconds": round(time.time() - self._start_time, 0),
        }

    def get_all_metrics(self) -> Dict[str, Any]:
        """Retourne un snapshot complet de toutes les métriques."""
        return {
            "counters": self.counters.copy(),
            "gauges": self.gauges.copy(),
            "system": self.get_system_health(),
        }


# Instance globale
metrics = SystemMetrics()
