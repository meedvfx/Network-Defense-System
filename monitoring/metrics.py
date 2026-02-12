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
    """Collecte les métriques système et applicatives."""

    def __init__(self):
        self._start_time = time.time()
        self.counters: Dict[str, int] = {
            "packets_processed": 0,
            "flows_analyzed": 0,
            "alerts_generated": 0,
            "predictions_made": 0,
            "anomalies_detected": 0,
        }
        self.gauges: Dict[str, float] = {
            "current_threat_score": 0.0,
            "active_flows": 0,
            "buffer_usage": 0.0,
        }

    def increment(self, counter: str, value: int = 1):
        """Incrémente un compteur."""
        if counter in self.counters:
            self.counters[counter] += value

    def set_gauge(self, gauge: str, value: float):
        """Met à jour un gauge."""
        self.gauges[gauge] = value

    def get_system_health(self) -> Dict[str, Any]:
        """Collecte les métriques système (CPU, mémoire, disque)."""
        return {
            "cpu_percent": psutil.cpu_percent(interval=0.1),
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
        """Retourne toutes les métriques."""
        return {
            "counters": self.counters.copy(),
            "gauges": self.gauges.copy(),
            "system": self.get_system_health(),
        }


# Instance globale
metrics = SystemMetrics()
