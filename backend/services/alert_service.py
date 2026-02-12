"""
Service d'alertes : création, mise à jour, statistiques.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from backend.database.redis_client import publish_alert, set_threat_score

logger = logging.getLogger(__name__)


class AlertService:
    """Service de gestion des alertes SOC."""

    def __init__(self):
        self._alert_count = 0

    async def create_alert(
        self,
        flow_id: str,
        decision: Dict[str, Any],
        flow_metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Crée une alerte à partir d'une décision du moteur hybride.

        Args:
            flow_id: ID du flux réseau.
            decision: Résultat du HybridDecisionEngine.
            flow_metadata: Métadonnées du flux.

        Returns:
            Données de l'alerte créée.
        """
        alert_data = {
            "flow_id": flow_id,
            "timestamp": datetime.utcnow(),
            "severity": decision["severity"],
            "attack_type": decision.get("attack_type"),
            "threat_score": decision["threat_score"],
            "decision": decision["decision"],
            "status": "open",
            "alert_metadata": {
                "src_ip": flow_metadata.get("src_ip"),
                "dst_ip": flow_metadata.get("dst_ip"),
                "priority": decision.get("priority", 5),
                "reasoning": decision.get("reasoning", ""),
                "supervised_confidence": decision.get("supervised_confidence", 0),
                "anomaly_score": decision.get("anomaly_score", 0),
            },
        }

        self._alert_count += 1

        # Publier l'alerte en temps réel via Redis
        try:
            await publish_alert({
                **alert_data,
                "timestamp": alert_data["timestamp"].isoformat(),
            })
        except Exception as e:
            logger.warning(f"Impossible de publier l'alerte Redis : {e}")

        logger.info(
            f"Alerte créée : {decision['decision']} | "
            f"{decision['severity']} | {decision.get('attack_type', 'N/A')}"
        )

        return alert_data

    async def update_threat_score(self, score: float):
        """Met à jour le score de menace global."""
        try:
            await set_threat_score(score)
        except Exception as e:
            logger.warning(f"Impossible de mettre à jour le threat score : {e}")

    @property
    def total_alerts(self) -> int:
        return self._alert_count
