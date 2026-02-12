"""
Service d'alertes : création, mise à jour, statistiques.
"""

import logging
from typing import Dict, Any
from datetime import datetime

from backend.database.redis_client import publish_alert, set_threat_score

logger = logging.getLogger(__name__)

_alert_count = 0


async def create_alert(
    flow_id: str,
    decision: Dict[str, Any],
    flow_metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """Crée une alerte à partir d'une décision du moteur hybride."""
    global _alert_count

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

    _alert_count += 1

    try:
        await publish_alert(
            {
                **alert_data,
                "timestamp": alert_data["timestamp"].isoformat(),
            }
        )
    except Exception as e:
        logger.warning(f"Impossible de publier l'alerte Redis : {e}")

    logger.info(
        f"Alerte créée : {decision['decision']} | "
        f"{decision['severity']} | {decision.get('attack_type', 'N/A')}"
    )

    return alert_data


async def update_threat_score(score: float) -> None:
    """Met à jour le score de menace global."""
    try:
        await set_threat_score(score)
    except Exception as e:
        logger.warning(f"Impossible de mettre à jour le threat score : {e}")


def total_alerts() -> int:
    return _alert_count
