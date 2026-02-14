"""
Moteur de décision hybride.
Fusionne les résultats supervisé + non-supervisé + réputation IP
pour produire une décision finale structurée.

Sortie :
    - attack_type : type d'attaque prédit
    - probability : confiance de la classification
    - anomaly_score : score d'anomalie normalisé
    - final_risk_score : score de risque combiné [0, 1]
    - severity : critical / high / medium / low
    - decision : confirmed_attack / suspicious / unknown_anomaly / normal
"""

import logging
from typing import Dict, Any

from ai.config.model_config import inference_config, severity_config

logger = logging.getLogger(__name__)


def create_engine(
    weight_supervised: float = None,
    weight_unsupervised: float = None,
    weight_reputation: float = None,
) -> Dict[str, float]:
    w_sup = inference_config.weight_supervised if weight_supervised is None else weight_supervised
    w_unsup = inference_config.weight_unsupervised if weight_unsupervised is None else weight_unsupervised
    w_rep = inference_config.weight_reputation if weight_reputation is None else weight_reputation

    total = w_sup + w_unsup + w_rep
    if total <= 0:
        logger.warning("Poids hybrides invalides (somme <= 0), fallback config par défaut")
        w_sup = inference_config.weight_supervised
        w_unsup = inference_config.weight_unsupervised
        w_rep = inference_config.weight_reputation
        total = w_sup + w_unsup + w_rep

    return {
        "w_sup": w_sup / total,
        "w_unsup": w_unsup / total,
        "w_rep": w_rep / total,
    }


def _determine_decision(
    is_attack: bool,
    is_anomaly: bool,
    final_risk_score: float,
    sup_confidence: float,
) -> str:
    if is_attack and is_anomaly:
        return "confirmed_attack"
    if is_attack and not is_anomaly:
        if sup_confidence >= 0.8:
            return "confirmed_attack"
        return "suspicious"
    if not is_attack and is_anomaly:
        return "unknown_anomaly"
    if final_risk_score >= inference_config.threshold_attack:
        return "suspicious"
    return "normal"


def _compute_priority(severity: str, decision: str) -> int:
    priority_map = {
        ("critical", "confirmed_attack"): 1,
        ("critical", "unknown_anomaly"): 1,
        ("critical", "suspicious"): 2,
        ("high", "confirmed_attack"): 2,
        ("high", "unknown_anomaly"): 2,
        ("high", "suspicious"): 3,
        ("medium", "confirmed_attack"): 3,
        ("medium", "unknown_anomaly"): 3,
        ("medium", "suspicious"): 4,
    }
    return priority_map.get((severity, decision), 5)


def decide(
    engine: Dict[str, float],
    supervised_result: Dict[str, Any],
    unsupervised_result: Dict[str, Any],
    ip_reputation: float = 0.0,
) -> Dict[str, Any]:
    sup_score = supervised_result.get("probability", 0.0)
    is_attack = supervised_result.get("is_attack", False)
    attack_type = supervised_result.get("attack_type", "Unknown")
    anomaly_score = unsupervised_result.get("anomaly_score", 0.0)
    is_anomaly = unsupervised_result.get("is_anomaly", False)
    reputation_score = min(1.0, max(0.0, float(ip_reputation)))

    supervised_risk = sup_score if is_attack else 1.0 - sup_score

    final_risk_score = (
        engine["w_sup"] * supervised_risk
        + engine["w_unsup"] * anomaly_score
        + engine["w_rep"] * reputation_score
    )
    final_risk_score = round(min(1.0, max(0.0, final_risk_score)), 6)

    decision = _determine_decision(
        is_attack=is_attack,
        is_anomaly=is_anomaly,
        final_risk_score=final_risk_score,
        sup_confidence=sup_score,
    )

    severity = severity_config.get_severity(final_risk_score)
    priority = _compute_priority(severity, decision)

    return {
        "attack_type": attack_type if is_attack else None,
        "probability": round(sup_score, 6),
        "anomaly_score": round(anomaly_score, 6),
        "final_risk_score": final_risk_score,
        "severity": severity,
        "decision": decision,
        "priority": priority,
        "details": {
            "supervised_risk": round(supervised_risk, 6),
            "unsupervised_anomaly": round(anomaly_score, 6),
            "ip_reputation": round(reputation_score, 4),
            "is_attack": is_attack,
            "is_anomaly": is_anomaly,
            "weights": {
                "supervised": round(engine["w_sup"], 3),
                "unsupervised": round(engine["w_unsup"], 3),
                "reputation": round(engine["w_rep"], 3),
            },
        },
    }
