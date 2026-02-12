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


class HybridDecisionEngine:
    """
    Combine les sorties des deux modèles et la réputation IP
    pour une décision finale de sécurité.
    """

    def __init__(
        self,
        weight_supervised: float = None,
        weight_unsupervised: float = None,
        weight_reputation: float = None,
    ):
        self.w_sup = weight_supervised or inference_config.weight_supervised
        self.w_unsup = weight_unsupervised or inference_config.weight_unsupervised
        self.w_rep = weight_reputation or inference_config.weight_reputation

        # Normaliser pour que les poids somment à 1
        total = self.w_sup + self.w_unsup + self.w_rep
        self.w_sup /= total
        self.w_unsup /= total
        self.w_rep /= total

    def decide(
        self,
        supervised_result: Dict[str, Any],
        unsupervised_result: Dict[str, Any],
        ip_reputation: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Produit la décision finale en fusionnant les 3 sources.

        Args:
            supervised_result: Sortie de SupervisedPredictor.predict().
            unsupervised_result: Sortie de UnsupervisedPredictor.predict().
            ip_reputation: Score de réputation IP [0, 1] (0 = propre, 1 = malveillant).

        Returns:
            Résultat structuré avec attack_type, probability, anomaly_score,
            final_risk_score, severity, decision, priority.
        """
        # Scores individuels
        sup_score = supervised_result.get("probability", 0.0)
        is_attack = supervised_result.get("is_attack", False)
        attack_type = supervised_result.get("attack_type", "Unknown")
        anomaly_score = unsupervised_result.get("anomaly_score", 0.0)
        is_anomaly = unsupervised_result.get("is_anomaly", False)

        # Score de risque pour le supervisé
        # Si BENIGN, le risque supervisé est faible
        if is_attack:
            supervised_risk = sup_score
        else:
            supervised_risk = 1.0 - sup_score  # Inversion : haute confiance BENIGN = faible risque

        # Score de risque combiné (moyenne pondérée)
        final_risk_score = (
            self.w_sup * supervised_risk
            + self.w_unsup * anomaly_score
            + self.w_rep * ip_reputation
        )
        final_risk_score = round(min(1.0, max(0.0, final_risk_score)), 6)

        # Matrice de décision
        decision = self._determine_decision(
            is_attack=is_attack,
            is_anomaly=is_anomaly,
            final_risk_score=final_risk_score,
            sup_confidence=sup_score,
        )

        # Severity
        severity = severity_config.get_severity(final_risk_score)

        # Priorité SOC (1 = urgent, 5 = faible)
        priority = self._compute_priority(severity, decision)

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
                "ip_reputation": round(ip_reputation, 4),
                "is_attack": is_attack,
                "is_anomaly": is_anomaly,
                "weights": {
                    "supervised": round(self.w_sup, 3),
                    "unsupervised": round(self.w_unsup, 3),
                    "reputation": round(self.w_rep, 3),
                },
            },
        }

    def _determine_decision(
        self,
        is_attack: bool,
        is_anomaly: bool,
        final_risk_score: float,
        sup_confidence: float,
    ) -> str:
        """
        Matrice de décision :

        | Supervisé  | Non-supervisé | Décision            |
        |------------|---------------|---------------------|
        | Attaque ✓  | Anomalie ✓    | confirmed_attack    |
        | Attaque ✓  | Normal        | suspicious          |
        | BENIGN     | Anomalie ✓    | unknown_anomaly     |
        | BENIGN     | Normal        | normal              |

        + Override par risk score élevé.
        """
        if is_attack and is_anomaly:
            return "confirmed_attack"
        elif is_attack and not is_anomaly:
            if sup_confidence >= 0.8:
                return "confirmed_attack"
            return "suspicious"
        elif not is_attack and is_anomaly:
            return "unknown_anomaly"
        else:
            # Les deux disent normal
            if final_risk_score >= inference_config.threshold_attack:
                return "suspicious"  # Réputation IP pousse le score
            return "normal"

    def _compute_priority(self, severity: str, decision: str) -> int:
        """Calcule la priorité SOC (1-5)."""
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
