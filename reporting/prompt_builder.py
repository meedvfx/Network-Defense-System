import json
from datetime import datetime
from typing import Dict, Any

def build_prompt_from_stats(
    start_time: datetime,
    end_time: datetime,
    metrics: Dict[str, Any],
    trends: Dict[str, Any],
    threat_index: int,
    detail_level: str = "Technical"
) -> str:
    """
    Prépare le texte à envoyer au LLM en injectant les statistiques sous forme de JSON structuré
    ou de texte clair, avec les instructions spécifiques.
    """
    
    period_str = f"du {start_time.strftime('%Y-%m-%d %H:%M')} au {end_time.strftime('%Y-%m-%d %H:%M')}"
    
    # Json safe context
    context_data = {
        "period": period_str,
        "threat_index": f"{threat_index}/100",
        "total_attacks": metrics["total_attacks"],
        "attack_variation_vs_previous_period": trends["attacks_variation"],
        "avg_severity": round(metrics["avg_severity_score"], 2),
        "severity_variation": trends["severity_variation"],
        "attack_types_distribution": metrics["attack_types"],
        "top_ips": [ip["ip"] for ip in metrics["top_ips"]],
        "top_countries": [c["country"] for c in metrics["top_countries"]]
    }
    
    context_json = json.dumps(context_data, indent=2)
    
    prompt = f"""Tu es un analyste expert en cybersécurité SOC (Security Operations Center).
Ton rôle est de rédiger une partie d'un rapport de sécurité basé UNIQUEMENT sur les statistiques agrégées fournies ci-dessous.
Tu ne dois pas inventer de données. Tu dois être clinique, professionnel et précis.

DONNÉES STATISTIQUES ({period_str}) :
```json
{context_json}
```

INSTRUCTIONS DE GÉNÉRATION :
Le niveau de détail demandé est : {detail_level} (Executive = résumé managérial, Technical = détails approfondis).

Produis un document répondant exactement en format JSON avec ces 4 clés (et UNIQUEMENT ce JSON valide):
1. "executive_summary": Résumé global de la situation en 2-3 phrases. Mentionne le Threat Index.
2. "technical_analysis": Interprétation comportementale de ce que signifient les chiffres (ex: pourquoi tel type d'attaque prédomine, commentaire sur l'évolution).
3. "attacker_behavior": Analyse des pays d'origine et des pics, que cherchent les attaquants ?
4. "recommendations": 3 à 5 recommandations prioritaires sous forme de tirets.

Retourne uniquement du format JSON valide, sans balises markdown ```json autour.
"""
    return prompt
