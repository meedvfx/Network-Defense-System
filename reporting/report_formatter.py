from datetime import datetime
from typing import Dict, Any

def generate_markdown_report(
    start_time: datetime,
    end_time: datetime,
    metrics: Dict[str, Any],
    trends: Dict[str, Any],
    threat_index: int,
    llm_analysis: Dict[str, Any]
) -> str:
    """
    Génère le document final du rapport au format Markdown.
    """
    period_str = f"{start_time.strftime('%Y-%m-%d %H:%M')} au {end_time.strftime('%Y-%m-%d %H:%M')}"
    
    # Header
    md =  f"# Rapport de Sécurité SOC\n"
    md += f"**Période d'analyse :** {period_str}\n\n"
    md += f"---\n\n"
    
    # 1. Executive Summary & Threat Index
    md += f"## 1. Executive Summary\n"
    md += f"> **Threat Index : {threat_index}/100**\n\n"
    md += f"{llm_analysis.get('executive_summary', 'Non disponible.')}\n\n"
    
    # 2. Métriques & Tendances
    md += f"## 2. Métriques Clés\n"
    md += f"- **Total des flux analysés** : {metrics.get('total_flows', 0):,}\n"
    md += f"- **Total des attaques détectées** : {metrics.get('total_attacks', 0):,} ({trends.get('attacks_variation', '0%')} vs période précédente)\n"
    md += f"- **Ratio d'attaques** : {metrics.get('attack_ratio_percent', 0.0)}%\n"
    md += f"- **Sévérité moyenne** : {metrics.get('avg_severity_score', 0.0):.2f}/1.0 ({trends.get('severity_variation', '0%')} vs période précédente)\n\n"
    
    # 3. Analyse technique (LLM)
    md += f"## 3. Analyse Technique\n"
    md += f"{llm_analysis.get('technical_analysis', 'Non disponible.')}\n\n"
    
    # 4. Comportement des Attaquants (LLM)
    md += f"## 4. Comportement des Attaquants\n"
    md += f"### Top 5 IP Sources\n"
    top_ips = metrics.get("top_ips", [])
    if top_ips:
        for idx, ip_data in enumerate(top_ips[:5], 1):
            md += f"{idx}. **{ip_data['ip']}** ({ip_data['count']:,} requêtes)\n"
    else:
        md += f"*- Aucune donnée IP source enregistrée.*\n"
    md += "\n"
    
    md += f"### Top 5 Pays d'Origine\n"
    top_countries = metrics.get("top_countries", [])
    if top_countries:
        for idx, country_data in enumerate(top_countries[:5], 1):
            md += f"{idx}. **{country_data['country']}** ({country_data['count']:,} attaques)\n"
    else:
        md += f"*- Aucune donnée géographique enregistrée.*\n"
    md += "\n"
    
    md += f"{llm_analysis.get('attacker_behavior', 'Non disponible.')}\n\n"
    
    # 5. Recommandations (LLM)
    md += f"## 5. Recommandations Stratégiques\n"
    recs = llm_analysis.get("recommendations", [])
    if isinstance(recs, list):
        for rec in recs:
            md += f"- {rec}\n"
    else:
        # Fallback if LLM output string
        md += f"{recs}\n"
        
    md += f"\n---\n*Généré automatiquement par le module d'IA NDS.*"
    
    return md
