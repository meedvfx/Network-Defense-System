from typing import Dict, Any

def calculate_threat_index(metrics: Dict[str, Any], trends: Dict[str, Any]) -> int:
    """
    Calcule le Threat Index (0-100) basé sur les métriques et tendances.
    """
    score = 0.0
    
    # 1. Volume d'attaques (max 30 points)
    total_attacks = metrics.get("total_attacks", 0)
    if total_attacks > 10000:
        score += 30
    elif total_attacks > 1000:
        score += 20
    elif total_attacks > 100:
        score += 10
    elif total_attacks > 0:
        score += 5
        
    # 2. Sévérité moyenne (max 25 points)
    # severity est entre 0.0 et 1.0
    severity = metrics.get("avg_severity_score", 0.0)
    score += (severity * 25)
    
    # 3. Diversité des types (max 15 points)
    types_count = len(metrics.get("attack_types", {}))
    if types_count >= 5:
        score += 15
    elif types_count >= 3:
        score += 10
    elif types_count >= 1:
        score += 5
        
    # 4. Augmentation vs baseline (max 30 points)
    # Ex: "+50.0%"
    variation_str = trends.get("attacks_variation", "0%")
    try:
        variation_val = float(variation_str.replace('%', '').replace('+', ''))
        if variation_val > 100:
            score += 30
        elif variation_val > 50:
            score += 20
        elif variation_val > 20:
            score += 10
        elif variation_val > 0:
            score += 5
    except ValueError:
        pass
        
    return int(min(100, max(0, score)))
