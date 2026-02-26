from datetime import datetime, timedelta
from typing import Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession

from reporting.metrics_engine import get_period_metrics

async def analyze_trends(session: AsyncSession, current_start: datetime, current_end: datetime) -> Dict[str, Any]:
    """
    Compare les métriques de la période actuelle avec celles de la période précédente.
    """
    duration = current_end - current_start
    prev_end = current_start
    prev_start = current_start - duration
    
    current_metrics = await get_period_metrics(session, current_start, current_end)
    prev_metrics = await get_period_metrics(session, prev_start, prev_end)
    
    def calculate_variation(current: float, previous: float) -> str:
        if previous == 0:
            return "+100%" if current > 0 else "0%"
        variation = ((current - previous) / previous) * 100
        sign = "+" if variation > 0 else ""
        return f"{sign}{variation:.1f}%"
        
    trends = {
        "attacks_variation": calculate_variation(current_metrics["total_attacks"], prev_metrics["total_attacks"]),
        "severity_variation": calculate_variation(current_metrics["avg_severity_score"], prev_metrics["avg_severity_score"]),
        "previous_total_attacks": prev_metrics["total_attacks"],
        "previous_avg_severity": prev_metrics["avg_severity_score"],
        "current_metrics": current_metrics
    }
    
    return trends
