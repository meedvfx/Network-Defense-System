"""
Routes API pour le dashboard (statistiques et métriques).
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any

from backend.database.connection import get_db
from backend.database.repository import (
    AlertRepository, PredictionRepository,
    AnomalyRepository, FlowRepository,
)
from backend.database.redis_client import get_threat_score, get_metric

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/overview")
async def get_dashboard_overview(
    hours: int = Query(24, ge=1, le=720),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Retourne les données principales du dashboard."""
    alert_stats = await AlertRepository.get_stats(db, hours=hours)
    anomaly_rate = await AnomalyRepository.get_anomaly_rate(db, hours=hours)
    total_flows = await FlowRepository.count(db)

    try:
        threat_score = await get_threat_score()
    except Exception:
        threat_score = 0.0

    return {
        "threat_score": threat_score,
        "total_alerts": alert_stats.get("total", 0),
        "alerts_by_severity": alert_stats.get("by_severity", {}),
        "anomaly_rate": round(anomaly_rate, 4),
        "total_flows_analyzed": total_flows,
        "period_hours": hours,
    }


@router.get("/attack-distribution")
async def get_attack_distribution(
    hours: int = Query(24, ge=1, le=720),
    db: AsyncSession = Depends(get_db),
):
    """Distribution des types d'attaques détectées."""
    distribution = await PredictionRepository.get_attack_distribution(db, hours=hours)
    return {"distribution": distribution, "period_hours": hours}


@router.get("/top-threats")
async def get_top_threats(
    limit: int = Query(10, ge=1, le=50),
    hours: int = Query(24, ge=1, le=720),
    db: AsyncSession = Depends(get_db),
):
    """Top IPs menaçantes avec détails."""
    top_ips = await AlertRepository.get_top_ips(db, limit=limit, hours=hours)
    return {"threats": top_ips, "period_hours": hours}


@router.get("/recent-alerts")
async def get_recent_alerts(
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """Alertes les plus récentes pour le feed temps réel."""
    alerts = await AlertRepository.get_alerts(db, limit=limit)
    return [
        {
            "id": str(a.id),
            "timestamp": a.timestamp.isoformat(),
            "severity": a.severity,
            "attack_type": a.attack_type,
            "threat_score": a.threat_score,
            "decision": a.decision,
            "status": a.status,
            "src_ip": a.alert_metadata.get("src_ip") if a.alert_metadata else None,
        }
        for a in alerts
    ]


@router.get("/metrics")
async def get_system_metrics():
    """Métriques système temps réel."""
    try:
        packets_processed = await get_metric("packets_processed")
        flows_analyzed = await get_metric("flows_analyzed")
        alerts_generated = await get_metric("alerts_generated")
    except Exception:
        packets_processed = flows_analyzed = alerts_generated = 0

    return {
        "packets_processed": packets_processed,
        "flows_analyzed": flows_analyzed,
        "alerts_generated": alerts_generated,
    }
