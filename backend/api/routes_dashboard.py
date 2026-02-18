"""
Routes API pour le dashboard (statistiques et métriques).
"""

import asyncio

from fastapi import APIRouter, Query
from sqlalchemy import select, func
from typing import Dict, Any
from datetime import datetime, timedelta

from backend.database.connection import async_session_factory
from backend.database import repository
from backend.database.redis_client import get_threat_score, get_metric
from backend.database.models import NetworkFlow, Alert

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/overview")
async def get_dashboard_overview(
    hours: int = Query(24, ge=1, le=720, description="Période glissante en heures"),
) -> Dict[str, Any]:
    """
    Agrège les KPI principaux pour la vue 'Overview' du dashboard.
    Données temps réel + statistiques historiques.
    """
    async with async_session_factory() as db:
        try:
            # Exécution parallèle des requêtes DB pour réduire la latence
            alert_stats = await asyncio.wait_for(repository.get_alert_stats(db, hours=hours), timeout=1.5)
            anomaly_rate = await asyncio.wait_for(repository.get_anomaly_rate(db, hours=hours), timeout=1.5)
            total_flows = await asyncio.wait_for(repository.count_flows(db), timeout=1.5)
        except Exception:
            # Fallback en cas de timeout ou erreur DB pour ne pas casser le dashboard
            alert_stats = {"total": 0, "by_severity": {}}
            anomaly_rate = 0.0
            total_flows = 0

    try:
        # Score de menace temps réel depuis Redis (calculé par AlertService)
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
):
    """
    Répartition des types d'attaques (ex: DOS, PortScan...) pour le camembert.
    """
    async with async_session_factory() as db:
        try:
            distribution = await asyncio.wait_for(repository.get_attack_distribution(db, hours=hours), timeout=1.5)
        except Exception:
            distribution = []
    return {"distribution": distribution, "period_hours": hours}


@router.get("/top-threats")
async def get_top_threats(
    limit: int = Query(10, ge=1, le=50),
    hours: int = Query(24, ge=1, le=720),
):
    """
    Liste des IPs les plus actives dans les attaques récentes.
    """
    async with async_session_factory() as db:
        try:
            top_ips = await asyncio.wait_for(repository.get_top_alert_ips(db, limit=limit, hours=hours), timeout=1.5)
        except Exception:
            top_ips = []
    return {"threats": top_ips, "period_hours": hours}


@router.get("/recent-alerts")
async def get_recent_alerts(
    limit: int = Query(20, ge=1, le=100),
):
    """
    Flux des dernières alertes pour le widget 'Live Alerts'.
    """
    async with async_session_factory() as db:
        try:
            alerts = await asyncio.wait_for(repository.get_alerts(db, limit=limit), timeout=1.5)
        except Exception:
            alerts = []
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
    """
    Métriques techniques brutes depuis Redis (compteurs atomiques).
    - packets_processed: performance capture
    - flows_analyzed: performance IA
    - alerts_generated: activité détection
    """
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


@router.get("/traffic-timeseries")
async def get_traffic_timeseries(
    hours: int = Query(24, ge=1, le=720),
):
    """
    Construit les séries temporelles pour le graphique principal.
    Superpose le trafic total, suspect et les attaques confirmées par heure.
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    bucket = func.date_trunc("hour", NetworkFlow.timestamp)

    # Requête 1: Trafic total par heure
    total_q = (
        select(bucket.label("bucket"), func.count(NetworkFlow.id).label("total"))
        .where(NetworkFlow.timestamp >= since)
        .group_by(bucket)
    )

    # Requête 2: Activité suspecte (Alerts low/medium)
    suspicious_q = (
        select(bucket.label("bucket"), func.count(Alert.id).label("count"))
        .join(Alert, Alert.flow_id == NetworkFlow.id)
        .where(NetworkFlow.timestamp >= since)
        .where(Alert.decision.in_(["suspicious", "unknown_anomaly"]))
        .group_by(bucket)
    )

    # Requête 3: Attaques confirmées (Alerts high/critical)
    attacks_q = (
        select(bucket.label("bucket"), func.count(Alert.id).label("count"))
        .join(Alert, Alert.flow_id == NetworkFlow.id)
        .where(NetworkFlow.timestamp >= since)
        .where(Alert.decision == "confirmed_attack")
        .group_by(bucket)
    )

    async with async_session_factory() as db:
        try:
            total_rows = await asyncio.wait_for(db.execute(total_q), timeout=1.5)
            suspicious_rows = await asyncio.wait_for(db.execute(suspicious_q), timeout=1.5)
            attack_rows = await asyncio.wait_for(db.execute(attacks_q), timeout=1.5)
        except Exception:
            return {"series": [], "period_hours": hours}

    # Agrégation et formatage des données
    totals = {row.bucket: int(row.total) for row in total_rows}
    suspicious = {row.bucket: int(row.count) for row in suspicious_rows}
    attacks = {row.bucket: int(row.count) for row in attack_rows}

    buckets = sorted(totals.keys())
    series = []
    for b in buckets:
        s = suspicious.get(b, 0)
        a = attacks.get(b, 0)
        normal = max(totals.get(b, 0) - s - a, 0)
        series.append(
            {
                "time": b.strftime("%H:00"),
                "normal": normal,
                "suspicious": s,
                "attacks": a,
            }
        )

    return {"series": series, "period_hours": hours}


@router.get("/protocol-distribution")
async def get_protocol_distribution(
    hours: int = Query(24, ge=1, le=720),
):
    """
    Répartition du trafic par protocole (TCP, UDP, ICMP...).
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    async with async_session_factory() as db:
        try:
            rows = await asyncio.wait_for(
                db.execute(
                    select(NetworkFlow.protocol, func.count(NetworkFlow.id).label("count"))
                    .where(NetworkFlow.timestamp >= since)
                    .group_by(NetworkFlow.protocol)
                    .order_by(func.count(NetworkFlow.id).desc())
                ),
                timeout=1.5,
            )
        except Exception:
            return {"distribution": [], "period_hours": hours}

    protocol_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
    distribution = [
        {
            "name": protocol_names.get(int(row.protocol), f"PROTO-{int(row.protocol)}"),
            "count": int(row.count),
        }
        for row in rows
    ]

    return {"distribution": distribution, "period_hours": hours}
