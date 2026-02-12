"""
Routes API pour la gestion des alertes.
"""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from backend.database.connection import get_db
from backend.database.repository import AlertRepository

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


class AlertResponse(BaseModel):
    id: str
    timestamp: str
    severity: str
    attack_type: Optional[str]
    threat_score: float
    decision: str
    status: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None


class AlertUpdateRequest(BaseModel):
    status: str  # open, acknowledged, resolved, false_positive


@router.get("/", response_model=List[AlertResponse])
async def get_alerts(
    severity: Optional[str] = Query(None, description="Filtrer par severity"),
    status: Optional[str] = Query(None, description="Filtrer par status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """Liste les alertes avec filtres et pagination."""
    alerts = await AlertRepository.get_alerts(
        db=db, severity=severity, status=status, limit=limit, offset=offset
    )
    return [
        AlertResponse(
            id=str(a.id),
            timestamp=a.timestamp.isoformat(),
            severity=a.severity,
            attack_type=a.attack_type,
            threat_score=a.threat_score,
            decision=a.decision,
            status=a.status,
            src_ip=a.alert_metadata.get("src_ip") if a.alert_metadata else None,
            dst_ip=a.alert_metadata.get("dst_ip") if a.alert_metadata else None,
        )
        for a in alerts
    ]


@router.patch("/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    request: AlertUpdateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Met à jour le statut d'une alerte."""
    valid_statuses = ["open", "acknowledged", "resolved", "false_positive"]
    if request.status not in valid_statuses:
        return {"error": f"Status invalide. Valides : {valid_statuses}"}

    await AlertRepository.update_status(db, alert_id, request.status)
    return {"status": "updated", "alert_id": alert_id, "new_status": request.status}


@router.get("/stats")
async def get_alert_stats(
    hours: int = Query(24, ge=1, le=720),
    db: AsyncSession = Depends(get_db),
):
    """Statistiques des alertes sur une période."""
    stats = await AlertRepository.get_stats(db, hours=hours)
    return stats


@router.get("/top-ips")
async def get_top_ips(
    limit: int = Query(10, ge=1, le=50),
    hours: int = Query(24, ge=1, le=720),
    db: AsyncSession = Depends(get_db),
):
    """Top IPs malveillantes par nombre d'alertes."""
    ips = await AlertRepository.get_top_ips(db, limit=limit, hours=hours)
    return ips
