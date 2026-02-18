"""
Routes API pour la gestion des alertes.
"""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from backend.database.connection import get_db
from backend.database import repository

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


# ---- Schémas de données ----

class AlertResponse(BaseModel):
    """Schéma de réponse pour une alerte."""
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
    """Schéma de mise à jour du statut."""
    status: str  # open, acknowledged, resolved, false_positive


# ---- Endpoints ----

@router.get("/", response_model=List[AlertResponse])
async def get_alerts(
    severity: Optional[str] = Query(None, description="Filtrer par sévérité (low, medium, high, critical)"),
    status: Optional[str] = Query(None, description="Filtrer par statut (open, acknowledged, resolved)"),
    limit: int = Query(50, ge=1, le=200, description="Nombre d'éléments par page"),
    offset: int = Query(0, ge=0, description="Décalage pour la pagination"),
    db: AsyncSession = Depends(get_db),
):
    """
    Récupère la liste des alertes avec options de filtrage et pagination.
    Utilisé par la page 'Alertes' du dashboard.
    """
    alerts = await repository.get_alerts(
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
    """
    Met à jour le cycle de vie d'une alerte (ex: marquer comme résolue).
    """
    valid_statuses = ["open", "acknowledged", "resolved", "false_positive"]
    if request.status not in valid_statuses:
        return {"error": f"Status invalide. Valides : {valid_statuses}"}

    await repository.update_alert_status(db, alert_id, request.status)
    return {"status": "updated", "alert_id": alert_id, "new_status": request.status}


@router.get("/stats")
async def get_alert_stats(
    hours: int = Query(24, ge=1, le=720, description="Période en heures"),
    db: AsyncSession = Depends(get_db),
):
    """
    Fournit les statistiques agrégées (total, par sévérité) pour les widgets en haut du dashboard.
    """
    stats = await repository.get_alert_stats(db, hours=hours)
    return stats


@router.get("/top-ips")
async def get_top_ips(
    limit: int = Query(10, ge=1, le=50, description="Nombre max d'IPs à retourner"),
    hours: int = Query(24, ge=1, le=720, description="Période en heures"),
    db: AsyncSession = Depends(get_db),
):
    """
    Liste les IPs sources les plus problématiques (celles générant le plus d'alertes).
    Utilisé pour le tableau 'Top Attackers'.
    """
    ips = await repository.get_top_alert_ips(db, limit=limit, hours=hours)
    return ips
