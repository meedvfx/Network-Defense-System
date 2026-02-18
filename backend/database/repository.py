"""
Couche d'accès aux données (Repository pattern).
Requêtes optimisées avec pagination et filtres.
"""

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from uuid import uuid4

from sqlalchemy import select, func, desc, update, delete, exists
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.models import (
    NetworkFlow, Prediction, AnomalyScore,
    Alert, IPGeolocation, ModelVersion, FeedbackLabel
)


# ---- Network Flows ----

async def create_flow(db: AsyncSession, flow_data: dict) -> NetworkFlow:
    """Crée un nouvel enregistrement de flux réseau."""
    flow = NetworkFlow(id=str(uuid4()), **flow_data)
    db.add(flow)
    await db.flush()
    return flow


async def create_flow_batch(db: AsyncSession, flows_data: List[dict]) -> List[NetworkFlow]:
    """
    Insère plusieurs flux en une seule transaction (Bulk Insert).
    Optimisé pour les forts volumes d'écriture en temps réel.
    """
    flows = [NetworkFlow(id=str(uuid4()), **data) for data in flows_data]
    db.add_all(flows)
    await db.flush()
    return flows


async def get_recent_flows(db: AsyncSession, limit: int = 100, offset: int = 0) -> List[NetworkFlow]:
    """Récupère les derniers flux capturés pour affichage dans le dashboard."""
    result = await db.execute(
        select(NetworkFlow)
        .order_by(desc(NetworkFlow.timestamp))
        .limit(limit)
        .offset(offset)
    )
    return list(result.scalars().all())


async def count_flows(db: AsyncSession) -> int:
    """Compte le nombre total de flux enregistrés (pour pagination)."""
    result = await db.execute(select(func.count(NetworkFlow.id)))
    return result.scalar()


# ---- Predictions (Supervised) ----

async def create_prediction(db: AsyncSession, prediction_data: dict) -> Prediction:
    """Enregistre le résultat d'une classification supervisée."""
    prediction = Prediction(id=str(uuid4()), **prediction_data)
    db.add(prediction)
    await db.flush()
    return prediction


async def get_prediction_by_flow(db: AsyncSession, flow_id: str) -> Optional[Prediction]:
    """Récupère la prédiction associée à un flux spécifique."""
    result = await db.execute(select(Prediction).where(Prediction.flow_id == flow_id))
    return result.scalar_one_or_none()


async def get_attack_distribution(db: AsyncSession, hours: int = 24) -> List[Dict[str, Any]]:
    """
    Calcule la distribution des types d'attaques sur une période donnée.
    Utilisé pour les graphiques "camembert" (Pie Chart) du dashboard.
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    result = await db.execute(
        select(Prediction.predicted_label, func.count(Prediction.id).label("count"))
        .where(Prediction.timestamp >= since)
        .group_by(Prediction.predicted_label)
        .order_by(desc("count"))
    )
    return [{"label": row[0], "count": row[1]} for row in result.all()]


# ---- Anomalies (Unsupervised) ----

async def create_anomaly(db: AsyncSession, anomaly_data: dict) -> AnomalyScore:
    """Enregistre un score d'anomalie calculé par l'autoencoder."""
    anomaly = AnomalyScore(id=str(uuid4()), **anomaly_data)
    db.add(anomaly)
    await db.flush()
    return anomaly


async def get_anomalies(db: AsyncSession, limit: int = 50) -> List[AnomalyScore]:
    """Récupère les dernières anomalies détectées (où is_anomaly=True)."""
    result = await db.execute(
        select(AnomalyScore)
        .where(AnomalyScore.is_anomaly == True)  # noqa: E712
        .order_by(desc(AnomalyScore.timestamp))
        .limit(limit)
    )
    return list(result.scalars().all())


async def get_anomaly_rate(db: AsyncSession, hours: int = 24) -> float:
    """
    Calcule le pourcentage de trafic anormal sur une fenêtre de temps.
    Ratio = (Flux anormaux / Total flux)
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    total = await db.execute(select(func.count(AnomalyScore.id)).where(AnomalyScore.timestamp >= since))
    anomalies = await db.execute(
        select(func.count(AnomalyScore.id))
        .where(AnomalyScore.timestamp >= since)
        .where(AnomalyScore.is_anomaly == True)  # noqa: E712
    )
    total_count = total.scalar()
    if total_count == 0:
        return 0.0
    return anomalies.scalar() / total_count


# ---- Alerts (Hybrid Engine) ----

async def create_alert(db: AsyncSession, alert_data: dict) -> Alert:
    """Crée une nouvelle alerte de sécurité."""
    alert = Alert(id=str(uuid4()), **alert_data)
    db.add(alert)
    await db.flush()
    return alert


async def get_alerts(
    db: AsyncSession,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> List[Alert]:
    """
    Récupère la liste des alertes avec filtrage optionnel par sévérité et statut.
    Supporte la pagination.
    """
    query = select(Alert)
    if severity:
        query = query.where(Alert.severity == severity)
    if status:
        query = query.where(Alert.status == status)
    query = query.order_by(desc(Alert.timestamp)).limit(limit).offset(offset)
    result = await db.execute(query)
    return list(result.scalars().all())


async def update_alert_status(db: AsyncSession, alert_id: str, new_status: str) -> None:
    """
    Change le statut d'une alerte (ex: open -> acknowledged -> resolved).
    Permet aux analystes de suivre le traitement des incidents.
    """
    await db.execute(update(Alert).where(Alert.id == alert_id).values(status=new_status))


async def get_alert_stats(db: AsyncSession, hours: int = 24) -> Dict[str, Any]:
    """
    Statistiques globales sur les alertes (Total + ventilation par sévérité).
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    total = await db.execute(select(func.count(Alert.id)).where(Alert.timestamp >= since))
    by_severity = await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.timestamp >= since)
        .group_by(Alert.severity)
    )
    return {
        "total": total.scalar(),
        "by_severity": {row[0]: row[1] for row in by_severity.all()},
    }


async def get_top_alert_ips(db: AsyncSession, limit: int = 10, hours: int = 24) -> List[Dict[str, Any]]:
    """
    Identifie les adresses IP sources générant le plus d'alertes.
    Utile pour identifier les attaquants les plus agressifs (Top Talkers).
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    result = await db.execute(
        select(
            NetworkFlow.src_ip,
            func.count(Alert.id).label("alert_count"),
            func.avg(Alert.threat_score).label("avg_threat"),
        )
        .join(NetworkFlow, Alert.flow_id == NetworkFlow.id)
        .where(Alert.timestamp >= since)
        .group_by(NetworkFlow.src_ip)
        .order_by(desc("alert_count"))
        .limit(limit)
    )
    return [
        {"ip": row[0], "alert_count": row[1], "avg_threat": round(float(row[2]), 3)}
        for row in result.all()
    ]


# ---- GeoIP Cache ----

async def upsert_geolocation(db: AsyncSession, geo_data: dict) -> IPGeolocation:
    """
    Insère ou met à jour les informations de géolocalisation pour une IP (Upsert).
    Si l'IP existe déjà, met à jour les données et le timestamp.
    """
    existing = await db.execute(select(IPGeolocation).where(IPGeolocation.ip_address == geo_data["ip_address"]))
    geo = existing.scalar_one_or_none()
    if geo:
        for key, value in geo_data.items():
            setattr(geo, key, value)
        geo.last_updated = datetime.utcnow()
    else:
        geo = IPGeolocation(id=str(uuid4()), **geo_data)
        db.add(geo)
    await db.flush()
    return geo


async def get_geolocation_by_ip(db: AsyncSession, ip_address: str) -> Optional[IPGeolocation]:
    """Cherche la géolocalisation d'une IP dans le cache local."""
    result = await db.execute(select(IPGeolocation).where(IPGeolocation.ip_address == ip_address))
    return result.scalar_one_or_none()


async def get_all_geolocations(db: AsyncSession) -> List[IPGeolocation]:
    """Récupère tout le cache GeoIP (pour l'affichage sur la carte)."""
    result = await db.execute(select(IPGeolocation))
    return list(result.scalars().all())


# ---- Model Versions (MLOps) ----

async def create_model_version(db: AsyncSession, model_data: dict) -> ModelVersion:
    """Enregistre une nouvelle version de modèle (après entraînement)."""
    model = ModelVersion(id=str(uuid4()), **model_data)
    db.add(model)
    await db.flush()
    return model


async def get_active_model_version(db: AsyncSession, model_type: str) -> Optional[ModelVersion]:
    """Récupère la version actuellement active pour un type de modèle donné."""
    result = await db.execute(
        select(ModelVersion)
        .where(ModelVersion.model_type == model_type)
        .where(ModelVersion.is_active == True)  # noqa: E712
    )
    return result.scalar_one_or_none()


async def set_active_model_version(db: AsyncSession, model_id: str, model_type: str) -> None:
    """
    Bascule la version active d'un modèle.
    Désactive l'ancienne version active et active la nouvelle.
    """
    await db.execute(update(ModelVersion).where(ModelVersion.model_type == model_type).values(is_active=False))
    await db.execute(update(ModelVersion).where(ModelVersion.id == model_id).values(is_active=True))


async def get_model_versions(db: AsyncSession, model_type: str) -> List[ModelVersion]:
    """Liste l'historique des versions pour un type de modèle."""
    result = await db.execute(
        select(ModelVersion)
        .where(ModelVersion.model_type == model_type)
        .order_by(desc(ModelVersion.trained_at))
    )
    return list(result.scalars().all())


# ---- Feedback Loop (Active Learning) ----

async def create_feedback(db: AsyncSession, feedback_data: dict) -> FeedbackLabel:
    """Enregistre un feedback analyste sur une alerte."""
    feedback = FeedbackLabel(id=str(uuid4()), **feedback_data)
    db.add(feedback)
    await db.flush()
    return feedback


async def get_unused_feedback(db: AsyncSession) -> List[FeedbackLabel]:
    """Récupère les feedbacks non encore utilisés pour l'entraînement."""
    result = await db.execute(
        select(FeedbackLabel)
        .where(FeedbackLabel.used_for_training == False)  # noqa: E712
        .order_by(FeedbackLabel.created_at)
    )
    return list(result.scalars().all())


async def count_unused_feedback(db: AsyncSession) -> int:
    """Compte le nombre de nouveaux feedbacks disponibles."""
    result = await db.execute(
        select(func.count(FeedbackLabel.id))
        .where(FeedbackLabel.used_for_training == False)  # noqa: E712
    )
    return result.scalar()


async def mark_feedback_used(db: AsyncSession, feedback_ids: List[str]) -> None:
    """Marque les feedbacks comme utilisés après un ré-entraînement."""
    await db.execute(
        update(FeedbackLabel)
        .where(FeedbackLabel.id.in_(feedback_ids))
        .values(used_for_training=True)
    )


# ---- Data Retention ----

async def delete_old_flows_batch(
    db: AsyncSession,
    older_than_days: int,
    batch_size: int = 5000,
    keep_alerted_flows: bool = True,
) -> int:
    """
    Supprime un lot de flux anciens pour libérer de l'espace (Rétention des données).
    
    Args:
        older_than_days: Âge minimum des flux à supprimer.
        batch_size: Nombre max de suppressions par appel (évite de bloquer la DB).
        keep_alerted_flows: Si True, ne supprime jamais les flux liés à une alerte.
        
    Returns:
        int: Nombre d'enregistrements supprimés.
    """
    cutoff = datetime.utcnow() - timedelta(days=older_than_days)

    ids_query = (
        select(NetworkFlow.id)
        .where(NetworkFlow.timestamp < cutoff)
        .order_by(NetworkFlow.timestamp.asc())
        .limit(batch_size)
    )

    if keep_alerted_flows:
        # Exclusion des flux liés à une alerte existante
        alert_exists = exists(select(Alert.id).where(Alert.flow_id == NetworkFlow.id))
        ids_query = ids_query.where(~alert_exists)

    result = await db.execute(ids_query)
    flow_ids = [row[0] for row in result.all()]

    if not flow_ids:
        return 0

    delete_result = await db.execute(delete(NetworkFlow).where(NetworkFlow.id.in_(flow_ids)))
    return delete_result.rowcount or len(flow_ids)
