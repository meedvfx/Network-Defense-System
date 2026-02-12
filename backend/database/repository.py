"""
Couche d'accès aux données (Repository pattern).
Requêtes optimisées avec pagination et filtres.
"""

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from uuid import uuid4

from sqlalchemy import select, func, desc, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.models import (
    NetworkFlow, Prediction, AnomalyScore,
    Alert, IPGeolocation, ModelVersion, FeedbackLabel
)


class FlowRepository:
    """Opérations CRUD pour les flux réseau."""

    @staticmethod
    async def create(db: AsyncSession, flow_data: dict) -> NetworkFlow:
        flow = NetworkFlow(id=str(uuid4()), **flow_data)
        db.add(flow)
        await db.flush()
        return flow

    @staticmethod
    async def create_batch(db: AsyncSession, flows_data: List[dict]) -> List[NetworkFlow]:
        flows = [NetworkFlow(id=str(uuid4()), **data) for data in flows_data]
        db.add_all(flows)
        await db.flush()
        return flows

    @staticmethod
    async def get_recent(db: AsyncSession, limit: int = 100, offset: int = 0) -> List[NetworkFlow]:
        result = await db.execute(
            select(NetworkFlow)
            .order_by(desc(NetworkFlow.timestamp))
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    @staticmethod
    async def count(db: AsyncSession) -> int:
        result = await db.execute(select(func.count(NetworkFlow.id)))
        return result.scalar()


class PredictionRepository:
    """Opérations CRUD pour les prédictions supervisées."""

    @staticmethod
    async def create(db: AsyncSession, prediction_data: dict) -> Prediction:
        prediction = Prediction(id=str(uuid4()), **prediction_data)
        db.add(prediction)
        await db.flush()
        return prediction

    @staticmethod
    async def get_by_flow(db: AsyncSession, flow_id: str) -> Optional[Prediction]:
        result = await db.execute(
            select(Prediction).where(Prediction.flow_id == flow_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_attack_distribution(db: AsyncSession, hours: int = 24) -> List[Dict[str, Any]]:
        since = datetime.utcnow() - timedelta(hours=hours)
        result = await db.execute(
            select(
                Prediction.predicted_label,
                func.count(Prediction.id).label("count")
            )
            .where(Prediction.timestamp >= since)
            .group_by(Prediction.predicted_label)
            .order_by(desc("count"))
        )
        return [{"label": row[0], "count": row[1]} for row in result.all()]


class AnomalyRepository:
    """Opérations CRUD pour les scores d'anomalie."""

    @staticmethod
    async def create(db: AsyncSession, anomaly_data: dict) -> AnomalyScore:
        anomaly = AnomalyScore(id=str(uuid4()), **anomaly_data)
        db.add(anomaly)
        await db.flush()
        return anomaly

    @staticmethod
    async def get_anomalies(db: AsyncSession, limit: int = 50) -> List[AnomalyScore]:
        result = await db.execute(
            select(AnomalyScore)
            .where(AnomalyScore.is_anomaly == True)  # noqa: E712
            .order_by(desc(AnomalyScore.timestamp))
            .limit(limit)
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_anomaly_rate(db: AsyncSession, hours: int = 24) -> float:
        since = datetime.utcnow() - timedelta(hours=hours)
        total = await db.execute(
            select(func.count(AnomalyScore.id)).where(AnomalyScore.timestamp >= since)
        )
        anomalies = await db.execute(
            select(func.count(AnomalyScore.id))
            .where(AnomalyScore.timestamp >= since)
            .where(AnomalyScore.is_anomaly == True)  # noqa: E712
        )
        total_count = total.scalar()
        if total_count == 0:
            return 0.0
        return anomalies.scalar() / total_count


class AlertRepository:
    """Opérations CRUD pour les alertes."""

    @staticmethod
    async def create(db: AsyncSession, alert_data: dict) -> Alert:
        alert = Alert(id=str(uuid4()), **alert_data)
        db.add(alert)
        await db.flush()
        return alert

    @staticmethod
    async def get_alerts(
        db: AsyncSession,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Alert]:
        query = select(Alert)
        if severity:
            query = query.where(Alert.severity == severity)
        if status:
            query = query.where(Alert.status == status)
        query = query.order_by(desc(Alert.timestamp)).limit(limit).offset(offset)
        result = await db.execute(query)
        return list(result.scalars().all())

    @staticmethod
    async def update_status(db: AsyncSession, alert_id: str, new_status: str) -> None:
        await db.execute(
            update(Alert).where(Alert.id == alert_id).values(status=new_status)
        )

    @staticmethod
    async def get_stats(db: AsyncSession, hours: int = 24) -> Dict[str, Any]:
        since = datetime.utcnow() - timedelta(hours=hours)
        total = await db.execute(
            select(func.count(Alert.id)).where(Alert.timestamp >= since)
        )
        by_severity = await db.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.timestamp >= since)
            .group_by(Alert.severity)
        )
        return {
            "total": total.scalar(),
            "by_severity": {row[0]: row[1] for row in by_severity.all()},
        }

    @staticmethod
    async def get_top_ips(db: AsyncSession, limit: int = 10, hours: int = 24) -> List[Dict]:
        since = datetime.utcnow() - timedelta(hours=hours)
        result = await db.execute(
            select(
                NetworkFlow.src_ip,
                func.count(Alert.id).label("alert_count"),
                func.avg(Alert.threat_score).label("avg_threat")
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


class GeoRepository:
    """Opérations CRUD pour la géolocalisation."""

    @staticmethod
    async def upsert(db: AsyncSession, geo_data: dict) -> IPGeolocation:
        existing = await db.execute(
            select(IPGeolocation).where(IPGeolocation.ip_address == geo_data["ip_address"])
        )
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

    @staticmethod
    async def get_by_ip(db: AsyncSession, ip_address: str) -> Optional[IPGeolocation]:
        result = await db.execute(
            select(IPGeolocation).where(IPGeolocation.ip_address == ip_address)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_all(db: AsyncSession) -> List[IPGeolocation]:
        result = await db.execute(select(IPGeolocation))
        return list(result.scalars().all())


class ModelVersionRepository:
    """Opérations CRUD pour le registre de modèles."""

    @staticmethod
    async def create(db: AsyncSession, model_data: dict) -> ModelVersion:
        model = ModelVersion(id=str(uuid4()), **model_data)
        db.add(model)
        await db.flush()
        return model

    @staticmethod
    async def get_active(db: AsyncSession, model_type: str) -> Optional[ModelVersion]:
        result = await db.execute(
            select(ModelVersion)
            .where(ModelVersion.model_type == model_type)
            .where(ModelVersion.is_active == True)  # noqa: E712
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def set_active(db: AsyncSession, model_id: str, model_type: str) -> None:
        # Désactiver tous les modèles du même type
        await db.execute(
            update(ModelVersion)
            .where(ModelVersion.model_type == model_type)
            .values(is_active=False)
        )
        # Activer le nouveau
        await db.execute(
            update(ModelVersion)
            .where(ModelVersion.id == model_id)
            .values(is_active=True)
        )

    @staticmethod
    async def get_versions(db: AsyncSession, model_type: str) -> List[ModelVersion]:
        result = await db.execute(
            select(ModelVersion)
            .where(ModelVersion.model_type == model_type)
            .order_by(desc(ModelVersion.trained_at))
        )
        return list(result.scalars().all())


class FeedbackRepository:
    """Opérations CRUD pour les feedback analystes."""

    @staticmethod
    async def create(db: AsyncSession, feedback_data: dict) -> FeedbackLabel:
        feedback = FeedbackLabel(id=str(uuid4()), **feedback_data)
        db.add(feedback)
        await db.flush()
        return feedback

    @staticmethod
    async def get_unused(db: AsyncSession) -> List[FeedbackLabel]:
        result = await db.execute(
            select(FeedbackLabel)
            .where(FeedbackLabel.used_for_training == False)  # noqa: E712
            .order_by(FeedbackLabel.created_at)
        )
        return list(result.scalars().all())

    @staticmethod
    async def count_unused(db: AsyncSession) -> int:
        result = await db.execute(
            select(func.count(FeedbackLabel.id))
            .where(FeedbackLabel.used_for_training == False)  # noqa: E712
        )
        return result.scalar()

    @staticmethod
    async def mark_used(db: AsyncSession, feedback_ids: List[str]) -> None:
        await db.execute(
            update(FeedbackLabel)
            .where(FeedbackLabel.id.in_(feedback_ids))
            .values(used_for_training=True)
        )
