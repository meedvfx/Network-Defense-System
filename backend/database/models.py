"""
Modèles ORM SQLAlchemy pour les 7 tables du SOC.
Chaque modèle représente une table de la base de données PostgreSQL.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime,
    ForeignKey, Text, BigInteger, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from backend.database.connection import Base


def generate_uuid():
    """Génère un UUID v4."""
    return str(uuid.uuid4())


class NetworkFlow(Base):
    """Flux réseau capturés et leurs features extraites."""
    __tablename__ = "network_flows"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)
    protocol = Column(Integer, nullable=False)
    duration = Column(Float, default=0.0)
    total_fwd_packets = Column(BigInteger, default=0)
    total_bwd_packets = Column(BigInteger, default=0)
    flow_bytes_per_s = Column(Float, default=0.0)
    flow_packets_per_s = Column(Float, default=0.0)
    raw_features = Column(JSONB, nullable=True)

    # Relations
    predictions = relationship("Prediction", back_populates="flow", cascade="all, delete-orphan")
    anomaly_scores = relationship("AnomalyScore", back_populates="flow", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="flow", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_flows_timestamp_desc", timestamp.desc()),
        Index("idx_flows_src_dst", src_ip, dst_ip),
    )


class Prediction(Base):
    """Prédictions du modèle supervisé."""
    __tablename__ = "predictions"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    flow_id = Column(UUID(as_uuid=False), ForeignKey("network_flows.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    model_version = Column(String(50), nullable=False)
    predicted_label = Column(String(100), nullable=False, index=True)
    confidence = Column(Float, nullable=False)
    class_probabilities = Column(JSONB, nullable=True)

    # Relations
    flow = relationship("NetworkFlow", back_populates="predictions")


class AnomalyScore(Base):
    """Scores d'anomalie du modèle non-supervisé."""
    __tablename__ = "anomaly_scores"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    flow_id = Column(UUID(as_uuid=False), ForeignKey("network_flows.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    reconstruction_error = Column(Float, nullable=False)
    anomaly_score = Column(Float, nullable=False)
    threshold_used = Column(Float, nullable=False)
    is_anomaly = Column(Boolean, default=False)

    # Relations
    flow = relationship("NetworkFlow", back_populates="anomaly_scores")


class Alert(Base):
    """Alertes générées par le système de détection."""
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    flow_id = Column(UUID(as_uuid=False), ForeignKey("network_flows.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    severity = Column(String(20), nullable=False, index=True)  # low, medium, high, critical
    attack_type = Column(String(100), nullable=True)
    threat_score = Column(Float, nullable=False)
    decision = Column(String(50), nullable=False)  # normal, suspicious, confirmed_attack, unknown_anomaly
    status = Column(String(20), default="open", index=True)  # open, acknowledged, resolved, false_positive
    alert_metadata = Column(JSONB, nullable=True)

    # Relations
    flow = relationship("NetworkFlow", back_populates="alerts")
    feedback = relationship("FeedbackLabel", back_populates="alert", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_alerts_severity_time", severity, timestamp.desc()),
    )


class IPGeolocation(Base):
    """Cache de géolocalisation des adresses IP."""
    __tablename__ = "ip_geolocation"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    country = Column(String(100), nullable=True)
    country_code = Column(String(5), nullable=True)
    city = Column(String(200), nullable=True)
    region = Column(String(200), nullable=True)
    asn = Column(String(50), nullable=True)
    isp = Column(String(200), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    last_updated = Column(DateTime, default=datetime.utcnow, nullable=False)


class ModelVersion(Base):
    """Registre de versions des modèles AI."""
    __tablename__ = "model_versions"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    model_type = Column(String(50), nullable=False)  # supervised, unsupervised
    version = Column(String(20), nullable=False)
    file_path = Column(String(500), nullable=False)
    accuracy = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    loss = Column(Float, nullable=True)
    trained_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_active = Column(Boolean, default=False)
    training_config = Column(JSONB, nullable=True)
    training_samples = Column(Integer, nullable=True)
    notes = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_model_active", model_type, is_active),
    )


class FeedbackLabel(Base):
    """Feedback des analystes SOC pour l'auto-learning."""
    __tablename__ = "feedback_labels"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    alert_id = Column(UUID(as_uuid=False), ForeignKey("alerts.id"), nullable=False)
    analyst_label = Column(String(100), nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    used_for_training = Column(Boolean, default=False)

    # Relations
    alert = relationship("Alert", back_populates="feedback")

    __table_args__ = (
        Index("idx_feedback_unused", used_for_training),
    )
