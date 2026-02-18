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
    """
    Modèle représentant un flux réseau (Network Flow) capturé.
    
    Un flux est une agrégation de paquets partageant les mêmes 5-tuple (Src IP, Dst IP, Src Port, Dst Port, Protocol).
    Il contient les métriques brutes et les fonctionnalités extraites (features) utilisées par les modèles d'IA.
    """
    __tablename__ = "network_flows"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Identifiants du flux (5-tuple)
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)
    protocol = Column(Integer, nullable=False) # 6=TCP, 17=UDP, etc.
    
    # Métriques de base
    duration = Column(Float, default=0.0) # Durée du flux en secondes
    total_fwd_packets = Column(BigInteger, default=0) # Total paquets aller
    total_bwd_packets = Column(BigInteger, default=0) # Total paquets retour
    flow_bytes_per_s = Column(Float, default=0.0) # Débit octets/sec
    flow_packets_per_s = Column(Float, default=0.0) # Débit paquets/sec
    
    # Features complètes pour l'IA (JSON)
    # Stocke ~78 features CIC-IDS (min, max, mean, std des temps inter-arrivées, tailles de paquets, flags...)
    raw_features = Column(JSONB, nullable=True)

    # Relations avec les résultats d'analyse
    predictions = relationship("Prediction", back_populates="flow", cascade="all, delete-orphan")
    anomaly_scores = relationship("AnomalyScore", back_populates="flow", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="flow", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_flows_timestamp_desc", timestamp.desc()),
        Index("idx_flows_src_dst", src_ip, dst_ip),
    )


class Prediction(Base):
    """
    Résultat de l'inférence du modèle SUPERVISÉ (classification multi-classes).
    Indique le type d'attaque présumé (ou BENIGN) avec un score de confiance.
    """
    __tablename__ = "predictions"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    flow_id = Column(UUID(as_uuid=False), ForeignKey("network_flows.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    model_version = Column(String(50), nullable=False) # Version du modèle utilisé (ex: v1.0.0)
    
    # Résultat principal
    predicted_label = Column(String(100), nullable=False, index=True) # Ex: DDoS, PortScan, BENIGN
    confidence = Column(Float, nullable=False) # Score de confiance (0.0 à 1.0)
    
    # Détail des probabilités pour chaque classe (JSON)
    # Ex: {"BENIGN": 0.01, "DDoS": 0.99, ...}
    class_probabilities = Column(JSONB, nullable=True)

    # Relations
    flow = relationship("NetworkFlow", back_populates="predictions")


class AnomalyScore(Base):
    """
    Résultat de l'inférence du modèle NON-SUPERVISÉ (Autoencoder).
    Mesure l'écart par rapport au trafic normal appris (erreur de reconstruction).
    """
    __tablename__ = "anomaly_scores"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    flow_id = Column(UUID(as_uuid=False), ForeignKey("network_flows.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Métriques d'anomalie
    reconstruction_error = Column(Float, nullable=False) # Erreur MSE brute
    anomaly_score = Column(Float, nullable=False) # Score normalisé
    threshold_used = Column(Float, nullable=False) # Seuil utilisé pour la décision
    is_anomaly = Column(Boolean, default=False) # True si erreur > seuil

    # Relations
    flow = relationship("NetworkFlow", back_populates="anomaly_scores")


class Alert(Base):
    """
    Alerte de sécurité générée par le moteur de décision hybride.
    Une alerte est levée quand le modèle supervisé OU l'autoencoder détectent une menace significative.
    """
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    flow_id = Column(UUID(as_uuid=False), ForeignKey("network_flows.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Classification de la menace
    severity = Column(String(20), nullable=False, index=True)  # critical, high, medium, low
    attack_type = Column(String(100), nullable=True) # Type d'attaque identifié (si supervisé) ou "Anomaly"
    threat_score = Column(Float, nullable=False) # Score global de risque (0.0 à 1.0)
    
    # Décision du moteur hybride
    decision = Column(String(50), nullable=False)  # confirmed_attack, suspicious, unknown_anomaly
    
    # Gestion du cycle de vie de l'alerte
    status = Column(String(20), default="open", index=True)  # open, acknowledged, resolved, false_positive
    
    # Métadonnées contextuelles (ex: règle déclenchée, composants du score...)
    alert_metadata = Column(JSONB, nullable=True)

    # Relations
    flow = relationship("NetworkFlow", back_populates="alerts")
    feedback = relationship("FeedbackLabel", back_populates="alert", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_alerts_severity_time", severity, timestamp.desc()),
    )


class IPGeolocation(Base):
    """
    Cache local pour les informations de géolocalisation des adresses IP.
    Évite de requêter l'API externe (ip-api.com) à chaque fois.
    """
    __tablename__ = "ip_geolocation"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    
    # Informations géographiques
    country = Column(String(100), nullable=True)
    country_code = Column(String(5), nullable=True)
    city = Column(String(200), nullable=True)
    region = Column(String(200), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    
    # Informations FAI / Réseau
    asn = Column(String(50), nullable=True)
    isp = Column(String(200), nullable=True)
    
    last_updated = Column(DateTime, default=datetime.utcnow, nullable=False)


class ModelVersion(Base):
    """
    Registre des versions de modèles d'IA (MLOps).
    Permet de suivre quels modèles ont été entraînés, leurs performances, et lequel est actif.
    """
    __tablename__ = "model_versions"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    model_type = Column(String(50), nullable=False)  # supervised, unsupervised
    version = Column(String(20), nullable=False) # Tag (ex: v1.0, 20231024_1200)
    file_path = Column(String(500), nullable=False) # Chemin vers le fichier .keras
    
    # Métriques de performance
    accuracy = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    loss = Column(Float, nullable=True)
    
    # Métadonnées d'entraînement
    trained_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_active = Column(Boolean, default=False) # Un seul modèle actif par type à la fois
    training_config = Column(JSONB, nullable=True) # Hyperparamètres utilisés
    training_samples = Column(Integer, nullable=True) # Nombre d'échantillons d'entraînement
    
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
