-- ============================================
-- Network Defense System — Initial Schema
-- PostgreSQL 16+
-- ============================================

-- Extension UUID
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================
-- Table: network_flows
-- Flux réseau capturés avec features extraites
-- ============================================
CREATE TABLE IF NOT EXISTS network_flows (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp       TIMESTAMP NOT NULL DEFAULT NOW(),
    src_ip          VARCHAR(45) NOT NULL,
    dst_ip          VARCHAR(45) NOT NULL,
    src_port        INTEGER NOT NULL,
    dst_port        INTEGER NOT NULL,
    protocol        INTEGER NOT NULL,
    duration        FLOAT DEFAULT 0.0,
    total_fwd_packets   BIGINT DEFAULT 0,
    total_bwd_packets   BIGINT DEFAULT 0,
    flow_bytes_per_s    FLOAT DEFAULT 0.0,
    flow_packets_per_s  FLOAT DEFAULT 0.0,
    raw_features    JSONB
);

-- ============================================
-- Table: predictions
-- Prédictions du modèle supervisé
-- ============================================
CREATE TABLE IF NOT EXISTS predictions (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    flow_id             UUID NOT NULL REFERENCES network_flows(id) ON DELETE CASCADE,
    timestamp           TIMESTAMP NOT NULL DEFAULT NOW(),
    model_version       VARCHAR(50) NOT NULL,
    predicted_label     VARCHAR(100) NOT NULL,
    confidence          FLOAT NOT NULL,
    class_probabilities JSONB
);

-- ============================================
-- Table: anomaly_scores
-- Scores d'anomalie du modèle non-supervisé
-- ============================================
CREATE TABLE IF NOT EXISTS anomaly_scores (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    flow_id                 UUID NOT NULL REFERENCES network_flows(id) ON DELETE CASCADE,
    timestamp               TIMESTAMP NOT NULL DEFAULT NOW(),
    reconstruction_error    FLOAT NOT NULL,
    anomaly_score           FLOAT NOT NULL,
    threshold_used          FLOAT NOT NULL,
    is_anomaly              BOOLEAN DEFAULT FALSE
);

-- ============================================
-- Table: alerts
-- Alertes générées par le moteur hybride
-- ============================================
CREATE TABLE IF NOT EXISTS alerts (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    flow_id         UUID NOT NULL REFERENCES network_flows(id) ON DELETE CASCADE,
    timestamp       TIMESTAMP NOT NULL DEFAULT NOW(),
    severity        VARCHAR(20) NOT NULL,
    attack_type     VARCHAR(100),
    threat_score    FLOAT NOT NULL,
    decision        VARCHAR(50) NOT NULL,
    status          VARCHAR(20) DEFAULT 'open',
    metadata        JSONB
);

-- ============================================
-- Table: ip_geolocation
-- Cache de géolocalisation des IP
-- ============================================
CREATE TABLE IF NOT EXISTS ip_geolocation (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address      VARCHAR(45) UNIQUE NOT NULL,
    country         VARCHAR(100),
    country_code    VARCHAR(5),
    city            VARCHAR(200),
    region          VARCHAR(200),
    asn             VARCHAR(50),
    isp             VARCHAR(200),
    latitude        FLOAT,
    longitude       FLOAT,
    last_updated    TIMESTAMP NOT NULL DEFAULT NOW()
);

-- ============================================
-- Table: model_versions
-- Registre de versions des modèles AI
-- ============================================
CREATE TABLE IF NOT EXISTS model_versions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_type      VARCHAR(50) NOT NULL,
    version         VARCHAR(20) NOT NULL,
    file_path       VARCHAR(500) NOT NULL,
    accuracy        FLOAT,
    f1_score        FLOAT,
    loss            FLOAT,
    trained_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    is_active       BOOLEAN DEFAULT FALSE,
    training_config JSONB,
    training_samples INTEGER,
    notes           TEXT
);

-- ============================================
-- Table: feedback_labels
-- Feedback des analystes SOC
-- ============================================
CREATE TABLE IF NOT EXISTS feedback_labels (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id            UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    analyst_label       VARCHAR(100) NOT NULL,
    notes               TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    used_for_training   BOOLEAN DEFAULT FALSE
);

-- ============================================
-- INDEXES — Performance
-- ============================================
CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON network_flows(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON network_flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON network_flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_src_dst ON network_flows(src_ip, dst_ip);

CREATE INDEX IF NOT EXISTS idx_predictions_label ON predictions(predicted_label);
CREATE INDEX IF NOT EXISTS idx_predictions_flow ON predictions(flow_id);

CREATE INDEX IF NOT EXISTS idx_anomaly_flow ON anomaly_scores(flow_id);
CREATE INDEX IF NOT EXISTS idx_anomaly_is_anomaly ON anomaly_scores(is_anomaly);

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_flow ON alerts(flow_id);

CREATE INDEX IF NOT EXISTS idx_geo_ip ON ip_geolocation(ip_address);

CREATE INDEX IF NOT EXISTS idx_model_active ON model_versions(model_type, is_active);

CREATE INDEX IF NOT EXISTS idx_feedback_unused ON feedback_labels(used_for_training)
    WHERE NOT used_for_training;
CREATE INDEX IF NOT EXISTS idx_feedback_alert ON feedback_labels(alert_id);
