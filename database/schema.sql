-- Run after creating the database:  CREATE DATABASE cybersecurity_db;
-- (or simply run: python -m database.init_db)

CREATE TABLE IF NOT EXISTS security_logs (
    event_id       VARCHAR(36)      PRIMARY KEY,
    event_time     TIMESTAMPTZ      NOT NULL,
    ip_address     VARCHAR(45)      NOT NULL,
    username       VARCHAR(64),
    event_type     VARCHAR(32)      NOT NULL,
    action         VARCHAR(64),
    status         VARCHAR(16)      NOT NULL,
    endpoint       VARCHAR(255),
    http_method    VARCHAR(10),
    response_code  INTEGER,
    response_time  DOUBLE PRECISION,           -- milliseconds
    bytes_sent     BIGINT,
    ingested_at    TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_logs_event_time    ON security_logs (event_time);
CREATE INDEX IF NOT EXISTS idx_logs_ip_address    ON security_logs (ip_address);
CREATE INDEX IF NOT EXISTS idx_logs_event_type    ON security_logs (event_type);
CREATE INDEX IF NOT EXISTS idx_logs_status        ON security_logs (status);
CREATE INDEX IF NOT EXISTS idx_logs_response_code ON security_logs (response_code);

CREATE TABLE IF NOT EXISTS security_alerts (
    alert_id      BIGSERIAL    PRIMARY KEY,
    alert_time    TIMESTAMPTZ  NOT NULL,
    window_start  TIMESTAMPTZ  NOT NULL,
    ip_address    VARCHAR(45)  NOT NULL,
    threat_type   VARCHAR(40)  NOT NULL,
    severity      VARCHAR(10)  NOT NULL,
    description   TEXT,
    event_count   INTEGER,
    CONSTRAINT uq_alert UNIQUE (window_start, ip_address, threat_type)
);
CREATE INDEX IF NOT EXISTS idx_alerts_alert_time  ON security_alerts (alert_time);
CREATE INDEX IF NOT EXISTS idx_alerts_ip_address  ON security_alerts (ip_address);
CREATE INDEX IF NOT EXISTS idx_alerts_threat_type ON security_alerts (threat_type);
CREATE INDEX IF NOT EXISTS idx_alerts_severity    ON security_alerts (severity);

CREATE TABLE IF NOT EXISTS ip_window_stats (
    window_start       TIMESTAMPTZ      NOT NULL,
    window_end         TIMESTAMPTZ      NOT NULL,
    ip_address         VARCHAR(45)      NOT NULL,
    total_requests     INTEGER          NOT NULL,
    failed_logins      INTEGER          NOT NULL,
    error_responses    INTEGER          NOT NULL,
    privileged_events  INTEGER          NOT NULL,
    avg_response_time  DOUBLE PRECISION,
    max_response_time  DOUBLE PRECISION,
    total_bytes        BIGINT,
    PRIMARY KEY (window_start, ip_address)
);
CREATE INDEX IF NOT EXISTS idx_stats_window_start ON ip_window_stats (window_start);
