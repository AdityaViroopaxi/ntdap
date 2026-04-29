-- ============================================================
-- NTDAP MySQL Setup Script
-- Run this ONE TIME in MySQL Workbench before starting the app
-- ============================================================

-- 1. Create the database
CREATE DATABASE IF NOT EXISTS ntdap_db;
USE ntdap_db;

-- 2. Create a dedicated user (optional but recommended)
--    Replace 'your_password' with a password you choose
-- CREATE USER IF NOT EXISTS 'ntdap_user'@'localhost' IDENTIFIED BY 'your_password';
-- GRANT ALL PRIVILEGES ON ntdap_db.* TO 'ntdap_user'@'localhost';
-- FLUSH PRIVILEGES;

-- NOTE: The Python app (db.py) will auto-create all tables below
-- when it starts. You don't need to run the CREATE TABLE statements
-- manually — they are here just for your reference.

-- ── Table: capture_sessions ──────────────────────────────────────
-- One row per uploaded PCAP file
CREATE TABLE IF NOT EXISTS capture_sessions (
    id                      INT AUTO_INCREMENT PRIMARY KEY,
    filename                VARCHAR(255)    NOT NULL,
    uploaded_at             DATETIME        DEFAULT CURRENT_TIMESTAMP,
    total_packets           INT             DEFAULT 0,
    total_bytes             BIGINT          DEFAULT 0,
    avg_packet_size         FLOAT           DEFAULT 0,
    capture_duration_secs   FLOAT           DEFAULT 0,
    packets_per_second      FLOAT           DEFAULT 0,
    most_common_protocol    VARCHAR(50),
    unique_src_ips          INT             DEFAULT 0,
    unique_dst_ips          INT             DEFAULT 0,
    anomaly_count           INT             DEFAULT 0,
    anomaly_percentage      FLOAT           DEFAULT 0,
    port_scan_detected      TINYINT(1)      DEFAULT 0
);

-- ── Table: packets ────────────────────────────────────────────────
-- One row per packet in a capture session
CREATE TABLE IF NOT EXISTS packets (
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    session_id          INT             NOT NULL,
    packet_number       INT,
    timestamp           DOUBLE,
    relative_time       FLOAT,
    packet_length       INT,
    payload_length      INT,
    protocol            VARCHAR(20),
    src_ip              VARCHAR(45),
    dst_ip              VARCHAR(45),
    src_port            INT,
    dst_port            INT,
    ttl                 INT,
    tcp_flags           VARCHAR(20),
    window_size         INT,
    inter_arrival_time  FLOAT,
    payload_ratio       FLOAT,
    is_private_src      TINYINT(1)      DEFAULT 0,
    is_private_dst      TINYINT(1)      DEFAULT 0,
    is_anomaly          TINYINT(1)      DEFAULT 0,
    anomaly_score       FLOAT,
    FOREIGN KEY (session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE,
    INDEX idx_session   (session_id),
    INDEX idx_protocol  (protocol),
    INDEX idx_src_ip    (src_ip),
    INDEX idx_dst_ip    (dst_ip)
);

-- ── Table: anomaly_alerts ─────────────────────────────────────────
-- Port scan and statistical alerts detected per session
CREATE TABLE IF NOT EXISTS anomaly_alerts (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    session_id      INT             NOT NULL,
    alert_type      VARCHAR(50),
    src_ip          VARCHAR(45),
    detail          TEXT,
    created_at      DATETIME        DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE
);

-- ── Useful queries for MySQL Workbench ───────────────────────────

-- View all sessions:
-- SELECT * FROM capture_sessions ORDER BY uploaded_at DESC;

-- View all packets in session 1:
-- SELECT * FROM packets WHERE session_id = 1 LIMIT 100;

-- View only anomalous packets:
-- SELECT * FROM packets WHERE is_anomaly = 1;

-- View all alerts:
-- SELECT * FROM anomaly_alerts ORDER BY created_at DESC;

-- Count packets per protocol in a session:
-- SELECT protocol, COUNT(*) as count FROM packets WHERE session_id = 1 GROUP BY protocol;
