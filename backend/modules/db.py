# db.py — NTDAP v4.0 Advanced MySQL Database Module
# Extended schema with threat alerts, flow table, and session tagging.

import os
import json
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv

load_dotenv()

DB_CONFIG = {
    "host":     os.getenv("MYSQLHOST"),
    "port":     int(os.getenv("MYSQLPORT", 3306)),
    "user":     os.getenv("MYSQLUSER"),
    "password": os.getenv("MYSQLPASSWORD"),
    "database": os.getenv("MYSQLDATABASE"),
}
def get_connection():
    return mysql.connector.connect(**DB_CONFIG)


def init_db():
    cfg = {k: v for k, v in DB_CONFIG.items() if k != "database"}
    conn = mysql.connector.connect(**cfg)
    cur  = conn.cursor()
    cur.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
    cur.execute(f"USE {DB_CONFIG['database']}")

    # ── sessions ──────────────────────────────────────────────────
    cur.execute("""
                USE ntdap_db;
    CREATE TABLE IF NOT EXISTS capture_sessions (
        id INT AUTO_INCREMENT PRIMARY KEY,

        user_id INT NOT NULL,

        filename VARCHAR(255) NOT NULL,
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,

        total_packets INT DEFAULT 0,
        total_bytes BIGINT DEFAULT 0,
        avg_packet_size FLOAT DEFAULT 0,
        capture_duration_secs FLOAT DEFAULT 0,
        packets_per_second FLOAT DEFAULT 0,
        bytes_per_second FLOAT DEFAULT 0,

        most_common_protocol VARCHAR(50),
        protocol_count INT DEFAULT 0,

        unique_src_ips INT DEFAULT 0,
        unique_dst_ips INT DEFAULT 0,
        unique_flows INT DEFAULT 0,

        anomaly_count INT DEFAULT 0,
        anomaly_percentage FLOAT DEFAULT 0,

        severity VARCHAR(20) DEFAULT 'NORMAL',
        severity_score INT DEFAULT 0,

        port_scan_detected TINYINT(1) DEFAULT 0,
        syn_flood_detected TINYINT(1) DEFAULT 0,
        beaconing_detected TINYINT(1) DEFAULT 0,
        dns_tunnel_detected TINYINT(1) DEFAULT 0,

        suspicious_port_count INT DEFAULT 0,
        contamination_estimate FLOAT DEFAULT 0,

        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,

        INDEX idx_uploaded (uploaded_at),
        INDEX idx_severity (severity)
    )
""")

    # ── packets ───────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id                  INT AUTO_INCREMENT PRIMARY KEY,
            session_id          INT             NOT NULL,
            packet_number       INT,
            timestamp           DOUBLE,
            relative_time       FLOAT,
            packet_length       INT,
            payload_length      INT,
            protocol            VARCHAR(30),
            src_ip              VARCHAR(45),
            dst_ip              VARCHAR(45),
            src_port            INT,
            dst_port            INT,
            ttl                 INT,
            tcp_flags           VARCHAR(20),
            tcp_flags_value     INT,
            window_size         INT,
            inter_arrival_time  FLOAT,
            payload_ratio       FLOAT,
            flow_packet_count   INT,
            flow_bytes_total    BIGINT,
            flow_duration       FLOAT,
            is_private_src      TINYINT(1) DEFAULT 0,
            is_private_dst      TINYINT(1) DEFAULT 0,
            is_suspicious_port  TINYINT(1) DEFAULT 0,
            is_multicast        TINYINT(1) DEFAULT 0,
            flag_syn            TINYINT(1) DEFAULT 0,
            flag_ack            TINYINT(1) DEFAULT 0,
            flag_rst            TINYINT(1) DEFAULT 0,
            flag_fin            TINYINT(1) DEFAULT 0,
            packet_type         VARCHAR(20),
            dns_query           VARCHAR(255),
            http_method         VARCHAR(10),
            is_anomaly          TINYINT(1) DEFAULT 0,
            anomaly_score       FLOAT,
            FOREIGN KEY (session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE,
            INDEX idx_session   (session_id),
            INDEX idx_protocol  (protocol),
            INDEX idx_src_ip    (src_ip),
            INDEX idx_is_anom   (is_anomaly),
            INDEX idx_pkt_type  (packet_type)
        )
    """)

    # ── threat_alerts ─────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS threat_alerts (
            id              INT AUTO_INCREMENT PRIMARY KEY,
            session_id      INT             NOT NULL,
            alert_type      VARCHAR(50),
            severity        VARCHAR(20),
            src_ip          VARCHAR(45),
            dst_ip          VARCHAR(45),
            detail          JSON,
            created_at      DATETIME        DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE,
            INDEX idx_session  (session_id),
            INDEX idx_type     (alert_type),
            INDEX idx_severity (severity)
        )
    """)

    conn.commit()
    cur.close()
    conn.close()
    print("✅ MySQL DB v4.0 initialized.")


def save_session(filename, stats, anomaly_results, clean_df, labels, user_id):
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO capture_sessions (
                user_id,
                filename,
                total_packets,
                total_bytes,
                avg_packet_size,
                anomaly_count,
                anomaly_percentage,
                severity,
                uploaded_at
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,NOW())
        """, (
            user_id,
            filename,
            stats.get("total_packets", 0),
            stats.get("total_bytes", 0),
            stats.get("avg_packet_size", 0),
            anomaly_results.get("anomaly_count", 0),
            anomaly_results.get("anomaly_percentage", 0),
            "UNKNOWN"
        ))

        session_id = cur.lastrowid
        conn.commit()

        print("✅ Session saved successfully")
        return session_id

    except Exception as e:
        conn.rollback()
        print("DB SAVE ERROR:", e)
        raise e

    finally:
        cur.close()
        conn.close()


def update_session_severity(session_id, severity, severity_score):
    conn = get_connection()
    cur  = conn.cursor()
    try:
        cur.execute(
            "UPDATE capture_sessions SET severity=%s, severity_score=%s WHERE id=%s",
            (severity, severity_score, session_id)
        )
        conn.commit()
    finally:
        cur.close()
        conn.close()


def get_all_sessions():
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT id, filename, uploaded_at, total_packets, total_bytes,
               most_common_protocol, protocol_count,
               unique_src_ips, unique_dst_ips, unique_flows,
               anomaly_count, anomaly_percentage,
               severity, severity_score,
               port_scan_detected, syn_flood_detected,
               beaconing_detected, dns_tunnel_detected,
               suspicious_port_count
        FROM capture_sessions
        ORDER BY uploaded_at DESC
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()
    for r in rows:
        if r.get("uploaded_at"):
            r["uploaded_at"] = str(r["uploaded_at"])
    return rows


def get_session_detail(session_id):
    """Full detail for one session including packets and threat alerts."""
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)

    cur.execute("SELECT * FROM capture_sessions WHERE id=%s", (session_id,))
    session = cur.fetchone()
    if session and session.get("uploaded_at"):
        session["uploaded_at"] = str(session["uploaded_at"])

    cur.execute("""
        SELECT packet_number, protocol, src_ip, dst_ip, src_port, dst_port,
               packet_length, ttl, tcp_flags, is_anomaly, anomaly_score,
               packet_type, dns_query, http_method
        FROM packets WHERE session_id=%s ORDER BY packet_number ASC LIMIT 500
    """, (session_id,))
    packets = cur.fetchall()

    cur.execute("""
        SELECT alert_type, severity, src_ip, dst_ip, detail, created_at
        FROM threat_alerts WHERE session_id=%s ORDER BY severity DESC
    """, (session_id,))
    alerts = cur.fetchall()
    for a in alerts:
        if a.get("created_at"):
            a["created_at"] = str(a["created_at"])
        if isinstance(a.get("detail"), str):
            try: a["detail"] = json.loads(a["detail"])
            except: pass

    cur.close(); conn.close()
    return {"session": session, "packets": packets, "alerts": alerts}


def get_session_packets(session_id, limit=500):
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT packet_number, protocol, src_ip, dst_ip, src_port, dst_port,
               packet_length, ttl, tcp_flags, is_anomaly, anomaly_score,
               packet_type, dns_query, http_method, flow_packet_count
        FROM packets WHERE session_id=%s ORDER BY packet_number ASC LIMIT %s
    """, (session_id, limit))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return rows


def get_threat_stats():
    """Aggregate threat stats across all sessions."""
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT alert_type, severity, COUNT(*) as count
        FROM threat_alerts
        GROUP BY alert_type, severity
        ORDER BY count DESC
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()
    return rows


def _si(val):
    try: return int(val) if val is not None and str(val) != "nan" else None
    except: return None

def _sf(val):
    try: return float(val) if val is not None and str(val) != "nan" else None
    except: return None
