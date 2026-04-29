# auth.py — NTDAP v4.0 User Authentication & Authorization Module
import os
import hashlib
import secrets
import json
from datetime import datetime, timedelta
from mysql.connector import Error
from .db import get_connection

# ── Session token store (in-memory; swap for Redis in prod) ───────
_active_tokens = {}   # token -> {user_id, expires_at}


def _hash_password(password: str, salt: str = None):
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return salt, hashed.hex()


def init_auth_db():
    """Create users table if not present."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INT AUTO_INCREMENT PRIMARY KEY,
                username      VARCHAR(80)  NOT NULL UNIQUE,
                email         VARCHAR(160) NOT NULL UNIQUE,
                password_hash VARCHAR(512) NOT NULL,
                salt          VARCHAR(64)  NOT NULL,
                role          ENUM('user','admin') DEFAULT 'user',
                created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login    DATETIME,
                is_active     TINYINT(1) DEFAULT 1,
                INDEX idx_email    (email),
                INDEX idx_username (username)
            )
        """)

        # Add user_id FK to capture_sessions so sessions are owned by users
        try:
            cur.execute("""
                ALTER TABLE capture_sessions
                ADD COLUMN user_id INT DEFAULT NULL,
                ADD INDEX idx_user_id (user_id)
            """)
        except Error:
            pass  # Column already exists

        # Add FK constraint (soft — ignore if already set)
        try:
            cur.execute("""
                ALTER TABLE capture_sessions
                ADD CONSTRAINT fk_session_user
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            """)
        except Error:
            pass

        conn.commit()

        # Seed default admin if none exists
        cur.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
        if cur.fetchone()[0] == 0:
            _create_user_internal(cur, "admin", "admin@ntdap.local", "admin123", "admin")
            conn.commit()
            print("✅ Default admin seeded  →  username: admin  password: admin123")

        print("✅ Auth DB initialized.")
    finally:
        cur.close()
        conn.close()


def _create_user_internal(cur, username, email, password, role="user"):
    salt, pw_hash = _hash_password(password)
    cur.execute(
        """INSERT INTO users (username, email, password_hash, salt, role)
           VALUES (%s, %s, %s, %s, %s)""",
        (username, email, pw_hash, salt, role)
    )
    return cur.lastrowid


# ── Public API ─────────────────────────────────────────────────────

def register_user(username: str, email: str, password: str):
    """Returns (user_dict, None) or (None, error_str)."""
    if len(password) < 6:
        return None, "Password must be at least 6 characters."
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT id FROM users WHERE username=%s OR email=%s", (username, email))
        if cur.fetchone():
            return None, "Username or email already in use."
        salt, pw_hash = _hash_password(password)
        cur.execute(
            """INSERT INTO users (username, email, password_hash, salt, role)
               VALUES (%s, %s, %s, %s, 'user')""",
            (username, email, pw_hash, salt)
        )
        user_id = cur.lastrowid
        conn.commit()
        return {"id": user_id, "username": username, "email": email, "role": "user"}, None
    except Error as e:
        conn.rollback()
        return None, str(e)
    finally:
        cur.close()
        conn.close()


def login_user(username_or_email: str, password: str):
    """Returns (token, user_dict) or (None, error_str)."""
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute(
            "SELECT * FROM users WHERE (username=%s OR email=%s) AND is_active=1",
            (username_or_email, username_or_email)
        )
        user = cur.fetchone()
        if not user:
            return None, "Invalid credentials."
        _, expected_hash = _hash_password(password, user["salt"])
        if expected_hash != user["password_hash"]:
            return None, "Invalid credentials."

        # Update last_login
        cur.execute("UPDATE users SET last_login=NOW() WHERE id=%s", (user["id"],))
        conn.commit()

        token = secrets.token_urlsafe(32)
        _active_tokens[token] = {
            "user_id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "expires_at": datetime.utcnow() + timedelta(hours=12),
        }
        public_user = {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "last_login": str(user["last_login"]) if user["last_login"] else None,
            "created_at": str(user["created_at"]),
        }
        return token, public_user
    finally:
        cur.close()
        conn.close()


def logout_user(token: str):
    _active_tokens.pop(token, None)
    return True


def get_current_user(token: str):
    """Returns user info dict or None if token invalid/expired."""
    info = _active_tokens.get(token)
    if not info:
        return None
    if datetime.utcnow() > info["expires_at"]:
        _active_tokens.pop(token, None)
        return None
    return info


def require_auth(token: str):
    """Raise ValueError if token invalid; else return user info."""
    user = get_current_user(token)
    if not user:
        raise ValueError("Unauthorized — please log in.")
    return user


def require_admin(token: str):
    user = require_auth(token)
    if user["role"] != "admin":
        raise ValueError("Forbidden — admin only.")
    return user


# ── User-scoped session queries ────────────────────────────────────

def get_user_sessions(user_id: int):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT id, filename, uploaded_at, total_packets, total_bytes,
               most_common_protocol, anomaly_count, anomaly_percentage,
               severity, severity_score,
               port_scan_detected, syn_flood_detected,
               beaconing_detected, dns_tunnel_detected
        FROM capture_sessions
        WHERE user_id=%s
        ORDER BY uploaded_at DESC
    """, (user_id,))
    rows = cur.fetchall()
    cur.close(); conn.close()
    for r in rows:
        if r.get("uploaded_at"):
            r["uploaded_at"] = str(r["uploaded_at"])
    return rows


def get_all_users_admin():
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT u.id, u.username, u.email, u.role, u.created_at, u.last_login, u.is_active,
               COUNT(cs.id) AS session_count,
               SUM(cs.total_packets) AS total_packets_analyzed
        FROM users u
        LEFT JOIN capture_sessions cs ON cs.user_id = u.id
        GROUP BY u.id
        ORDER BY u.created_at DESC
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()
    for r in rows:
        r["created_at"] = str(r["created_at"]) if r.get("created_at") else None
        r["last_login"]  = str(r["last_login"])  if r.get("last_login")  else None
    return rows


def get_all_sessions_admin():
    """All sessions with username attached."""
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT cs.id, cs.filename, cs.uploaded_at, cs.total_packets, cs.total_bytes,
               cs.most_common_protocol, cs.anomaly_count, cs.anomaly_percentage,
               cs.severity, cs.severity_score,
               cs.port_scan_detected, cs.syn_flood_detected,
               cs.beaconing_detected, cs.dns_tunnel_detected,
               u.username, u.email
        FROM capture_sessions cs
        LEFT JOIN users u ON u.id = cs.user_id
        ORDER BY cs.uploaded_at DESC
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()
    for r in rows:
        if r.get("uploaded_at"):
            r["uploaded_at"] = str(r["uploaded_at"])
    return rows


def toggle_user_active(target_user_id: int, active: bool):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_active=%s WHERE id=%s", (1 if active else 0, target_user_id))
    conn.commit()
    cur.close(); conn.close()


def get_user_profile(user_id: int):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT id, username, email, role, created_at, last_login
        FROM users WHERE id=%s
    """, (user_id,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if row:
        row["created_at"] = str(row["created_at"]) if row.get("created_at") else None
        row["last_login"]  = str(row["last_login"])  if row.get("last_login")  else None
    return row
