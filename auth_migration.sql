-- NTDAP v4.0 — Auth Migration SQL
-- Run this ONLY if you're upgrading from v4 (existing DB).
-- If starting fresh, init_auth_db() handles everything automatically.

USE ntdap_db;

-- Users table
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
);

-- Add user_id to capture_sessions (nullable = legacy sessions kept)
ALTER TABLE capture_sessions
    ADD COLUMN IF NOT EXISTS user_id INT DEFAULT NULL,
    ADD INDEX IF NOT EXISTS idx_user_id (user_id);

ALTER TABLE capture_sessions
    ADD CONSTRAINT IF NOT EXISTS fk_session_user
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;

-- Seed default admin (password: admin123)
-- Replace with your own after first login!
INSERT IGNORE INTO users (username, email, password_hash, salt, role)
VALUES (
  'admin',
  'admin@ntdap.local',
  -- IMPORTANT: This is NOT a real hash. The Python auth module seeds automatically.
  -- Leave this block commented and let init_auth_db() seed the admin.
  '', '', 'admin'
);

-- Remove the placeholder row above (init_auth_db handles the real seeding)
DELETE FROM users WHERE username='admin' AND password_hash='';
