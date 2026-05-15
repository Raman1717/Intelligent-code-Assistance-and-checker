-- =============================================================
-- DATABASE: Python Security & RAG Analyzer
-- =============================================================
CREATE DATABASE IF NOT EXISTS code_analyzer
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
USE code_analyzer;

-- =============================================================
-- 1. SESSIONS  (no UNIQUE on code_hash — every upload = new row)
-- =============================================================
CREATE TABLE IF NOT EXISTS sessions (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    filename     VARCHAR(512) NOT NULL,
    title        VARCHAR(120) NOT NULL DEFAULT '',
    code         MEDIUMTEXT NOT NULL,
    code_hash    VARCHAR(64) NOT NULL,   -- kept for reference only
    syntax_valid BOOLEAN DEFAULT TRUE,
    high_count   INT DEFAULT 0,
    medium_count INT DEFAULT 0,
    total_issues INT DEFAULT 0,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- =============================================================
-- 2. SECURITY FINDINGS
-- =============================================================
CREATE TABLE IF NOT EXISTS security_findings (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    session_id  INT NOT NULL,
    severity    ENUM('HIGH', 'MEDIUM') NOT NULL,
    rule        VARCHAR(128),
    line_number INT,
    message     TEXT,
    suggestion  TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- =============================================================
-- 3. CHAT MESSAGES
-- =============================================================
CREATE TABLE IF NOT EXISTS chat_messages (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    session_id       INT NOT NULL,
    role             ENUM('user', 'assistant') NOT NULL,
    content          MEDIUMTEXT,
    query_hash       VARCHAR(64),
    retrieved_chunks JSON,
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- =============================================================
-- 4. CODE CHUNKS  (no UNIQUE on chunk_index — each session is fresh)
-- =============================================================
CREATE TABLE IF NOT EXISTS code_chunks (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    session_id   INT NOT NULL,
    chunk_index  INT NOT NULL,
    chunk_text   TEXT,
    start_line   INT,
    end_line     INT,
    embedding_id VARCHAR(100),
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- =============================================================
-- 5. ANALYSIS CACHE (for RAG)
-- =============================================================
CREATE TABLE IF NOT EXISTS analysis_cache (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    code_hash   VARCHAR(64),
    query_hash  VARCHAR(64),
    query       TEXT,
    response    MEDIUMTEXT,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_cache_lookup (code_hash, query_hash)
) ENGINE=InnoDB;

-- =============================================================
-- INDEXES
-- =============================================================
CREATE INDEX idx_findings_session ON security_findings(session_id);
CREATE INDEX idx_chat_session     ON chat_messages(session_id);
CREATE INDEX idx_chunks_session   ON code_chunks(session_id);
CREATE INDEX idx_code_hash        ON sessions(code_hash);

-- =============================================================
-- IF DATABASE ALREADY EXISTS — drop the unique constraint only:
-- =============================================================
-- ALTER TABLE sessions DROP INDEX unique_code;
-- ALTER TABLE code_chunks DROP INDEX unique_chunk;
select * from sessions;
select * from sessions;