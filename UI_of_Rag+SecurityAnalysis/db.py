"""
db.py — MySQL Database Helper
==============================
Connects your app to MySQL.
Install: pip install mysql-connector-python

Set these in a .env file or as environment variables:
    DB_HOST=localhost
    DB_PORT=3306
    DB_USER=root
    DB_PASSWORD=yourpassword
    DB_NAME=code_analyzer
"""

import os
import json
import hashlib
import mysql.connector
from mysql.connector import Error
from typing import Optional

# ── Connection config ─────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("DB_HOST",     "localhost"),
    "port":     int(os.getenv("DB_PORT", "3306")),
    "user":     os.getenv("DB_USER",     "root"),
    "password": os.getenv("DB_PASSWORD", ".............."),
    "database": os.getenv("DB_NAME",     "code_analyzer"),
}

def _get_conn():
    """Return a fresh MySQL connection."""
    return mysql.connector.connect(**DB_CONFIG)


def _hash(text: str) -> str:
    """Return a SHA-256 hex digest (64 chars) for any string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ═════════════════════════════════════════════════════════════════
#  1. SAVE SESSION + FINDINGS
# ═════════════════════════════════════════════════════════════════

def save_session(result: dict, code: str, title: str = "") -> Optional[int]:
    """
    Insert one analysis session and all its security findings.
    Every upload always creates a brand-new session — no duplicate checking.
    Returns the new session_id (int) or None on failure.
    """
    con = None
    try:
        con = _get_conn()
        cur = con.cursor()

        session_title = title or result.get("filename", "Untitled")
        code_hash     = _hash(code)  # stored for cache lookups, no uniqueness enforced

        cur.execute("""
            INSERT INTO sessions
                (filename, title, code, code_hash, syntax_valid,
                 high_count, medium_count, total_issues)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            result.get("filename", "input.py"),
            session_title,
            code,
            code_hash,
            1 if result.get("syntax_valid", True) else 0,
            result.get("high_count",   0),
            result.get("medium_count", 0),
            result.get("total_issues", 0),
        ))
        session_id = cur.lastrowid

        for issue in result.get("final_issues", []):
            cur.execute("""
                INSERT INTO security_findings
                    (session_id, severity, rule, line_number, message, suggestion)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                session_id,
                issue.get("severity", "MEDIUM"),
                issue.get("rule"),
                issue.get("line"),
                issue.get("message"),
                issue.get("suggestion"),
            ))

        con.commit()
        print(f"[DB] ✅ Session saved — id={session_id}, title='{session_title}'")
        return session_id

    except Error as e:
        print(f"[DB] ❌ save_session error: {e}")
        if con:
            con.rollback()
        return None
    finally:
        if con and con.is_connected():
            cur.close()
            con.close()


# ═════════════════════════════════════════════════════════════════
#  1b. UPDATE SESSION TITLE
# ═════════════════════════════════════════════════════════════════

def update_session_title(session_id: int, new_title: str) -> bool:
    """
    Update the title of an existing session.
    Returns True on success, False on failure.
    """
    con = None
    try:
        con = _get_conn()
        cur = con.cursor()
        cur.execute(
            "UPDATE sessions SET title = %s WHERE id = %s",
            (new_title.strip(), session_id)
        )
        con.commit()
        affected = cur.rowcount
        if affected:
            print(f"[DB] ✅ Session {session_id} renamed to '{new_title}'")
        else:
            print(f"[DB] ⚠️  Session {session_id} not found for rename")
        return affected > 0

    except Error as e:
        print(f"[DB] ❌ update_session_title error: {e}")
        if con:
            con.rollback()
        return False
    finally:
        if con and con.is_connected():
            cur.close()
            con.close()


# ═════════════════════════════════════════════════════════════════
#  1c. DELETE SESSION
# ═════════════════════════════════════════════════════════════════

def delete_session(session_id: int) -> bool:
    """
    Permanently delete a session and all its related data.
    CASCADE on FK relationships handles child rows automatically.
    Returns True on success, False on failure.
    """
    con = None
    try:
        con = _get_conn()
        cur = con.cursor()
        cur.execute("DELETE FROM sessions WHERE id = %s", (session_id,))
        con.commit()
        affected = cur.rowcount
        if affected:
            print(f"[DB] ✅ Session {session_id} deleted (cascade removed findings, messages, chunks)")
        else:
            print(f"[DB] ⚠️  Session {session_id} not found for deletion")
        return affected > 0

    except Error as e:
        print(f"[DB] ❌ delete_session error: {e}")
        if con:
            con.rollback()
        return False
    finally:
        if con and con.is_connected():
            cur.close()
            con.close()


# ═════════════════════════════════════════════════════════════════
#  2. SAVE CHAT MESSAGE
# ═════════════════════════════════════════════════════════════════

def save_chat_message(
    session_id: int,
    role: str,
    content: str,
    metadata: dict = None
) -> None:
    """
    Save a single chat message (user or assistant) to the database.
    """
    con = None
    try:
        con = _get_conn()
        cur = con.cursor()

        query_hash: Optional[str] = None
        if role == "user" and content:
            query_hash = _hash(content)

        retrieved_chunks: Optional[str] = None
        if metadata:
            retrieved_chunks = json.dumps(metadata)

        cur.execute("""
            INSERT INTO chat_messages
                (session_id, role, content, query_hash, retrieved_chunks)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            session_id,
            role,
            content,
            query_hash,
            retrieved_chunks,
        ))
        con.commit()

    except Error as e:
        print(f"[DB] ❌ save_chat_message error: {e}")
        if con:
            con.rollback()
    finally:
        if con and con.is_connected():
            cur.close()
            con.close()


# ═════════════════════════════════════════════════════════════════
#  3. SAVE RAG CHUNKS
# ═════════════════════════════════════════════════════════════════

def save_chunks(session_id: int, rag_metadata: list) -> None:
    """
    Save all RAG chunk texts for a session.
    """
    if not session_id or not rag_metadata:
        return
    con = None
    try:
        con = _get_conn()
        cur = con.cursor()

        rows = []
        for idx, m in enumerate(rag_metadata):
            rows.append((
                session_id,
                m.get("chunk_index", idx),
                m.get("content", ""),
                m.get("start_line"),
                m.get("end_line"),
                m.get("embedding_id"),
            ))

        cur.executemany("""
            INSERT INTO code_chunks
                (session_id, chunk_index, chunk_text,
                 start_line, end_line, embedding_id)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, rows)

        con.commit()
        print(f"[DB] ✅ {len(rows)} chunks saved for session_id={session_id}")

    except Error as e:
        print(f"[DB] ❌ save_chunks error: {e}")
        if con:
            con.rollback()
    finally:
        if con and con.is_connected():
            cur.close()
            con.close()


# ═════════════════════════════════════════════════════════════════
#  4. GET ALL PAST SESSIONS
# ═════════════════════════════════════════════════════════════════

def get_all_sessions() -> list:
    """
    Return all past sessions ordered by newest first.
    """
    con = None
    try:
        con = _get_conn()
        cur = con.cursor(dictionary=True)
        cur.execute("""
            SELECT id, filename, title, high_count, medium_count,
                   total_issues, created_at
            FROM sessions
            ORDER BY created_at DESC
            LIMIT 50
        """)
        return cur.fetchall()

    except Error as e:
        print(f"[DB] ❌ get_all_sessions error: {e}")
        return []
    finally:
        if con and con.is_connected():
            cur.close()
            con.close()


# ═════════════════════════════════════════════════════════════════
#  5. LOAD FULL SESSION BY ID
# ═════════════════════════════════════════════════════════════════

def load_session_by_id(session_id: int) -> Optional[dict]:
    """
    Fetch everything stored for a session.
    """
    con = None
    try:
        con = _get_conn()
        cur = con.cursor(dictionary=True)

        cur.execute("""
            SELECT id, filename, title, code, syntax_valid,
                   high_count, medium_count, total_issues, created_at
            FROM sessions
            WHERE id = %s
        """, (session_id,))
        session = cur.fetchone()
        if not session:
            return None

        cur.execute("""
            SELECT severity, rule, line_number AS line,
                   message, suggestion
            FROM security_findings
            WHERE session_id = %s
            ORDER BY id
        """, (session_id,))
        findings = cur.fetchall()

        security_report = {
            "filename":     session["filename"],
            "syntax_valid": bool(session["syntax_valid"]),
            "syntax_error": None,
            "high_count":   session["high_count"],
            "medium_count": session["medium_count"],
            "total_issues": session["total_issues"],
            "final_issues": [
                {
                    "severity":   f["severity"],
                    "rule":       f["rule"],
                    "line":       f["line"],
                    "message":    f["message"],
                    "suggestion": f["suggestion"],
                }
                for f in findings
            ],
            "metrics": {},
        }

        cur.execute("""
            SELECT role, content, retrieved_chunks
            FROM chat_messages
            WHERE session_id = %s
            ORDER BY id
        """, (session_id,))
        rows = cur.fetchall()

        chat_history = []
        for row in rows:
            meta = {}
            if row["retrieved_chunks"]:
                try:
                    meta = json.loads(row["retrieved_chunks"])
                except Exception:
                    meta = {}
            chat_history.append({
                "role":     row["role"],
                "content":  row["content"],
                "metadata": meta,
            })

        return {
            "session_id":      session["id"],
            "filename":        session["filename"],
            "title":           session["title"] or session["filename"],
            "code":            session["code"],
            "syntax_valid":    bool(session["syntax_valid"]),
            "high_count":      session["high_count"],
            "medium_count":    session["medium_count"],
            "total_issues":    session["total_issues"],
            "created_at":      session["created_at"],
            "security_report": security_report,
            "chat_history":    chat_history,
        }

    except Error as e:
        print(f"[DB] ❌ load_session_by_id error: {e}")
        return None
    finally:
        if con and con.is_connected():
            cur.close()
            con.close()


# ═════════════════════════════════════════════════════════════════
#  6. ANALYSIS CACHE — GET
# ═════════════════════════════════════════════════════════════════

def get_cached_response(code_hash: str, query_hash: str) -> Optional[str]:
    """
    Return cached LLM response if same code + same question was asked before.
    Returns the response string, or None if not found.
    """
    con = None
    try:
        con = _get_conn()
        cur = con.cursor(dictionary=True)
        cur.execute("""
            SELECT response FROM analysis_cache
            WHERE code_hash = %s AND query_hash = %s
            ORDER BY created_at DESC
            LIMIT 1
        """, (code_hash, query_hash))
        row = cur.fetchone()
        if row:
            print(f"[DB] ✅ Cache HIT — code_hash={code_hash[:8]}… query_hash={query_hash[:8]}…")
            return row["response"]
        return None

    except Error as e:
        print(f"[DB] ❌ get_cached_response error: {e}")
        return None
    finally:
        if con and con.is_connected():
            cur.close()
            con.close()


# ═════════════════════════════════════════════════════════════════
#  7. ANALYSIS CACHE — SAVE
# ═════════════════════════════════════════════════════════════════

def save_cache(code_hash: str, query_hash: str, query: str, response: str) -> None:
    """
    Save an LLM response to cache so identical queries skip RAG next time.
    """
    con = None
    try:
        con = _get_conn()
        cur = con.cursor()
        cur.execute("""
            INSERT INTO analysis_cache
                (code_hash, query_hash, query, response)
            VALUES (%s, %s, %s, %s)
        """, (code_hash, query_hash, query, response))
        con.commit()
        print(f"[DB] ✅ Cache SAVED — code_hash={code_hash[:8]}… query_hash={query_hash[:8]}…")

    except Error as e:
        print(f"[DB] ❌ save_cache error: {e}")
        if con:
            con.rollback()
    finally:
        if con and con.is_connected():
            cur.close()
            con.close()