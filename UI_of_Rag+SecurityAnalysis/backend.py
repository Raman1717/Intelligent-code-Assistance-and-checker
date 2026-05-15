"""
backend.py — PyGuard: Backend Logic
====================================
Security analysis and RAG Q&A are delegated to main.py.
Cache check added to handle_query() so identical questions
on the same code never hit the LLM twice.
"""

from main import run_security_analysis, CodeRAG
from db import (
    save_session, save_chat_message, save_chunks,
    get_all_sessions, load_session_by_id,
    update_session_title, delete_session,
    get_cached_response, save_cache,
    _hash,
)

# Per-session RAG store — keyed by db_session_id.
_rag_store: dict[int, CodeRAG] = {}


# ══════════════════════════════════════════════════════════════════
#  PUBLIC API 
# ══════════════════════════════════════════════════════════════════

def handle_analyze(code: str, filename: str, title: str) -> dict:
    """
    Run security analysis then build a per-session RAG index.
    Returns the run_security_analysis() result dict extended with '_db_session_id'.
    """
    result        = run_security_analysis(code, filename)
    db_session_id = save_session(result, code, title=title)

    if db_session_id:
        print(f"[DB] Analysis saved → session_id={db_session_id}, title='{title}'")

    if db_session_id:
        try:
            rag = CodeRAG()
            if rag.load_code(code, filename):
                _rag_store[db_session_id] = rag
                print(f"✓ RAG index built for session {db_session_id}.")

                if hasattr(rag, 'metadata'):
                    save_chunks(db_session_id, rag.metadata)
            else:
                print(f"⚠  CodeRAG.load_code() returned False for session {db_session_id}.")

        except Exception as e:
            print(f"⚠  RAG indexing failed for session {db_session_id}: {e}")

    result['_db_session_id'] = db_session_id
    return result


def handle_query(question: str, code: str, db_session_id) -> dict:
    """
    Answer a natural-language question about code.
    Flow:
      1. Resolve code — fetch from DB if not supplied, so hash is always consistent
      2. Check analysis_cache — return immediately on hit, skip RAG entirely
      3. Run RAG / LLM
      4. Save answer to cache + save exchange to chat_messages
    """
    sid = int(db_session_id) if db_session_id else None
    
    # ── Step 1: resolve code so hash is always consistent ─────────
    resolved_code = code

    if not resolved_code and sid:
        session_data = load_session_by_id(sid)
        if session_data:
            resolved_code = session_data.get("code", "")
            print(f"[backend] Resolved code from DB for session {sid}")

    # ── Step 2: cache check ───────────────────────────────────────
    if resolved_code:
        code_hash  = _hash(resolved_code)
        query_hash = _hash(question)

        cached_answer = get_cached_response(code_hash, query_hash)
        if cached_answer:
            print(f"[backend] ✅ Cache HIT — skipping RAG for session {sid}")

            if sid:
                try:
                    save_chat_message(sid, "user", question)
                    save_chat_message(
                        sid, "assistant", cached_answer,
                        metadata={"cached": True}
                    )
                except Exception as e:
                    print(f"[DB] ⚠  chat save failed (cached path): {e}")

            return {"answer": cached_answer, "cached": True, "success": True}
    else:
        code_hash  = None
        query_hash = None

    # ── Step 3: run RAG ───────────────────────────────────────────
    result: dict

    if sid and sid in _rag_store:
        result = _rag_store[sid].query(question)

    elif resolved_code:
        print(f"[backend] No RAG index for session {sid} — rebuilding from code.")
        rag = CodeRAG()
        if rag.load_code(resolved_code, 'uploaded.py'):
            if sid:
                _rag_store[sid] = rag
            result = rag.query(question)
        else:
            result = {"success": False, "error": "CodeRAG.load_code() failed."}

    else:
        result = {"success": False, "error": "No code indexed for this session. Run an analysis first."}

    # ── Step 4: save to cache + chat ──────────────────────────────
    answer = result.get("answer") or result.get("error", "")

    if code_hash and query_hash and result.get("success", True) and answer:
        try:
            save_cache(code_hash, query_hash, question, answer)
        except Exception as e:
            print(f"[DB] ⚠  cache save failed: {e}")

    if sid:
        try:
            save_chat_message(sid, "user", question)
            meta = {
                "query_type":     result.get("query_type"),
                "chunks_used":    result.get("chunks_used"),
                "retrieval_time": result.get("retrieval_time"),
                "classification": result.get("classification"),
                "cached":         False,
            }
            save_chat_message(sid, "assistant", answer, metadata=meta)
        except Exception as e:
            print(f"[DB] ⚠  chat save failed: {e}")

    return result


# ── Session helpers ───────────────────────────────────────────────

def get_sessions_list() -> dict:
    """Return all sessions from DB."""
    rows = get_all_sessions()
    for r in rows:
        if hasattr(r.get('created_at'), 'isoformat'):
            r['created_at'] = r['created_at'].isoformat()
    return {"sessions": rows, "db": True}


def load_session(session_id: int) -> "dict | None":
    """Load a single session by DB id. Returns None if not found."""
    data = load_session_by_id(session_id)
    if data is None:
        return None
    if hasattr(data.get('created_at'), 'isoformat'):
        data['created_at'] = data['created_at'].isoformat()
    return data


def rename_session(session_id: int, new_title: str) -> dict:
    """Rename a session in the DB. Returns {ok, error?}."""
    if not new_title:
        return {"ok": False, "error": "Title cannot be empty"}
    ok = update_session_title(session_id, new_title)
    return {"ok": ok}


def delete_session_by_id(session_id: int) -> dict:
    """Delete a session from DB and clear its RAG index from memory."""
    _rag_store.pop(session_id, None)
    ok = delete_session(session_id)
    return {"ok": ok}