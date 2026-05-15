import sys
import threading
import webbrowser
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent))

import backend

# ══════════════════════════════════════════════════════════════════
#  APP INIT
# ══════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    threading.Timer(1.0, lambda: webbrowser.open("http://localhost:8080")).start()
    yield

app = FastAPI(
    title="PyGuard",
    description="Python Security Analyzer + Code RAG",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ══════════════════════════════════════════════════════════════════
#  REQUEST SCHEMAS
# ══════════════════════════════════════════════════════════════════

class AnalyzeRequest(BaseModel):
    code:     str
    filename: str           = "uploaded.py"
    title:    Optional[str] = None

class QueryRequest(BaseModel):
    question:      str
    code:          str           = ""
    db_session_id: Optional[int] = None

class RenameRequest(BaseModel):
    title: str

# ══════════════════════════════════════════════════════════════════
#  STATIC FILES
# ══════════════════════════════════════════════════════════════════

BASE_DIR = Path(__file__).parent

@app.get("/", include_in_schema=False)
@app.get("/index.html", include_in_schema=False)
def serve_index():
    path = BASE_DIR / "index.html"
    if not path.exists():
        raise HTTPException(status_code=404, detail="index.html not found")
    return FileResponse(path, media_type="text/html")

@app.get("/style.css", include_in_schema=False)
def serve_css():
    path = BASE_DIR / "style.css"
    if not path.exists():
        raise HTTPException(status_code=404, detail="style.css not found")
    return FileResponse(path, media_type="text/css")

# ══════════════════════════════════════════════════════════════════
#  API ROUTES
# ══════════════════════════════════════════════════════════════════

@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    try:
        title = (req.title or "").strip() or req.filename
        return backend.handle_analyze(req.code, req.filename, title)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/query")
def query(req: QueryRequest):
    try:
        return backend.handle_query(req.question, req.code, req.db_session_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/sessions")
def get_sessions():
    try:
        return backend.get_sessions_list()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/sessions/{session_id}")
def get_session(session_id: int):
    try:
        data = backend.load_session(session_id)
        if data is None:
            raise HTTPException(status_code=404, detail="Session not found")
        return {"session": data}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/sessions/{session_id}/rename")
def rename_session(session_id: int, req: RenameRequest):
    try:
        result = backend.rename_session(session_id, req.title.strip())
        if not result.get("ok"):
            raise HTTPException(status_code=400, detail=result.get("error", "Rename failed"))
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/sessions/{session_id}/delete")
def delete_session(session_id: int):
    try:
        return backend.delete_session_by_id(session_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))