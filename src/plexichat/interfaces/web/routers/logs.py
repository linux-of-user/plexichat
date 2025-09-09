from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse, JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from typing import List, Optional
import re

router = APIRouter(prefix="/admin/logs", tags=["admin-logs"])
templates = Jinja2Templates(directory="src/plexichat/interfaces/web/templates")

LOG_DIR = Path("logs")
PLUGINS_DIR = LOG_DIR / "plugins"

LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

@router.get("/", response_class=HTMLResponse)
async def logs_ui(request: Request):
    return templates.TemplateResponse("admin/logs.html", {"request": request})


@router.get("/files", response_class=JSONResponse)
async def list_log_files() -> dict:
    try:
        files = []
        if LOG_DIR.exists():
            for p in LOG_DIR.glob("*.txt"):
                files.append({"name": p.name, "path": str(p)})
            for p in LOG_DIR.glob("*.log"):
                files.append({"name": p.name, "path": str(p)})
        if PLUGINS_DIR.exists():
            for plugin_dir in PLUGINS_DIR.iterdir():
                if plugin_dir.is_dir():
                    for p in plugin_dir.glob("*.log"):
                        files.append({"name": f"plugins/{plugin_dir.name}/{p.name}", "path": str(p)})
        return {"files": files}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not list logs: {e}")

@router.get("/view", response_class=PlainTextResponse)
async def view_log(file: str = Query(..., description="Relative log file name"),
                   level: Optional[str] = Query(None, description="Filter by level (DEBUG..CRITICAL)"),
                   tail_kb: int = Query(64, ge=1, le=8192, description="Tail size in kilobytes")) -> str:
    try:
        if not re.match(r"^[a-zA-Z0-9_./-]+$", file):
            raise HTTPException(status_code=400, detail="Invalid file name")
        target = LOG_DIR / file if not file.startswith("plugins/") else (LOG_DIR / file)
        try:
            root = LOG_DIR.resolve()
            resolved = target.resolve()
            if not str(resolved).startswith(str(root)):
                raise HTTPException(status_code=400, detail="Invalid log path")
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid log path")
        if not target.exists() or not target.is_file():
            raise HTTPException(status_code=404, detail="Log file not found")
        size = target.stat().st_size
        start = max(0, size - tail_kb * 1024)
        with open(target, "rb") as f:
            f.seek(start)
            data = f.read()
        text = data.decode('ascii', errors='replace')
        if level and level.upper() in LEVELS:
            lines = [ln for ln in text.splitlines() if f"[{level.upper():<8}]" in ln]
            return "\n".join(lines)
        return text
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not read log: {e}")
