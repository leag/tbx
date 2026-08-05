"""FastAPI app for the tbx web UI: decompile/recompile/diff over HTTP.

Local dev tool only -- see docs/superpowers/specs/2026-08-04-web-ui-design.md.
"""

from __future__ import annotations

import difflib
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.requests import Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from tbx import decode0, emit0
from tbx.tools import oracle
from tbx.web.ir_json import program_to_json
from tbx.web.sessions import SessionStore

app = FastAPI(title="tbx web UI")
_store = SessionStore()


@app.exception_handler(HTTPException)
async def _error_body(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


@app.post("/api/decompile")
async def decompile(exe: UploadFile = File(...)) -> dict:
    exe_bytes = await exe.read()
    try:
        stmts = decode0.decode_user_code(exe_bytes)
        _, dialect = decode0.find_prologue(exe_bytes)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    source = emit0.emit(stmts)
    session = _store.create(exe_bytes, dialect=dialect.name)
    return {
        "session_id": session.id,
        "dialect": session.dialect,
        "source": source,
        "ir": program_to_json(stmts),
    }


class RecompileRequest(BaseModel):
    session_id: str
    source: str


@app.post("/api/recompile")
def recompile(req: RecompileRequest) -> dict:
    try:
        session = _store.get(req.session_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=f"unknown session {req.session_id!r}") from e

    try:
        oracle.preflight()
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e

    with tempfile.TemporaryDirectory(prefix="tbx-web-recompile-") as workspace:
        bas_path = Path(workspace) / "EDITED.BAS"
        bas_path.write_text(req.source, encoding="latin-1", newline="")
        try:
            recompiled = oracle.compile_bas(bas_path, dialect=session.dialect)
        except RuntimeError as e:
            raise HTTPException(status_code=422, detail=str(e)) from e

    original = session.exe_path.read_bytes()
    ratio = difflib.SequenceMatcher(None, original, recompiled).ratio()
    matched = ratio == 1.0
    first_diff_offset = None
    if not matched:
        for i, (a, b) in enumerate(zip(original, recompiled)):
            if a != b:
                first_diff_offset = i
                break
        else:
            first_diff_offset = min(len(original), len(recompiled))

    return {
        "matched": matched,
        "ratio": ratio,
        "first_diff_offset": first_diff_offset,
        "original_len": len(original),
        "recompiled_len": len(recompiled),
    }


# Mount the built frontend, if present
_dist = Path(__file__).resolve().parent.parent.parent / "webui" / "frontend" / "dist"
if _dist.is_dir():
    app.mount("/", StaticFiles(directory=_dist, html=True), name="frontend")
