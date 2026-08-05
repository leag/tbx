"""FastAPI app for the tbx web UI: decompile/recompile/diff over HTTP.

Local dev tool only -- see docs/superpowers/specs/2026-08-04-web-ui-design.md.
"""

from __future__ import annotations

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.requests import Request
from fastapi.responses import JSONResponse

from tbx import decode0, emit0
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
