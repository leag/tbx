"""FastAPI app for the tbx web UI: decompile/recompile/diff over HTTP.

Local dev tool only -- see docs/superpowers/specs/2026-08-04-web-ui-design.md.
"""

from __future__ import annotations

import base64
import difflib
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.requests import Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from tbx import decode0, emit0
from tbx.decode0.const import _TOGGLE_BITS, _TOGGLE_NAMES
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

        line_starts: list[int] = []
        source = emit0.emit(stmts, line_starts=line_starts)
        toggles = getattr(stmts, "toggles", "")
        session = _store.create(exe_bytes, dialect=dialect.name, toggles=toggles)
        # One entry per top-level statement (same order as `ir`): the byte
        # offset in the ORIGINAL exe that statement decoded from, or null
        # for a codeless statement (e.g. a synthesized `Do`). Lets the UI
        # highlight where a source line came from in the original binary;
        # there is no equivalent mapping into the recompiled bytes since
        # the real compiler is an opaque black box.
        control_graph = getattr(stmts, "control_graph", None)
        addresses = [n.address for n in control_graph.nodes] if control_graph else None
        return {
            "session_id": session.id,
            "dialect": session.dialect,
            "toggles": session.toggles,
            "source": source,
            "ir": program_to_json(stmts),
            "addresses": addresses,
            # One entry per top-level statement, same order/length as
            # `addresses`: the 0-based line index into `source` that
            # statement's text starts at. Statements grouped onto one
            # physical line (e.g. "10 A=1:B=2") share a value; a statement
            # that renders as a multi-line block (IF/END IF, SUB/END SUB)
            # is anchored to its first line. This is the authoritative
            # address<->line mapping -- do not re-derive it in the UI by
            # counting numbered lines, which breaks whenever a top-level
            # statement doesn't emit exactly one numbered line (tbd73.exe).
            "line_starts": line_starts,
        }
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}") from e


@app.get("/api/dialects")
def dialects() -> dict:
    return {"dialects": list(oracle.DIALECTS)}


#: The IDE Options-menu toggle letters compile_bas's `toggles` accepts, in
#: their canonical order, paired with their human-readable names.
_TOGGLE_LETTERS = tuple(letter for _bit, letter in _TOGGLE_BITS)


@app.get("/api/toggles")
def toggles() -> dict:
    return {
        "toggles": [
            {"letter": letter, "name": _TOGGLE_NAMES[letter]} for letter in _TOGGLE_LETTERS
        ]
    }


def _disassemble_exe(exe_bytes: bytes) -> dict:
    try:
        from tbx.tools import insns
    except ImportError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e

    # Code-only: decode_flow only ever decodes bytes an actual control-flow
    # edge leads to, starting from `start` -- the single-entry scan decode0
    # itself did (`ops`) is used for its op boundaries (see below), not to
    # bound how far in the file decode_flow may follow a real edge. A far
    # jmp/call can legitimately target code past where that single-entry
    # scan reached (that's the point of following it), so the upper bound
    # is the whole file: nothing points into real trailing data, so a
    # generous bound costs nothing, it's just never visited.
    start, _dialect = decode0.find_prologue(exe_bytes)
    ops = decode0._scan(exe_bytes, start, _dialect, set())
    end = len(exe_bytes)
    # decode0's own recognized op boundaries: some runtime dispatches (an
    # `int` selecting a DIM-array descriptor) are followed by inline
    # argument bytes the interrupt handler consumes at runtime, not further
    # code -- decode_flow uses these to know where such a run really ends,
    # instead of decoding into the argument bytes as bogus instructions.
    op_starts = [op[0] for op in ops]
    lines = insns.decode_flow(exe_bytes, start, end, op_starts=op_starts)
    return {
        "instructions": [
            {"address": addr, "text": text, "target": target} for addr, _kind, text, target in lines
        ]
    }


class DisassemblyRequest(BaseModel):
    session_id: str


@app.post("/api/disassembly")
def disassembly(req: DisassemblyRequest) -> dict:
    try:
        session = _store.get(req.session_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=f"unknown session {req.session_id!r}") from e

    return _disassemble_exe(session.exe_path.read_bytes())


class DisassembleBytesRequest(BaseModel):
    data_b64: str


@app.post("/api/disassemble_bytes")
def disassemble_bytes(req: DisassembleBytesRequest) -> dict:
    # Stateless counterpart to /api/disassembly: the recompiled binary only
    # ever exists as bytes already sent to the client (recompile() doesn't
    # persist it server-side), so disassembling it takes the bytes directly
    # rather than a session id.
    try:
        exe_bytes = base64.b64decode(req.data_b64, validate=True)
    except (ValueError, base64.binascii.Error) as e:
        raise HTTPException(status_code=422, detail=f"invalid base64: {e}") from e

    try:
        return _disassemble_exe(exe_bytes)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"could not locate a code region: {e}") from e


class RecompileRequest(BaseModel):
    session_id: str
    source: str
    dialect: str | None = None
    toggles: str | None = None


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

    dialect = req.dialect or session.dialect
    if dialect not in oracle.DIALECTS:
        raise HTTPException(
            status_code=422,
            detail=f"unknown dialect {dialect!r}; expected one of {sorted(oracle.DIALECTS)}",
        )

    # An explicit "" means "no toggles", distinct from "not provided" (use
    # the session's auto-detected toggles) -- `or` would conflate the two.
    toggles_ = session.toggles if req.toggles is None else req.toggles
    if not set(toggles_) <= set(_TOGGLE_LETTERS):
        raise HTTPException(
            status_code=422,
            detail=f"unknown toggle letters in {toggles_!r}; expected any of {_TOGGLE_LETTERS}",
        )

    with tempfile.TemporaryDirectory(prefix="tbx-web-recompile-") as workspace:
        bas_path = Path(workspace) / "EDITED.BAS"
        try:
            # Turbo Basic's editor can't load a source file over ~64KB at
            # all (a real compiler-era limit, not a tbx one -- it's what
            # produces the "too large. Truncate?" dialog the oracle harness
            # detects). split_source sidesteps it the same way the
            # compiler's own $INCLUDE does for a procedure-free program:
            # break the text into <=32KB chunks the root just $INCLUDEs.
            # A program with SUB/block DEF FN declarations can't be split
            # this way -- Turbo Basic itself rejects $INCLUDE alongside
            # those -- and split_source raises ValueError to say so; below
            # ~64KB it returns the source unchanged, so this is always safe
            # to run.
            bundle = emit0.split_source(req.source)
        except ValueError as e:
            raise HTTPException(
                status_code=422,
                detail=f"source cannot be compiled: {e}",
            ) from e
        try:
            bas_path.write_text(bundle.root, encoding="latin-1", newline="")
            for name, text in bundle.includes:
                (Path(workspace) / name).write_text(text, encoding="latin-1", newline="")
        except UnicodeEncodeError as e:
            raise HTTPException(
                status_code=422,
                detail=f"edited source contains a character that cannot be encoded: {e}",
            ) from e
        # The fast (snapshot-restore) path is ~2x quicker than rebooting the
        # oracle from scratch every call; prime it once per (dialect,
        # toggles) pair on first use -- see oracle.compile_bas's docstring.
        if not oracle.has_snapshot(dialect, toggles_):
            try:
                oracle.prime_snapshot(dialect, toggles_)
            except RuntimeError as e:
                raise HTTPException(status_code=503, detail=str(e)) from e
        try:
            recompiled = oracle.compile_bas(bas_path, dialect=dialect, toggles=toggles_, fast=True)
        except RuntimeError as e:
            raise HTTPException(status_code=422, detail=str(e)) from e

    original = session.exe_path.read_bytes()
    ratio = difflib.SequenceMatcher(None, original, recompiled).ratio()
    matched = original == recompiled
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
        "original_b64": base64.b64encode(original).decode("ascii"),
        "recompiled_b64": base64.b64encode(recompiled).decode("ascii"),
    }


# Mount the built frontend, if present
_dist = Path(__file__).resolve().parent.parent.parent / "webui" / "frontend" / "dist"
if _dist.is_dir():
    app.mount("/", StaticFiles(directory=_dist, html=True), name="frontend")
