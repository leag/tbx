# Web UI: decomp.me-style editor for tbx

Status: approved
Date: 2026-08-04

## Purpose

Give a local, browser-based workflow for testing decoder changes: upload a
compiled Turbo Basic EXE, see the source `tbx` recovers, edit that source,
recompile it through the vendored oracle, and see how close the recompiled
bytes come to the original. Modeled on decomp.me's edit/rebuild/diff loop.

## Scope

Local-only tool. It assumes the user has already provisioned the oracle's
compiler assets per `vendor/turbo_basic_oracle/README.tbx.md` and set
`TBX_ORACLE`. It is not a hosted/shared service, has no auth, and does not
attempt to solve the licensing question of distributing Borland's compiler.

Out of scope for this iteration:
- Multi-file (`--split`) source editing.
- An op-stream / IR debug panel.
- Persistence beyond a single browser session's temp files.

## Architecture

Two new, independent pieces. Neither touches `tbx.decode0`, `tbx.ir`, or
`tbx.emit0`, which stay dependency-free per the project's core design.

- `tbx/web/` — a FastAPI app added under a new optional dependency group
  `tbx[web]` (alongside the existing `debug` extra: `iced-x86`). Depends on
  `fastapi`, `uvicorn`, and `python-multipart` (for file upload parsing).
  Imports `tbx.decode0`, `tbx.emit0`, and `tbx.tools.oracle`.
- `webui/frontend/` — a React + Vite single-page app. Built to static assets
  (`webui/frontend/dist/`) that the FastAPI app mounts and serves; no
  server-side rendering.

## API

### `POST /api/decompile`

Multipart EXE upload (field name `exe`).

- Server writes the upload to a fresh per-session temp directory
  (`tempfile.mkdtemp()`, keyed by a UUID) and keeps the original bytes there
  for the later recompile step.
- Runs `decode0.decode_user_code(exe)` then `emit0` to produce source.
- Success (200): `{"session_id": str, "dialect": str, "source": str}`.
- Decode failure (422): `{"error": str}` where `error` is the
  `DecodeDiagnostics` report text (phase/offset/op/statement/recent), the
  same text the CLI prints — not a generic traceback.

### `POST /api/recompile`

JSON body `{"session_id": str, "source": str}`.

- Looks up the session's original EXE bytes and the dialect detected during
  `/api/decompile`.
- Calls `oracle.preflight()` first; if the oracle isn't configured, returns
  (503) `{"error": str}` pointing at
  `vendor/turbo_basic_oracle/README.tbx.md`.
- Calls `oracle.compile_bas(source, dialect=dialect)` with the edited
  source. If the Turbo Basic compiler rejects it, returns (422)
  `{"error": str}` with the compiler's own error output.
- On successful compile, diffs the recompiled bytes against the original:
  `difflib.SequenceMatcher(None, original, recompiled).ratio()` for a single
  normalized similarity metric (0.0-1.0), plus the offset of the first byte
  where the two sequences diverge (for context, not a full diff view).
- Success (200):
  `{"matched": bool, "ratio": float, "first_diff_offset": int | null, "original_len": int, "recompiled_len": int}`.
  `matched` is `true` iff the byte sequences are identical (`ratio == 1.0`);
  `first_diff_offset` is `null` when `matched` is `true`.

No database, no auth. Session temp directories are not explicitly cleaned up
by the server — this is a local dev tool, matching the throwaway-workspace
pattern already used by `batch_probe.py` and `oracle.compile_bas`.

## Frontend

Single page:

1. File drop/upload zone.
2. On successful decompile, a CodeMirror editor pre-filled with the
   recovered source.
3. A "Recompile" button that POSTs the current editor contents to
   `/api/recompile`.
4. A result panel showing: match ratio as a percentage, first-diff byte
   offset (if not matched), and the verbatim error text for any decode or
   compile failure.

## Error handling

Every user-facing failure path — decode raise, missing/misconfigured oracle,
compiler rejection of edited source — surfaces the underlying diagnostic
text verbatim in the UI, consistent with the project's fail-loud philosophy.
Nothing is swallowed into a generic "something went wrong."

## Testing

- `tests/tbx/test_web.py` using FastAPI's `TestClient`:
  - `/api/decompile` happy path against an existing corpus fixture EXE
    (e.g. `tests/fixtures/corpus/f87_t1_beep.exe`).
  - `/api/decompile` error path with garbage bytes, asserting the
    diagnostics text is present in the response.
  - `/api/recompile` happy-path and compiler-error-path tests are skipped
    when `oracle.preflight()` raises (no local compiler assets), following
    the project's existing pattern for oracle-dependent tests.
- Frontend: a minimal smoke test (renders, upload triggers the expected
  `fetch` call) — no exhaustive UI test suite, per YAGNI.
