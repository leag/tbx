# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`tbx` is a byte-exact decompiler for 16-bit MS-DOS EXEs compiled by Borland Turbo Basic 1.0/1.1. The correctness standard is unusual: a recovery counts only if recompiling the emitted source in the original Borland toolchain reproduces the input EXE **byte-for-byte**. That standard drives every convention below.

## Commands

```sh
uv sync                       # install dev environment (pytest, ruff, ty, iced-x86)
uv run pytest                 # full suite (~131 tests, a few seconds)
uv run pytest tests/tbx/test_arrays.py                # one file
uv run pytest tests/tbx/test_arrays.py::test_name     # one test
uv run ruff check             # lint
uv run ty check               # type check
uv run tbx PROGRAM.EXE        # decompile (add --ops for the op-stream dump)
```

Regenerating golden fixtures after an **intended** decoder/emitter change:

```sh
python tbx/tools/dump_ops.py                          # tests/fixtures/ops/*.txt
python tbx/tools/dump_user_code.py                    # tests/fixtures/usercode/*.bas
uv run python tests/tbx/test_ir_snapshot.py --write   # tests/fixtures/ir_snapshot.txt
```

Requires Python 3.11+. CI (`.github/workflows/ci.yml`) runs ruff, ty, and pytest on Python 3.11–3.13 for pushes to main and pull requests; all three must pass.

The core package (`tbx.decode0`, `tbx.ir`, `tbx.emit0`, `tbx.cli`) has **zero runtime dependencies**; keep it that way. Only `tbx/tools/` may use iced-x86 (the `debug` extra), and `tests/tbx/test_cfg.py` guards it with `pytest.importorskip`.

## Architecture

The pipeline is EXE bytes → op stream → typed IR → canonical source:

1. **Scan** (`decode0/scan.py`, `decode0/dialect.py`) — walk the user-code region into a flat op list. Turbo Basic compiles to a threaded style: floating point is the x87 *emulation* encoding (INT 34h+n for ESC opcode D8h+n), statements dispatch through INT ECh/EDh/EEh sub-vectors, and control flow is raw x86 (`e9`, `Jcc rel8`) interleaved with the INT stream. The compiler dialect (1.0 vs 1.1) is auto-detected from the prologue, and TB 1.0's shifted INT/sub numbering is normalized to 1.1's *at scan time* — everything downstream is dialect-blind.
2. **Layout** (`decode0/layout.py`, `decode0/datapool.py`) — solve the DGROUP data layout (scalar slots from DS:0120, array slot records, integer const pool, string space, error-trap line table, DATA pool) from the op stream's memory evidence plus the image's tail structures. Key invariant: the const-pool window's file position is always EOF − 0x2C, which pins the DS file base.
3. **Lift** (`decode0/core.py` + `decode0/handlers/`, `decode0/lift.py`, `decode0/select_case.py`) — `decode_user_code` runs a dispatch loop over the op stream. All loop state lives in `DecodeState` (`core.py`); handlers in `decode0/handlers/` (arith, control, dos_io, fileio, graphics) each consume ops and return `True`, and `select_case.py` is a state machine consulted at the top of each iteration. `lift.py` folds structured control flow (FOR/WHILE/DO, block IF, SUB/DEF FN) from its compiled shapes; `rename.py` renames variables to A, B, C… in first-store order.
4. **Emit** (`emit0.py`) — typed IR → canonical source: one statement per line, numbered 10, 20, …. Line numbers are renumbered freely EXCEPT where byte-significant (error-trap line tables, TRON trace hooks), in which case the originals are recovered and preserved exactly.

`tbx/ir/` is the shared IR: immutable dataclasses, pure data, pattern-matched by analyses. `unparse(parse_expr(s)) == s` is a checked invariant (`test_ir.py`). Both `tbx.ir` and `tbx.decode0` re-export their submodules' surface through `__init__.py`, so callers use `ir.Foo` / `decode0.bar`.

**The decoder→emitter contract**: `decode_user_code` returns `Program` (`decode0/meta.py`), a `list` subclass of IR statements carrying side-channel attributes that `emit0.emit` reads via `getattr` (so plain statement lists also emit, as tests exploit): `lines` (original line numbers when the error-trap line table makes them byte-significant; `None` = renumber freely), `metas` (`(stmt_index, text)` pairs for $STACK/$SOUND/$EVENT, emitted unnumbered before the indexed statement), `toggles` (IDE Options letters, reported out-of-band by the CLI), and the TRON trio `hook_seq`/`traced`/`trace_partial` (per-physical-line trace-hook numbering). Changes to any of these must keep both sides in sync.

## The calibration rule (most important convention)

The decoder is **fail-loud**: any byte pattern outside the calibrated vocabulary raises `ValueError` (with offending byte and file offset) rather than guessing. A byte pattern joins the vocabulary only after a fixture program in `tests/fixtures/corpus/` witnesses it and its decompile-recompile round trip was verified byte-exact against the real Turbo Basic compilers. Do not add speculative decodings. Verifying *new* fixtures end-to-end requires the original DOS toolchain (under an emulator), which this repo does not include or automate — existing goldens encode past verifications.

Where the compiler is genuinely lossy, aliases are normalized to one canonical form that recompiles byte-identically (STOP/SYSTEM ≡ END, INCR x ≡ x = x + 1, DATA regrouped as one statement, pre-test WHILE ≡ DO WHILE…LOOP) — normalization is fine, guessing is not.

IDE compiler toggles (Keyboard break, Bounds, Overflow, Stack test, 8087) have no source spelling and are deliberately **not** emitted (even as comments — comment text would perturb a runtime table under K/O). They ride on `Program.toggles`; the CLI reports them on stderr.

## Tests and fixtures

Regression layers, all swept on every pytest run:

- `tests/fixtures/ops/*.txt` — canonical op-stream dump per corpus EXE, gated by `test_goldens.py` (which reuses `dump_ops.canon`, so tool and test can't drift apart). Scan-level drift fails here.
- `tests/fixtures/ir_snapshot.txt` — one `repr()` per IR statement for every corpus EXE that has a usercode golden; decoder drift fails with the exact program and statement line (`test_ir_snapshot.py`).
- `tests/fixtures/usercode/*.bas` — golden emitted source, swept by `test_goldens.py`. Emit-level drift fails here.
- Hand-written per-feature tests in `tests/tbx/` that pin exact IR for specific fixtures — the strongest guard, since goldens can be regenerated but pinned IR must be edited deliberately.

Golden regeneration is only for **intended** changes; review the git diff it produces as carefully as code. `dump_user_code.py` deliberately skips flag fixtures (non-empty `Program.toggles`) — they carry no `.bas` golden because their source is identical to the unflagged program's, and `test_goldens.py` enforces that absence.

Corpus naming (`tests/fixtures/corpus/`): `.exe` files are compiled fixtures, `.bas` alongside them are the authored originals. Prefixes: plain `t1_`/`tier*`/`zz_` = TB 1.1; `v10_` = the same program compiled with TB 1.0 (dialect tests assert identical IR across both); `f<code>_` = compiled with one IDE Options toggle ON (fkb=Keyboard break, fbd=Bounds, fov=Overflow, fst=Stack test, f87=8087) — these carry no `.bas` golden so the sweep skips them, and `test_flags.py` pins them directly.

## Debugging a decode failure

`tbx PROGRAM.EXE --ops` shows how far the scan got. For an `unhandled byte ... at ...` error, `python -m tbx.tools.cfgview PROGRAM.EXE [--out cfg.dot]` disassembles the user-code region as raw x86 (needs the `debug` extra) to identify the missing compiler template. These tools are triage-only, never part of the decompile pipeline.

## Style notes

- Ruff ignores E701/E702 (one-line compound statements are used) and E741; `ty` runs in strict-ish mode (`missing-type-argument` and `possibly-unresolved-reference` are errors). Both must pass clean.
- Module and function docstrings carry the byte-level rationale (encodings, layout rules, which fixture witnessed a behavior) — keep that habit when touching decoder code; cite the witnessing fixture by stem.
