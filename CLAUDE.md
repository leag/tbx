# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`tbx` is a byte-exact decompiler for 16-bit MS-DOS EXEs compiled by Borland Turbo Basic 1.0/1.1. The correctness standard is unusual: a recovery counts only if recompiling the emitted source in the original Borland toolchain reproduces the input EXE **byte-for-byte**. That standard drives every convention below.

## Commands

```sh
uv sync                       # install dev environment (pytest, ruff, iced-x86)
uv run pytest                 # full suite (~131 tests, a few seconds)
uv run pytest tests/tbx/test_arrays.py                # one file
uv run pytest tests/tbx/test_arrays.py::test_name     # one test
uv run ruff check             # lint
uv run tbx PROGRAM.EXE        # decompile (add --ops for the op-stream dump)
```

Regenerating golden fixtures after an **intended** decoder/emitter change:

```sh
python tbx/tools/dump_ops.py                          # tests/fixtures/ops/*.txt
python tbx/tools/dump_user_code.py                    # tests/fixtures/usercode/*.bas
uv run python tests/tbx/test_ir_snapshot.py --write   # tests/fixtures/ir_snapshot.txt
```

With the vendored v86 toolchain oracle available (optionally selected with
`TBX_ORACLE`, see `tbx/tools/oracle.py`; needs node + mtools):

```sh
uv run python -m tbx.tools.verify_fixture STEM        # byte-exact round trip
uv run python -m tbx.tools.dump_dos_output --missing  # tests/fixtures/dosout/
```

Requires Python 3.11+. CI (`.github/workflows/ci.yml`) runs ruff and pytest on Python 3.11–3.13 for pushes to main and pull requests, plus a `c0` platform matrix (Linux gcc/clang with SDL2, macOS clang, experimental Windows MinGW) running `test_c0.py`; all must pass.

The core package (`tbx.decode0`, `tbx.ir`, `tbx.emit0`, `tbx.cli`) has **zero runtime dependencies**; keep it that way. Only `tbx/tools/` may use iced-x86 (the `debug` extra), and `tests/tbx/test_cfg.py` guards it with `pytest.importorskip`.

## Architecture

The pipeline is EXE bytes → op stream → typed IR → canonical source:

1. **Scan** (`decode0/scan.py`, `decode0/dialect.py`) — walk the user-code region into a flat op list. Turbo Basic compiles to a threaded style: floating point is the x87 *emulation* encoding (INT 34h+n for ESC opcode D8h+n), statements dispatch through INT ECh/EDh/EEh sub-vectors, and control flow is raw x86 (`e9`, `Jcc rel8`) interleaved with the INT stream. The compiler dialect (1.0 vs 1.1) is auto-detected from the prologue, and TB 1.0's shifted INT/sub numbering is normalized to 1.1's *at scan time* — everything downstream is dialect-blind.
2. **Layout** (`decode0/layout.py`, `decode0/datapool.py`) — solve the DGROUP data layout (scalar slots from DS:0120, array slot records, integer const pool, string space, error-trap line table, DATA pool) from the op stream's memory evidence plus the image's tail structures. Key invariant: the const-pool window's file position is always EOF − 0x2C, which pins the DS file base.
3. **Lift** (`decode0/core.py` + `decode0/handlers/`, `decode0/lift.py`, `decode0/select_case.py`) — `decode_user_code` runs a dispatch loop over the op stream. All loop state lives in `DecodeState` (`core.py`); handlers in `decode0/handlers/` (arith, control, dos_io, fileio, graphics) each consume ops and return `True`, and `select_case.py` is a state machine consulted at the top of each iteration. `lift.py` folds structured control flow (FOR/WHILE/DO, block IF, SUB/DEF FN) from its compiled shapes; `rename.py` renames variables to A, B, C… in first-store order.
4. **Emit** (`emit0.py`) — typed IR → canonical source: one statement per line, numbered 10, 20, …. Line numbers are renumbered freely EXCEPT where byte-significant (error-trap line tables, TRON trace hooks), in which case the originals are recovered and preserved exactly.

An alternative back end, `c0.py` (`tbx --emit-c`), lowers the same IR to a self-contained C translation unit for modern platforms (behavioral fidelity, not byte-exact; needs gcc/clang for labels-as-values GOSUB — POSIX or MinGW-w64 on Windows, the runtime carries `#ifdef _WIN32` paths). The C runtime lives in `tbx/c0_runtime/` as standalone units — each `.c` includes `tb_runtime.h` and compiles on its own; `make` there builds it as an ordinary library (`libtbrt.a`, `SDL=1` for the SDL backend) and `tbx --emit-c --no-runtime` emits programs that link against it instead of embedding it. By default `c0.py` amalgamates header + fragments in manifest order, stripping the include lines, into the self-contained output. A symbol goes in `tb_runtime.h` (non-`static`) only if another fragment or c0-generated code references it; fragment-internal helpers stay `static`. Machine access (PEEK/POKE/OUT/INP/WAIT/REG/BLOAD/BSAVE/DEF SEG/CHAIN) runs against the emulated real-mode machine in `machine.c` (documented surrogates, not DOS); `tbx --emit-c --sdl` swaps the PPM-at-exit graphics surrogate for a real SDL2 window (`sdl.c`, gated by `-DTB_SDL`, with the window keyboard feeding INKEY$/INSTAT). c0 is fail-loud like the decoder — unsupported constructs raise, never mistranslate — and `test_c0.py` pins recompiled-program stdout plus a corpus-coverage floor (currently 564/564 transpile). The byte-exact rules below do NOT govern c0; its standard is handbook semantics.

`tbx/ir/` is the shared IR: immutable dataclasses, pure data, pattern-matched by analyses. `unparse(parse_expr(s)) == s` is a checked invariant (`test_ir.py`). Both `tbx.ir` and `tbx.decode0` re-export their submodules' surface through `__init__.py`, so callers use `ir.Foo` / `decode0.bar`.

**The decoder→emitter contract**: `decode_user_code` returns `Program` (`decode0/meta.py`), a `list` subclass of IR statements carrying side-channel attributes that `emit0.emit` reads via `getattr` (so plain statement lists also emit, as tests exploit): `lines` (original line numbers when the error-trap line table makes them byte-significant; `None` = renumber freely), `metas` (`(stmt_index, text)` pairs for $STACK/$SOUND/$EVENT, emitted unnumbered before the indexed statement), `toggles` (IDE Options letters, reported out-of-band by the CLI), and the TRON trio `hook_seq`/`traced`/`trace_partial` (per-physical-line trace-hook numbering). Changes to any of these must keep both sides in sync.

## The calibration rule (most important convention)

The decoder is **fail-loud**: any byte pattern outside the calibrated vocabulary raises `ValueError` (with offending byte and file offset) rather than guessing. A byte pattern joins the vocabulary only after a fixture program in `tests/fixtures/corpus/` witnesses it and its decompile-recompile round trip was verified byte-exact against the real Turbo Basic compilers. Do not add speculative decodings. Verifying *new* fixtures end-to-end requires the original DOS toolchain (under an emulator), which this repo does not include — on machines with the external oracle (`TBX_ORACLE`), `python -m tbx.tools.verify_fixture STEM` automates the check; existing goldens encode past verifications.

Where the compiler is genuinely lossy, aliases are normalized to one canonical form that recompiles byte-identically (STOP/SYSTEM ≡ END, INCR x ≡ x = x + 1, DATA regrouped as one statement, pre-test WHILE ≡ DO WHILE…LOOP) — normalization is fine, guessing is not.

IDE compiler toggles (Keyboard break, Bounds, Overflow, Stack test, 8087) have no source spelling and are deliberately **not** emitted (even as comments — comment text would perturb a runtime table under K/O). They ride on `Program.toggles`; the CLI reports them on stderr.

## Tests and fixtures

Regression layers, all swept on every pytest run:

- `tests/fixtures/ops/*.txt` — canonical op-stream dump per corpus EXE, gated by `test_goldens.py` (which reuses `dump_ops.canon`, so tool and test can't drift apart). Scan-level drift fails here.
- `tests/fixtures/ir_snapshot.txt` — one `repr()` per IR statement for every corpus EXE that has a usercode golden; decoder drift fails with the exact program and statement line (`test_ir_snapshot.py`).
- `tests/fixtures/usercode/*.bas` — golden emitted source, swept by `test_goldens.py`. Emit-level drift fails here.
- `tests/fixtures/dosout/*.txt` (+ `<stem>.file.<NAME>` for files the program wrote) — what the ORIGINAL corpus EXE visibly did running on the real (emulated) machine, captured once by `dump_dos_output.py`. `test_c0.py::test_dos_golden` holds the recompiled native binaries to them — the c0 analog of the byte-exact rule. Waivers in `test_c0.py` name the surrogate that justifies each divergence.
- Hand-written per-feature tests in `tests/tbx/` that pin exact IR for specific fixtures — the strongest guard, since goldens can be regenerated but pinned IR must be edited deliberately.

Golden regeneration is only for **intended** changes; review the git diff it produces as carefully as code. `dump_user_code.py` deliberately skips flag fixtures (non-empty `Program.toggles`) — they carry no `.bas` golden because their source is identical to the unflagged program's, and `test_goldens.py` enforces that absence.

Corpus naming (`tests/fixtures/corpus/`): `.exe` files are compiled fixtures, `.bas` alongside them are the authored originals. Prefixes: plain `t1_`/`tier*`/`zz_` = TB 1.1; `v10_` = the same program compiled with TB 1.0 (dialect tests assert identical IR across both); `f<code>_` = compiled with one IDE Options toggle ON (fkb=Keyboard break, fbd=Bounds, fov=Overflow, fst=Stack test, f87=8087) — these carry no `.bas` golden so the sweep skips them, and `test_flags.py` pins them directly.

## Debugging a decode failure

`tbx PROGRAM.EXE --ops` shows how far the scan got. For an `unhandled byte ... at ...` error, `python -m tbx.tools.cfgview PROGRAM.EXE [--out cfg.dot]` disassembles the user-code region as raw x86 (needs the `debug` extra) to identify the missing compiler template. When the missing template's trigger isn't obvious and there are several plausible source shapes to try, `python tbx/tools/batch_probe.py PROBE_DIR [--want SUBSTRING] [--dialect 1.0|1.1]` batches the write-probe/compile/scan loop: it compiles every `.bas` in `PROBE_DIR` against the oracle and scans each one, reporting which (if any) reproduce the target gap. These tools are triage-only, never part of the decompile pipeline.

## Style notes

- Ruff ignores E701/E702 (one-line compound statements are used) and E741. Must pass clean.
- Module and function docstrings carry the byte-level rationale (encodings, layout rules, which fixture witnessed a behavior) — keep that habit when touching decoder code; cite the witnessing fixture by stem.

## Oracle probes that compile but do not decode

`wild/hits/` and `wild/probes/` are both gap-tally corpora consumed by
`tbx/tools/scan_wild.py`-style tooling, but they hold different things and
must not be mixed:

- `wild/hits/` is programs *found in the wild* (currently the PC-SIG 8th-edition
  scan) — third-party shareware, copyrighted, gitignored, **never committed**.
- `wild/probes/` is programs *you authored and had the oracle compile* while
  investigating a gap. These are your own source, not copyrighted, and are
  **tracked in git** — commit them like any other fixture.

When investigating a decoder gap with the Turbo Basic oracle, any probe that:

1. compiles successfully, and
2. fails during TBX scanning, decoding, lifting, or rendering

must be promoted to `wild/probes/` immediately, under a unique, descriptive
stem (e.g. `probe_paletteusing_var.exe`). Compilation failure is not
sufficient for promotion: leave rejected probes in temporary working storage
and record them only as negative evidence when they materially narrow the
investigation.

Record the probe's source shape, dialect, and exact first failure in `PLAN.md`
or the relevant investigation log. Keep the `.bas` source alongside the
compiled `.exe` in `wild/probes/` (or in temporary working storage if not yet
promoted) so the probe is reproducible without re-deriving it from prose.

Promotion to `tests/fixtures/corpus/` still requires the normal calibration
rule: identify the construct, preserve fail-loud behavior for unknown shapes,
and verify the fixture's byte-exact round trip with the oracle.
