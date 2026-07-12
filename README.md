# tbx — a byte-exact decompiler for Borland Turbo Basic 1.0/1.1

[![CI](https://github.com/leag/tbx/actions/workflows/ci.yml/badge.svg)](https://github.com/leag/tbx/actions/workflows/ci.yml)

`tbx` recovers Turbo Basic source from 16-bit MS-DOS EXEs compiled by Borland
Turbo Basic 1.0 or 1.1. Its correctness standard is unusual for a decompiler:
a recovery counts only if **recompiling the emitted source in the original
Borland toolchain reproduces the input EXE byte-for-byte**.

```
tbx PROGRAM.EXE                 # recovered source on stdout
tbx PROGRAM.EXE -o PROGRAM.BAS  # write to a file
tbx PROGRAM.EXE --ops           # canonical op-stream dump (debugging)
```

Python API:

```python
from tbx import decode0, emit0

source = emit0.emit(decode0.decode_user_code(open("PROGRAM.EXE", "rb").read()))
```

## Installation

Requires Python 3.11+. The core decompiler has no runtime dependencies.

```
pip install .
```

The disassembly-based debugging tools (see below) need
[iced-x86](https://pypi.org/project/iced-x86/), available via the `debug`
extra:

```
pip install '.[debug]'
```

or, for development (with [uv](https://docs.astral.sh/uv/)):

```
uv sync
uv run pytest
```

## How it works

Turbo Basic compiles to a thin threaded style over a runtime library: floating
point uses the x87 *emulation* encoding (INT 34h+n in place of ESC opcodes),
statements dispatch through INT ECh/EDh/EEh sub-vectors, and control flow is
raw x86 interleaved with the INT stream. The decoder:

1. **Scans** the user-code region into a canonical op stream (`decode0.scan`),
   auto-detecting the compiler version from the program prologue and
   normalizing TB 1.0's shifted INT numbering to 1.1's at scan time, so
   everything downstream is dialect-blind.
2. **Solves the DGROUP data layout** (`decode0.layout`) — scalar slots, array
   slot records, the constant pool and string space — from the op stream's
   memory evidence plus the image's tail structures.
3. **Lifts** the op stream to a typed statement/expression IR (`decode0.core`,
   `decode0.handlers`, `tbx.ir`), folding structured control flow
   (FOR/WHILE/DO, block IF, SELECT CASE, SUB/DEF FN) from its compiled shapes.
4. **Emits** canonical source (`emit0`): one statement per line, numbered
   10, 20, …, variables renamed A, B, C… in first-use order — except where
   original line numbers are byte-significant (error-trap line tables, TRON
   trace hooks), in which case they are recovered exactly.

## Coverage

The full Turbo Basic handbook surface is implemented — statements, intrinsic
functions, metastatements (`$STACK`/`$SOUND`/`$EVENT`), event trapping, error
handling (including the compiled error line table), graphics/blit, and
TRON/TROFF trace regions — plus their known interactions. Both compiler
dialects are supported and auto-detected; the fixture corpus pairs constructs
across TB 1.0 and 1.1.

## Design

- **Fail-loud.** Anything outside the calibrated vocabulary raises instead of
  guessing. A byte pattern joins the vocabulary only after a fixture program
  witnesses it and the byte-exact round trip passes.
- **Canonical IR across dialects.** TB 1.0 and 1.1 differ systematically
  (per-dispatch-table sub shifts, a vector shift, a handful of genuinely
  different encodings — RESUME, RUN, DEF SEG=, the blit descriptor push).
  `decode0` canonicalizes to 1.1 numbering at scan time.
- **Known lossy spots are normalized, not guessed.** Aliases the compiler
  makes indistinguishable are rendered as one canonical form that recompiles
  byte-identically (STOP/SYSTEM ≡ END, INCR x ≡ x = x + 1, `PRESET (x,y),c`
  ≡ PSET-with-color, …). DATA line grouping is physically discarded by the
  compiler, so DATA re-emits as one normalized statement; original line
  numbers are recovered exactly where they are byte-significant and
  renumbered freely otherwise.

## Testing

```
pytest
```

The test suite decodes several hundred compiled fixture EXEs
(`tests/fixtures/corpus/`) and checks their op streams and emitted source
against committed golden files (`tests/fixtures/ops/`,
`tests/fixtures/usercode/`). Every fixture was verified byte-exact against
the real Turbo Basic 1.0/1.1 compilers when it was added; validating new
recoveries end-to-end requires access to the original DOS toolchain (e.g.
under an emulator), which this repository does not include or automate.

## Native recompilation (experimental)

Beyond source recovery, `tbx` can recompile a decoded program for modern
platforms by emitting a self-contained C translation unit:

```
tbx PROGRAM.EXE --emit-c -o program.c
cc program.c -lm -o program        # gcc or clang (labels-as-values is used)
```

The generated file embeds a small runtime that follows Turbo Basic semantics:
GW-BASIC-style PRINT layout with per-channel TAB/SPC columns, CINT banker's
rounding, 16-bit integer operators (`\` `MOD` `AND` `OR` `XOR` `NOT`),
single-precision default variables, DATA/READ/RESTORE, sequential file I/O
(OPEN/CLOSE/PRINT#/INPUT#/WRITE/EOF), error trapping (ON ERROR GOTO / ERR /
ERL / RESUME, untrapped errors abort with TB's code and line), SUB/CALL with
by-reference parameters, and LOCATE/COLOR mapped to ANSI escapes. Fidelity is
behavioral, not byte-exact, and the back end is fail-loud like the decoder:
programs using constructs outside the implemented vocabulary (graphics, sound,
event traps, random-access files, machine access) are rejected rather than
mistranslated. About 62% of the fixture corpus recompiles and runs natively
today.

## Debugging tools

The decoder fails loudly by design: an unrecognized compiler template raises
`ValueError` with the offending byte and file offset. These tools exist to
triage those failures and to maintain the golden fixtures — none of them are
part of the decompile pipeline:

- `tbx PROGRAM.EXE --ops` — dump the canonical op stream instead of source,
  to see how far the statement scan got and what it recognized.
- `python -m tbx.tools.cfgview PROGRAM.EXE [--out cfg.dot]` — disassemble
  the user-code region as raw x86 (`tbx/tools/insns.py`, via iced-x86 from
  the `debug` extra) and write a Graphviz CFG. This is the tool for
  inspecting the bytes around an `unhandled byte ... at ...` error to work
  out which compiler template the scanner is missing.
- `python tbx/tools/dump_ops.py` and `python tbx/tools/dump_user_code.py` —
  regenerate the golden fixtures under `tests/fixtures/ops/` and
  `tests/fixtures/usercode/` from the corpus EXEs after an intended decoder
  change.

## License

MIT — see [LICENSE](LICENSE).
