# tbdc — Turbo Basic decompiler

`tbdc` recovers BASIC source from MS-DOS programs compiled with Borland
Turbo Basic 1.0 or 1.1. It combines the two decoders built before it:

- **tbx**, the calibrated decoder: every byte pattern it knows was witnessed
  by a compiled fixture and verified by recompiling to the identical EXE. It
  runs first, with its wild-recovery mode on, so a program that strays outside
  the calibrated vocabulary still decodes.
- **tbd**, the best-effort analyzer: it never gives up on a region and marks
  what it could not lift with `REM TBD` lines. It takes over when tbx fails.

On top of them `tbdc` repairs what Turbo Basic would reject, so the output
can be loaded and compiled: blocks that cross (a `LOOP` inside an `IF` begun
after the `DO`) are rewritten with labelled `GOTO`s, `CALL` arguments are
reconciled with the `SUB` signatures, unreachable statements after a `GOTO`
are dropped, unmatched block openers/closers become `REM TBDC:` comments,
programs past the editor limit are split into `$INCLUDE` files, and LZEXE
packed executables are unpacked first. Each repair is reported.

## Usage

```bash
uv sync
uv run tbdc PROGRAM.EXE                    # source on stdout
uv run tbdc PROGRAM.EXE -o PROGRAM.BAS     # writes PROGRAM.BAS (+ .INC/.BIN files when needed)
uv run tbdc PROGRAM.EXE -o PROGRAM.BAS --report report.json
uv run tbdc DIR -o OUTDIR                  # every .EXE in DIR, one folder each
```

| Option | Effect |
| --- | --- |
| `-o PATH` | Output `.BAS` (directory for a directory input). Files are DOS text (CRLF, Latin-1). |
| `--engine auto\|tbx\|tbd` | Force a decoder (default `auto`: tbx, then tbd). |
| `--numbered` | Number every line (default: only lines that are jump targets). |
| `--dense` | Also remove optional spaces (tbx's compact layout). |
| `--no-split` | Never split into `$INCLUDE` files. |
| `--report FILE` | JSON: engine, dialect, compiler toggles, warnings, every repair. |
| `--verify` | Recompile the output with Turbo Basic under QEMU and compare with the input. |
| `--repair` | With `--verify`: comment out each line Turbo Basic rejects until it compiles. |

The report's `toggles` are the IDE options (8087, Keyboard break, Bounds,
Overflow, Stack test) the program was compiled with; set them in the IDE when
rebuilding.

### Verifying with the real compiler

`--verify`, `--repair` and `scripts/evaluate.py` drive the original compiler
with the QEMU harness in `oracle_qemu/` (from tbd). They need
`qemu-system-i386`, mtools, and the disk images in `oracle/`
(`freedos.img`, `tb10_floppy.img` for TB 1.0, `tb_floppy.img` for TB 1.1),
or another directory named by `TBDC_IMAGES`.

```bash
uv run tbdc PROGRAM.EXE -o out/PROGRAM.BAS --verify --repair
```

## Results on the wild corpus

`scripts/evaluate.py` decompiles every EXE in a directory, recompiles each
output with the matching Turbo Basic, compares the rebuilt EXE with the
original, and (with `--behavior SECONDS`) runs both under QEMU without input
and compares the screens.

```bash
uv run python scripts/evaluate.py wild/hits --out build/eval --jobs 6 --behavior 8 --repair
```

| Measure | Programs |
| --- | ---: |
| Executables in the corpus | 108 |
| Not Turbo Basic (archives, other compilers) — rejected | 5 |
| Turbo Basic programs decompiled | 103 of 103 |
| … by tbx / by tbd fallback | 100 / 3 |
| Output compiles with Turbo Basic as emitted | 99 of 103 |
| … after `--repair` comments out rejected lines | 103 of 103 |
| Rebuilt EXE byte-identical | 1 |
| Rebuilt user code (prologue on) byte-identical | 4 |
| … not identical but ≥ 99 % of user-code bytes in place | 19 |
| Same screen as the original after 8 s, no input | 70 |
| Both screens blank after 8 s | 12 |
| Different screen | 17 |

Programs that need `--repair` (lines commented out):

- `bmaster.exe` (tbx): 2
- `ifi.exe` (tbx): 2
- `pw.exe` (tbx): 6
- `slimmer.exe` (tbd): 16

Rejected as not Turbo Basic: `bm1_dsk2.exe`, `brotheru.exe`, `lmaster.exe`, `pcdcfile.exe`, `pgmsarc.exe`

Measured on 2026-10-17 over the 108 executables of tbx's `wild/hits` corpus
(shareware from PC-SIG and other CDs).

How to read it:

- **Compiles** means Turbo Basic accepts the source and builds an EXE. It is
  not a proof of equivalence: wild recovery retargets jumps it cannot resolve,
  and the report's warnings list every such place.
- **Byte identity** is rare because most of these programs were built with
  Turbo Basic runtime revisions we do not have; the user program after the
  compiler prologue is the fairer comparison, and most differences there are
  data-layout offsets (variable and string-pool addresses), not code.
- **Screens** are captured after 8 seconds with no keyboard input. Some
  differences are noise: blinking cursors and animations, graphics modes the
  text capture cannot read, or the original's runtime revision failing under
  the test DOS (`ziptest.exe`'s original stops with "Error 5", the rebuilt one
  runs). The rest are real recovery gaps: `phone.exe` box drawing, `baby.exe`
  and `sprogh.exe` start-up, `billadd.exe` error-line numbers.
- Programs that fall back to **tbd** carry `REM TBD:` placeholders for code it
  could not lift; those parts are missing from the program.

On tbx's own calibrated fixtures nothing changes: tbdc's source repairs leave
all 1,151 decodable fixtures exactly as tbx emits them (`tests/tbdc`), and
`scripts/fixture_roundtrip.py` (every 25th fixture, recompiled in QEMU)
rebuilds 43 of 47 byte-identically; the other four rebuild the same way from
unmodified tbx under this harness.

## Layout

| Path | Contents |
| --- | --- |
| `tbdc/` | the front end: `pipeline.py` (engines and repairs), `structure.py` (block repair), `calls.py` (CALL/SUB reconciliation), `fixups.py`, `unpack.py` (LZEXE), `repair.py`/`verify.py` (compiler-driven checks), `cli.py` |
| `tbx/` | the calibrated decoder (see `docs/tbx-README.md`, `STATUS.md`, `docs/decoder-architecture.md`) |
| `tbd/` | the best-effort analyzer (see `docs/tbd.md`) |
| `oracle_qemu/` | headless QEMU + FreeDOS Turbo Basic harness |
| `scripts/` | `evaluate.py` (corpus measurement), `summarize.py`, `fixture_roundtrip.py`, `errline.py` / `recompile.py` (find the line a compile error is on) |
| `tests/` | tbx's fixture suite (byte-exact goldens) and `tests/tbdc/` |

```bash
uv run pytest -q --ignore=tests/tbx/test_web_api.py
```
