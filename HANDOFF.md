# Wild-corpus gap campaign — handoff

Status as of 2026-07-17, branch `claude/claude-md-docs-mr8ssz`.
Standing instruction: close the most common decoder gap first, in frequency
order, over the 84 wild PC-SIG Turbo Basic EXEs in `wild/hits/` (untracked,
gitignored, copyrighted shareware — **never commit them**).

## Where things stand

`python -m tbx.tools.scan_wild wild/hits` — 84 EXEs: 3 decode OK, 81 fail.
Current tally (post gap 22):

| count | error | status |
|---|---|---|
| 15 | INT cd | unwitnessable runtime-revision artifact — not actionable (see `scan_wild.py` docstring) |
| 7 | DGROUP layout not solvable | **gap 16, needs fresh diagnosis — see below** |
| 5 | byte 90 | set aside (4) + rstprint.exe advanced in from gap 21 (1, undiagnosed whether it's the same unwitnessable shape — check before assuming) |
| 4 | byte ea | mcmurphy.exe advanced in from gap 21; likely the multi-segment-code JMP FAR shape diagnosed under gap-ea below — probably a big lift, not a small gap |
| 3 each | INT 8c, byte 81, 06 | next tier, undiagnosed (byte 01 is fully gone; byte 83/ce also gone from earlier gaps this session) |
| 2 each | EC sub 66, EC sub 38, FP de/1e, FP dc/04, byte ff, 8c, 3b, 29 | then singles |

## Recently closed (this campaign, newest first)

- **Gap 22, compound-store integer ADD (disp16)** (this session): `01 06
  [disp16]` = `add word [disp16], ax` — the DGROUP-scalar sibling of the
  already-implemented `addm_ax_bp` (LOCAL variant, `01 46 [bp+disp8]`,
  from the `t1_local1` era). Covers `X% = X% + <expr>` whenever the RHS
  isn't a bare literal 1 (no INCR fast path applies) and the compiler
  folds the store back with ADD instead of a separate load/add/MOV —
  works uniformly whether the materialized RHS in `ax` came from a
  literal or a different variable read (menu.exe's wild occurrence reads
  a DIFFERENT scalar into `ax` before the ADD, `A% = A% + B%` shape).
  New op `addm_ax`, handled identically to `addm_ax_bp` but through
  `state.loc()` instead of `state.loc_local()`. Also caught and fixed a
  drift bug while implementing this: the COMMON-bands layout path
  (`layout.py`'s `_bands_layout`-feeding evidence list, ~line 365) has
  its OWN separate copy of the int-evidence tuple that fell out of sync
  during gap 20 (`addm_i8`/`cmp_mi16` were never added there) — fixed
  alongside `addm_ax`. Byte-exact verified both dialects, both a
  literal-RHS and variable-RHS probe. Fixture `t1_addimm`/`v10_t1_addimm`,
  pinned in `test_wild_batch3.py` + `test_tb10_dialect.py`. Closed wild
  baby.exe/menu.exe/number.exe's byte-01 failures; each advanced into a
  distinct next gap (INT 8c, byte 0b, byte 89).
- **Gap 21, Overflow-toggle INTO after arithmetic** (2026-07-17): byte
  `0xCE` = the raw x86 `INTO` instruction (call INT 4 if the Overflow flag
  is set), which the compiler inserts after integer arithmetic whenever
  the **Overflow** IDE Options toggle is ON. Confirmed by checking
  `_toggles()` on all three wild hits (bill.exe/mcmurphy.exe/rstprint.exe
  all carry `O`). The existing `fov_t1_and.exe` flagged fixture never
  actually exercised this byte (it's all FP comparisons, no integer
  arithmetic) — toggle *detection* was calibrated, but the runtime
  check's own byte pattern never was, so this sat as a gap despite
  looking "already supported." Like Bounds/Stack test, INTO has no
  source spelling; unlike those, it carries no operand and no state, so
  the fix is a pure skip — a new `"into"` op consumed at the very top of
  the main dispatch loop, before any statement-boundary logic touches
  `state.cur`, since it appears mid-expression. Compiled via
  `oracle`'s lower-level `tb_v86_compile.js --toggles O` (the
  Python `compile_bas` wrapper has no toggle parameter; needed `--tb
  <floppy>` too, not `--floppy`, for the TB 1.0 variant — a wrapper gap,
  not a compiler one). Byte-exact verified both dialects (recompiled with
  the same `--toggles O` flag). Fixtures `fov_t1_ovfadd.exe` +
  `v10_fov_t1_ovfadd.exe` (flagged fixtures: `.exe` only, no `.bas`, no
  dosout — pinned directly in `test_flags.py`, matching the existing
  `fov_t1_and`/`fbd_*`/`fst_*` convention). Closed all three wild
  byte-ce failures; each advanced into a distinct next gap (0x8a system
  cell, byte ea, byte 90) — no shared follow-on blocker.
- **Gap 20, integer FOR-NEXT with a literal STEP other than +-1, and/or a
  limit too large for a signed imm8** (this session): `83 06 [disp16]
  imm8` = `add word [disp16], imm8` is the FOR-NEXT increment fast path
  for a literal STEP the compiler folds directly into the instruction
  (`inc_m`/`dec_m` only cover +-1). New op `addm_i8`; on match against the
  open FOR's loop var it rewrites the already-`put` `ir.For` statement's
  step field IN PLACE (tracked via a new `"idx"` key in the FOR frame,
  set when the statement is first emitted with a provisional `Lit(1)`)
  rather than trying to know the step up front, since the ADD only
  appears at the NEXT, after the body's already been scanned. A negative
  literal step (sign-extended imm8) flips the loop-continuation jcc from
  JLE/JBE to JGE (0x7D) at the paired `cmp_mi8` consumer. Discovering this
  also surfaced a **second phantom scalar slot**: with both limit and
  step literal, NEITHER of the FOR's two reserved temp words gets any
  evidence (the existing single-phantom bridge in `walk_run` only
  covered one), so `layout.py` gained a second `elif d + 4 in ints`
  bridge. Testing surfaced one more sub-gap: `81 3E [disp16] imm16` =
  `cmp word [disp16], imm16`, needed whenever the limit doesn't fit a
  signed imm8 (`cmp_mi16`, wired into both the FOR-header recognition and
  the NEXT-side test) — this turned out to affect even a plain step-1
  FOR with a large limit, a latent gap independent of the STEP work.
  Byte-exact verified both dialects across three fixtures (positive step,
  negative step, large limit + step), t1_forstep/t1_forstepn/t1_forbig +
  v10 variants, pinned in `test_wild_batch3.py` + `test_tb10_dialect.py`.
  Closed wild football.exe/menu.exe/stat.exe's byte-83 failures; each
  advanced into a distinct next gap (EC sub 38, byte 01, FP de/1e resp.) —
  none share a common next blocker.
  **Note**: while diagnosing, found a separate PRE-EXISTING bug (STEP -1
  inside an integer FOR raises "displacement 0x124 is neither scalar nor
  array element" — the phantom-slot walk apparently mishandles the
  dec_m+FOR combination too) that no CURRENT wild file happens to trip;
  left unfixed as out of this gap's scope, but worth a look if a future
  wild file surfaces it.
- **Gap 18, by-ref int param IMUL fold** (2026-07-17): `26 F7 2C` = `imul
  word es:[si]` — the multiplicative counterpart to the existing
  `far_addax_si`/`far_andax_si`/`far_cmpax_si` folds in the `les
  si,[bp+N]; 26 <op> es:[si]` by-ref-SUB-param family (gap 11). Fills a
  gap: `A% * B%` where both operands are by-ref int params. New scan.py
  case emits `"far_imulax_si"`; consumed in `core.py`'s generic
  `kind.endswith("_si")` by-ref-param dispatch (~line 1460) alongside the
  sibling folds, using `"*"` through the same `_rgrp` orientation helper.
  Byte-exact verified both dialects, fixtures t1_byref2/v10_t1_byref2,
  pinned in `test_wild_batch3.py::test_decode_t1_byref2` +
  `test_tb10_dialect.py`'s `PAIRS`. Closes wild filepatc.exe/morcalc.exe/
  pw.exe's byte-26 failures fully — all three advanced into a NEW `byte
  06` gap (undiagnosed, now tied at 3 with ea/ce/83/81), not yet
  investigated this session.
- **Gap 17, RUN file$** (2026-07-17): `RUN "file$"` (loads and runs a
  DIFFERENT program) compiles to `movsi <string desc>; rt 0x9C (push); INT
  EC sub C4` — a distinct statement dispatch from bare `RUN`'s raw
  jmp-to-start (already handled). Sub 0xC4 sits alphabetically between
  RMDIR (0xC2) and SHELL/SCREEN in the EC sub-op table, exactly where a
  gap existed. `ir.Run` gained an optional `file` field (`None` = bare
  RUN); `core.py`'s `os_system` handler pops the pushed string and builds
  `ir.Run(file)`, mirroring `ir.Chain`. c0 doesn't support it (no
  host-process-replace surrogate for loading a different program) and now
  raises `_Unsupported` explicitly instead of silently mistranslating it
  as a restart — waived in `test_c0.py`. Byte-exact verified both dialects
  and both a literal (`RUN "X.BAS"`) and variable (`RUN A$`) filename
  form; fixtures t1_run2/v10_t1_run2 (literal form; variable form shares
  the same decode path so wasn't promoted separately), pinned in
  `test_wild_batch3.py::test_decode_t1_run2` + `test_tb10_dialect.py`'s
  `PAIRS`. Closes wild ck.exe fully; onelab87.exe/onelabel.exe advanced
  into the DGROUP-layout gap (gap 16) instead.
- **Gap 15, static string array at constant index** (2026-07-17): static
  string array element access (`DIM A$(5)` / `A$(2) = ...`) compiles
  `movsi <array_base + 4*index>`; that disp is neither a scalar slot nor a
  pool descriptor. Two fixes in `layout.py`'s `finish`: (1) the descriptor
  validation loop now exempts movsi disps landing inside a static STRING
  array's element span (`rec["str"]`, type byte 0x0A); (2) the walk-path's
  pre-`find_statics` movsi gate was reordered to run *after* `find_statics`
  so it can apply the same string-array-span exemption instead of blindly
  rejecting any candidate with an unaccounted movsi disp below the pool
  (that gate previously had no way to know about arrays yet). `core.py`'s
  `rt 0x9C` push leg (~line 1839) now also checks static string-array
  membership, not just scalar `strs`, before falling back to
  `_pool_str`. Byte-exact verified both dialects, fixtures t1_sstat +
  v10_t1_sstat, pinned in `test_wild_batch3.py::test_decode_t1_sstat` and
  `test_tb10_dialect.py`'s `PAIRS`.
  **Important**: diagnosing this shape came from a wild-file lead
  (schart.exe, movsi disp 0x600) but implementing it did NOT make any wild
  file advance — see gap 16 below, the wild DGROUP-5 files have a different
  or additional problem.
- **Gap 14, COMMON** (`b75086d`): compiles to zero ops — two 16-byte band
  stamps `(num_size, num_base)(str_size, num_base+num_size)(0, num_base)
  (0, num_base)` in the DGROUP init image: COMMON band at DS:0110, ordinary
  scalars segregated numerics-first. Stamps matched by shape (positions
  shift, may overlay band cells), loop closed by `align16(ord_end)+4 ==
  pool marker`. Declaration is lossy → one canonical COMMON emitted.
  `layout._bands_layout`, `ir.Common`, fixtures t1_common1/2/3 +
  v10_t1_common2.
- **Gap 13, pool-runaway walk** (`3da97b8`): band ending 16-aligned puts the
  movsi-referenced `""`/marker cell in the walk's path; solver now retries
  the walk cut at 16-aligned string positions. Fixture t1_poolrun.
- Gap 12 INCR/DECR (`0e4f0f7`), gap 11 by-ref int param family (`3f1e23d`),
  gap 10 LOCAL (`2ef2b6d`), gap 9 double arrays — see git log.

## Gap 16 — schart/hfprop/vhfprop/inv87/invoice, UNDIAGNOSED

The 5 wild "DGROUP layout not solvable" files did NOT advance after gap
15's fix landed. Traced schart.exe in detail (instrumented `layout._layout`
with temporary debug prints, since removed): the "no runtime arrays"
walk-based solver (`_layout`'s `for n in range(31, -1, -1)` loop) never
finds a consistent `(ds, n, statics)` triple for ANY `n` from 0 to 31 —
`find_statics` returns `None` for most `n`, and the handful of `n` where it
does return statics (9, 7, 6, 4, 3, 2, 1, 0) all produce bogus/spurious
array records (huge implausible bases like `0xc8a0`-`0xc960`, none of them
`str`-typed) that don't include a string array whose span covers the
movsi disp `0x600` referenced in the ops. That disp is never explained as
either a scalar, a pool descriptor, or (in any candidate reached) a string
array element.

This means schart.exe's real DGROUP shape doesn't fit the existing
walk-anchored solve strategy at all — likely something structurally
different (not just "add one more exemption"), e.g.: array element storage
interleaved with or ahead of the scalar walk in a way the `dc`-driven
`pool_base` formula doesn't model, a second/nested array region, or this
file actually needs the `rt_blocks` (runtime-DIM) anchor path but isn't
tripping it. Needs fresh evidence-set analysis (`tbx FILE --ops`,
`cfgview`, hexdump around disp 0x600 and its file offset) before attempting
another fix — do not assume it's a small tweak.

hfprop/vhfprop/inv87/invoice are untested against this specific finding;
they may or may not share schart's exact shape.

## Gap 19 — byte 06 (filepatc/morcalc/pw, all TB 1.0), UNDIAGNOSED

Surfaced by gap 18's closure (these 3 files previously failed on byte 26).
Failure: `unhandled byte 06` right after a fresh `proc_enter` (SUB/DEF FN
prologue `55 8b ec` = push bp; mov bp,sp), i.e. `06` = bare `push es` at
the very top of a new procedure body, which the decoder doesn't
recognize in that position. Full byte sequence at filepatc.exe 0x8870:

```
55 8b ec                push bp; mov bp,sp        (proc_enter)
06                       push es
1e                       push ds
8b 16 00 00              mov dx,[0000h]
c5 76 0a                 lds si,[bp+0Ah]
8e 04                    mov es,[si]
c5 76 06                 lds si,[bp+06h]
8b 3c                    mov di,[si]
c5 76 1a                 lds si,[bp+1Ah]
8b 04                    mov ax,[si]
50                       push ax
c5 76 0e                 lds si,[bp+0Eh]
8b 04                    mov ax,[si]
c5 76 12                 lds si,[bp+12h]
8b 5c 02                 mov bx,[si+2]
03 d8                    add bx,ax
c5 76 1e                 lds si,[bp+1Eh]
8b 0c                    mov cx,[si]
c5 76 16                 lds si,[bp+16h]
8b 74 ..                 mov si,[si+..]  (truncated where the dump ends)
```

**Read so far**: `bp+6, +0xA, +0xE, +0x12, +0x16, +0x1A, +0x1E` — seven
slots exactly 4 bytes apart, starting right after what would be a far
call's return address (`bp+2`=old bp, `bp+4`/`+6`... — i.e. a SUB/FUNCTION
with (at least) 7 parameters, each passed as a 4-byte far pointer, and
EACH accessed via a fresh `lds si,[bp+N]; mov <reg>,[si]` rather than the
already-implemented ES-shortcut family (`les si,[bp+N]; 26 <op>
es:[si]`, gaps 11/18). Working theory: the ES-shortcut only fires when a
SUB reuses the same by-ref param's ES:SI setup for a second op within
one statement; a single-use read of a DIFFERENT param each time falls
back to this general LDS-based form instead — if true, this is a
genuinely new, more general "plain by-ref param read" mechanism (target
register varies: ES, DI, AX, BX, CX, SI seen so far, not just AX), NOT a
small addition to the existing 26-prefixed dispatch table.

**Why not fixed this session**: 7 parameters with values loaded into ES/
DI/BX/CX/SI (not just AX) is unusual for ordinary arithmetic — ES
loaded from a by-ref param strongly suggests it's being used AS A
SEGMENT for a subsequent far access, and the `[si+2]` field-style access
suggests either pointer/structure arithmetic or something like FIELD-
based random file I/O combining buffer segments/offsets. Tried one
probe hypothesis (a SUB with an array parameter, `SUB SUB1(B())`) — TB
rejected the syntax outright (`Error 425: Integer constant expected`),
so that guess was wrong and ruled out. Did not attempt further guesses
without stronger evidence; picking this up needs either: (a) more
candidate probes (7-int-by-ref-param SUB doing varied arithmetic; GET/
PUT with FIELD-allocated buffers; CALL INTERRUPT with register-struct
args) compiled and diffed against this exact byte shape, or (b) reading
further into what `mov dx,[0000h]` reads (disp 0 is below `VAR_BASE`,
so it's a fixed runtime/system cell, not a user scalar — identifying
what lives at DS:0000 would narrow this down fast).

**Further traced (2026-07-17, same session)**: found the right `ds`
(`0xf900`, from `pool_base=0x4b4` — confirmed correct because `INPUT`'s
bare-prompt sentinel disp `0x4b0` == `pool_base-4` exactly, and because
extending `find_statics`'s scan window at this `ds` well past `sb` turns
up EXACTLY 10 valid, contiguously-packed (each `+0x36` apart) static slot
records with bases `0x7e0, 0x810, 0x840, 0x1fc0, 0x7430, 0xc8a0, 0xc8d0,
0xc900, 0xc930, 0xc960` — the first two and last five exactly match the 7
`addsi` bases seen in the ops (the other 3 are presumably `[si]`-only or
constant-index arrays with no `addsi` evidence). So `ds` and the true
static count (`n=10`) are BOTH right.

The bug: `find_statics(ds, sb, n)` bounds its scan window at
`ds+sb` (`sb = VAR_BASE + ARR_BLOCK*n`), i.e. it assumes all `n` records
are packed within exactly `n * 0x36` bytes from the grid start
(`ds+VAR_BASE`). For schart.exe they are NOT: the 10 real records sit
contiguously (correctly `0x36` apart from each other) but only starting
368 bytes (`0x170`) into the grid, well past where a tight `n*0x36`
window would look for record 1 — so the window cuts off after only 3
records instead of reaching all 10. Hex-dumped that leading 368-byte
span: it is NOT zero padding (ruled out the "zero-init table [that
floats before static-only records]" explanation from `find_statics`'s
own docstring) — it's dense structured binary data, unclear origin
(possibly another data structure entirely occupying that space, or slot
records in a format `_parse_static_slot` doesn't recognize). Did not
identify what it actually is.

**Why not fixed this session**: this is exactly the situation the
calibration rule warns against — patching `find_statics`'s window
math without understanding what that leading 368 bytes actually IS
would be guessing, and schart.exe (a wild EXE, not an authored fixture)
can't be byte-exact verified against the oracle even if a fix is found
(see the wild-corpus runtime-revision-skew caveat). Next step for
whoever picks this up: identify what occupies file offset `ds+VAR_BASE`
through `ds+VAR_BASE+0x170` (`0xfa20`-`0xfb90` for this specific `ds`) —
compare against a corpus fixture with a similarly large static-array
count to see if there's a known structure (DATA pool? another array
type not yet in `_parse_static_slot`?) that explains it, THEN author a
minimal authored probe reproducing that exact shape for oracle
verification, per the usual workflow — don't patch based on schart.exe
alone.

## The workflow (each gap, see gap 9–14 commits for examples)

1. `uv run python -m tbx.tools.scan_wild wild/hits` — pick the top
   actionable error.
2. Diagnose: `tbx FILE --ops`, hexdump/`tbx.tools.insns` at the offset,
   evidence-set dumps against `decode0.scan._scan`.
3. Author a minimal probe `.bas`; compile via `tbx.tools.oracle.compile_bas`
   (oracle at `../frame/oracle`; `dialect="1.0"` for the TB 1.0 floppy).
4. Implement; the probe must decode to its exact source.
5. Byte-exact verify: decode → emit → oracle recompile → compare.
6. Promote to `tests/fixtures/corpus/` as `t1_<name>` (+`v10_` if 1.0-
   relevant), regenerate goldens, capture dosout
   (`dump_dos_output --missing`; INPUT fixtures need a KEYS entry —
   lowercase keys only, uppercase doubles in the harness), add a pin test.
7. Full suite + ruff + ty, commit, push (fast-forward check first), re-scan.

Session-persistent notes live in the auto-memory file `wild-tb-corpus.md`
(gap history, unwitnessable cases, corpus caveats — e.g. wild EXEs may
never verify byte-exact against the oracle due to runtime-revision skew,
so they are never promoted; only authored probes are).
