# Wild-corpus gap campaign — handoff

Status as of 2026-07-17, branch `claude/claude-md-docs-mr8ssz`.
Standing instruction: close the most common decoder gap first, in frequency
order, over the 84 wild PC-SIG Turbo Basic EXEs in `wild/hits/` (untracked,
gitignored, copyrighted shareware — **never commit them**).

## Where things stand

`python -m tbx.tools.scan_wild wild/hits` — 84 EXEs: 3 decode OK, 81 fail.
Current tally (post gap 26):

| count | error | status |
|---|---|---|
| 16 | INT cd | unwitnessable runtime-revision artifact — not actionable (see `scan_wild.py` docstring); crossref.exe advanced in from gap 23 |
| 7 | DGROUP layout not solvable | **gap 16, needs fresh diagnosis — see below** |
| 5 | byte 90 | set aside (4) + rstprint.exe advanced in from gap 21 (1, undiagnosed whether it's the same unwitnessable shape — check before assuming) |
| 4 | byte ea | mcmurphy.exe advanced in from gap 21; likely the multi-segment-code JMP FAR shape diagnosed under gap-ea below — probably a big lift, not a small gap |
| 3 each | INT 8c, byte 06 | INT 8c documented below; byte 06 = **gap 19**, partially diagnosed below (byte 81/8b/3b tiers cleared by gaps 23–26) |
| 2 each | EC sub 66, EC sub 38, FP de/1e, FP dc/04, byte 8c, 29, 03, ff, 3b, system cell 0x8a, COLOR mask | then singles; the ff/3b/8b entries keep reshuffling as cleanup/reformat/horses/phone/CVT2TB chain through their next blockers |

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

## Gap 16 — schart/hfprop/vhfprop/inv87/invoice, UNDIAGNOSED (re-traced 2026-07-17, twice)

The 5 wild "DGROUP layout not solvable" files did NOT advance after gap
15's fix landed. **This section has been through two full re-traces this
session; the second overturns the first's "prompt disps collide with the
scalar band" theory below it.** Both are kept because the corpus-array
brute-force technique (first sub-section) is still the right way to pin
`ds` for a wild file, and because the schart-specific "prompt disps"
observation may still be this SAME newly-discovered mechanism wearing a
different mask (schart has INPUT statements; the reproducer below doesn't
need them at all) — not yet re-tested against schart itself.

### Trace 1 (superseded theory, kept for the `ds`-pinning technique)

The old theory (from an *even earlier* session) was an artifact of a wrong
`ds` (guessed `0xf900` from a `pool_base=0x4b4` assumption, which
misidentified the ordinary error-trap line table as an unexplained blob).
**The correct `ds` is `0xfa70`, confirmed by brute force**: scan the whole
file for a run of `_parse_static_slot`-valid records whose `base` fields
match the known `addsi` evidence bases; they land exactly 10 records
starting at file offset `0xfb90 = 0xfa70 + VAR_BASE`, each separated by
the full `0x36` `ARR_BLOCK` stride, ending cleanly at the one-and-only
marker occurrence (`P = 0xfdb0`). **This brute-force "find every valid
static-slot record in the whole file, check they're `ARR_BLOCK`-spaced,
derive `ds` from the first one's position minus `VAR_BASE`" technique is
reusable and correct — reuse it directly, don't re-derive.**

Trace 1 concluded (WRONG, see trace 2): "every dc/pool_base candidate
fails finish()'s descriptor validation, driven by prompt_disps landing on
real scalar-band slots" and recommended building a probe with several
static arrays plus mixed prompted/bare INPUT statements. That probe was
built this session (trace 2) — **the INPUT angle was a red herring**: the
real reproducer below has zero INPUT statements.

### Trace 2 (2026-07-17, this session, later) — real reproducer found, root cause narrowed but NOT fixed

**Minimal oracle-verified reproducer** (`wild/probes_gap16/q_gap16q.bas`,
compiles clean via `oracle.compile_bas`, TB 1.1):

```basic
10 DIM P1(20)
20 DIM P2(20)
30 DIM P3(20)
40 DIM P4(20)
50 DIM P5(20)
60 DIM P6(20)
70 DIM P7(20)
80 DIM S1(20)
90 DIM S2(20)
100 DIM S3(20)
110 A% = 1
120 B% = 2
130 C = 1.5
140 D = 2.5
150 E# = 3.5#
160 F# = 4.5#
170 G% = 3
180 FOR I% = 1 TO 6
190 P1(I%) = I%
260 NEXT I%
270 H% = P2(1) + P3(1) + P4(1) + P5(1) + P6(1) + P7(1) + S1(1) + S2(1) + S3(1)
340 PRINT A%, B%, C, D, E#, F#, G%, H%
350 END
```

tbx currently mis-decodes this as a WRONG-but-passing layout (`n_static=9`
instead of 10, `scalars={}` — see below), which then blows up downstream
with `displacement 0x360 is neither scalar nor array element` instead of
failing loud at the layout stage. **This is worse than "not solvable": a
silently-wrong layout, only caught by luck when decode later touches a
disp `finish()` should have rejected.** `q_gap16c.bas` (the original,
larger 3-large-array probe from earlier this session) hits the exact same
root cause and DOES fail loud as "DGROUP layout not solvable" — both are
saved in `wild/probes_gap16/` along with `q_gap16o/p/r.bas`, the bisection
probes that pinned the trigger condition (see below).

**Trigger condition, empirically bisected** (all combinations compiled +
decoded, see the `wild/probes_gap16/` files and this session's transcript
for the full matrix): the bug needs **exactly 10 total static arrays**
*and* **a FOR loop with a literal limit** (step defaults to 1) in the same
program. Neither alone triggers it:
- 10 static arrays, no FOR loop → decodes fine (any size mix, large or
  small — tested up to 3 arrays of 2701+ elements).
- A FOR loop (literal limit/step) with static arrays present, `n_static`
  anywhere from 0 (no arrays, the existing `t1_forstep` fixture) through
  9 → decodes fine, REGARDLESS of whether the loop body indexes an array.
- 3 large arrays alone (no small ones, no FOR) → fine.
- 10 arrays + FOR loop → **always breaks**, independent of array sizes,
  independent of whether the loop body touches an array, independent of
  loop-body statement count (controlled for a separate, unrelated
  pre-existing gap below).

**A genuine new 48-byte DGROUP structure exists, confirmed byte-for-byte
identical (up to its two variable words) across three independently
compiled files** (`q_gap16c`, `q_gap16o`/`q`, and even the *already-passing*
`t1_forstep.exe` in a collapsed 4-byte form since it has zero arrays):
16 zero bytes, then `00 00 10 01` repeated 4× (16 bytes), then a
structured 16-byte tail that decodes as 8 LE words
`[scalar_band_width, sb, 0, sb+scalar_band_width, n_static, VAR_BASE, 0, sb]`
— i.e. it is *self-describing*: its own words equal independently-derived
quantities (`sb = VAR_BASE + ARR_BLOCK*n_static`, the scalar band's total
byte width, and `n_static` itself), not junk. Where this block sits
relative to `VAR_BASE` and the array grid, and how the *individual*
scalars (I%, G%, ...) end up addressed relative to it, is **not yet
resolved** — three internally-consistent-looking hypotheses were tried
this session and each contradicted real op evidence when checked further
(see below); do not trust any of them without re-verifying against fresh
byte dumps first.

**What's ruled out**:
- It is NOT the existing "disps below VAR_BASE are runtime system cells"
  case extended — the block's *content* references `VAR_BASE` and `sb`
  as literal words, which only makes sense if the compiler computed those
  values for *this specific program*, i.e. it's DGROUP-layout-aware
  compiler output, not a generic fixed runtime cell.
- It is NOT specific to array size (large vs. small) or to the loop body
  indexing an array — confirmed via the bisection matrix above.
- The three hypotheses tried and contradicted:
  1. "Array grid starts exactly at `ds+VAR_BASE` as always; ignore the
     block, it's below `VAR_BASE`" — contradicted because the real
     `pool_base` this implies (836) is too small to hold the independently
     scan-confirmed scalar evidence (G%, F#, E#, D, C, B%, A% all land at
     or above it, yet are clearly mutable scalars via `movm_imm`/`fstp`,
     not pool literals).
  2. "`vb` (var_base) shifts by +48, like the existing LINE box-fill
     `+4` case" — `find_statics` still finds all 10 records fine under
     this shift (it's tolerant of leading slop either way, so this is
     not a discriminating test), but it puts I%'s and G%'s real disps
     (834, 836) *inside* the shifted grid+block span, which cannot be
     right since they're independent live scalars.
  3. "The marker's own 4 bytes double as I%'s storage (extending the
     already-established 'marker cell doubles as an INPUT empty-string
     sentinel' precedent)" — self-consistent for `ds=0x8730`/`pool_base=
     836`/I% alone, but leaves G%/F#/E#/D/C/B%/A% unexplained (all land
     above `pool_base` under this `ds`, same contradiction as (1)).

**Do not guess further from hypothesis-fitting alone** — the fix needs
either (a) a byte-level disassembly of the actual FOR-loop prologue/NEXT
code (not just the op-stream disps already extracted) to see what
instruction, if any, references the 48-byte block directly (none of the
scanned ops in `q_gap16q`'s dump reference disps in the `[VAR_BASE-48,
VAR_BASE)` range at all — worth double-checking with `cfgview`/raw
disassembly whether the FOR-loop's *codegen* touches those addresses, or
whether the block is purely a linker/loader artifact nothing ever reads),
or (b) a systematic sweep varying ONE thing at a time from the
`q_gap16r.bas` (works, 3 arrays) baseline — add arrays one at a time up to
10 while re-checking the block's presence/size and the scalar disps' exact
addresses at each step, to find where exactly `n_static` crosses whatever
threshold matters (the working `q_gap16p.bas` has `n_static=9`; the
bisection never tried `n_static=10` with a MUCH smaller/simpler scalar set
(just `A%` and `I%`, dropping B%/C/D/E#/F#/G%) to isolate whether the
*number* of ordinary scalars, not just their presence, participates.

**Also still true from trace 1**: hfprop/vhfprop/inv87/invoice/schart are
untested against this session's finding (none re-compiled/re-diagnosed
this session; schart specifically should be re-examined for whether its
INPUT statements are a coincidence or whether `INPUT`/`LINE INPUT` codegen
is what plants a FOR-loop-shaped 48-byte block even without a literal
FOR — unconfirmed, worth checking first since schart has no FOR loop in
evidence but might use `FOR`-adjacent internal codegen for something else,
e.g. a hidden loop in string handling).

## Gap INT-8c — likely ON KEY GOSUB related, UNDIAGNOSED

3 wild files (baby.exe, help.exe, prtguide.exe, all TB 1.0): raw byte
`CD 86` (canonicalizes to vector 0x8C via TB 1.0's +6 vec_shift — see
`dialect.py`'s `canon_vec`) is unmapped in `_scan_int`'s vector table
(neighbors: 0x8A stack-test GOSUB, 0x8B stack-test RETURN, 0x8F DEF FN
terminator — 0x8C/0x8D sit in the gap between them).

**Strong lead, not yet confirmed**: all three files' ONLY event-trap
declarations are `ON KEY(n) GOSUB` (`on_trap` sub `0x78`="KEY") —
baby.exe alone has EIGHT of them (F1–F8 menu pattern) plus many
`trap_ctl 0x5A/0x5E` (KEY OFF/ON) toggles. This is the only common
thread found across the three files' surrounding context (which is
otherwise unrelated: CLS+assignment, COMMAND$/UCASE$+strassign, a
plain retf).

**Ruled out** (compiled via oracle, decoded clean, no `CD 86` anywhere
in the output):
- A single `ON KEY(1) GOSUB` + `KEY(1) ON` + assignment + PRINT (probe
  `q_onkey.bas`) — full ops dump has zero `cd 86` occurrences.
- `ON TIMER(1) GOSUB` + `TIMER ON` (probe `q_ontimer.bas`) — same event-
  trap mechanism, ruled out as a possible confusion with "sub 120".
- `A$ = UCASE$(COMMAND$)` alone (probe `q_cmdstr.bas`), matching
  help.exe's immediate preceding ops — no correlation.
- A plain FOR loop under the Keyboard-break ('K') toggle (probe
  `q_kbloop.bas`) — all three wild files carry 'K' too, tested as an
  alternate hypothesis, ruled out.

Also ruled out: two simultaneous `ON KEY` traps (`q_onkey2.bas`, 2
GOSUB targets + 2 `KEY(n) ON`) — still zero `cd 86` in the output.

**Not yet tried**: a statement INSIDE the GOSUB handler itself, since
the poll/check (if that's what this is) might only appear there and
none of my probes have exercised the actual handler bodies during
compilation (the handlers just PRINT+RETURN, same as the wild files'
likely shape, but maybe the trigger needs the trap to interact with
something specific inside the handler); baby.exe's EIGHT traps might
need a genuine threshold (more than 2) to manifest, which would be an
expensive/unusual thing for TB to gate on but not impossible; the
`trap_ctl` (KEY ON/OFF) SEQUENCE pattern in baby.exe is unusually
dense (interleaved on/off toggles across many lines) and might matter
more than trap COUNT. This gap has consumed several probe iterations
without success — worth checking whether help.exe's or prtguide.exe's
actual `.bas` source (if ever recoverable, e.g. via a shareware-archive
source listing) would shortcut the guessing.

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

**Full-routine trace (2026-07-17, this session)**: disassembled filepatc.exe
0x8870 through the `retf` with iced-x86 (raw instructions, not just the
leading bytes HANDOFF previously quoted). The full body, after the 7
`lds si,[bp+N]; mov <reg>,[si]` reads, is a textbook **CGA snow-avoidance
direct video-memory writer**: `mov dx,3DAh` (CGA status port) /
`in al,dx` / `rcr al,1` / `jb` spin-waits for the safe write window, then
`cli` / `in al,dx` / `and al,ah` / `je` re-checks display-enable, writes a
char+attribute word via `stosw` to `es:di` (the far pointer from
`bp+0Ah`/`bp+6`, i.e. the video segment:offset), `sti`, and loops
(`loop`) over the string read via `lodsb` from the buffer at `bp+1Eh`/
`bp+16h`. Two code paths (one with the snow-check loop, one — reached via
`je short 88D3h` when `ax==0`, presumably "not CGA" or "safe mode
detected" — a plain `lodsb`/`stosw` loop with no port polling). This
resolves the earlier "what does this SUB do" question definitively: it
is not ordinary arithmetic, it's an anti-snow text-mode blitter.

This also resolves **why `mov dx,[0]` matters**: `[0]` (DS:0000, disp 0,
below `VAR_BASE`) is read at entry and restored via `mov ds,dx` right
before the final `pop ds; pop es; pop bp; retf` — i.e. it's simply *this
program's own DGROUP segment value*, stashed by the runtime startup so
routines that clobber DS as scratch (every `lds` here reloads DS from
whatever far pointer it's dereferencing) can restore it before returning.
Generic runtime bookkeeping cell, not specific to this feature — no
longer worth chasing as a lead.

**Ruled out this session**: this routine is NOT part of any *always-linked*
runtime path — grepped the compiled byte signature (`55 8b ec 06 1e 8b 16
00 00`, proc_enter + push es + push ds + the DS:0000 read) against every
`.exe` in `tests/fixtures/corpus/`, including several `v10_*` (TB 1.0)
fixtures that do plain `PRINT`: zero matches. So it isn't emitted for
ordinary console PRINT under TB 1.0 — something more specific in
filepatc.exe's/morcalc.exe's/pw.exe's actual source triggers linking this
routine in, still unidentified. `cli`/`sti` rule out this being literal
user BASIC statements (TB exposes no CLI/STI-emitting construct) so it's
compiler/runtime-generated, likely the internal implementation of some
specific TB statement that blits multiple characters to text-mode video
memory directly (candidates not yet tried as probes: `VIEW PRINT` region
scrolling, `WIDTH`-mode-dependent fast PRINT, `PCOPY`, or a PUT/GET
variant operating on a text-mode "screen" rather than a graphics array).
Next step is still probe-driven: try each of those statements individually
compiled under both dialects and diff the output against this exact byte
shape, since guessing the decoder-side fix (generic LDS-based by-ref-param
read + DS-restore epilogue) without knowing the real trigger risks solving
the wrong shape.

(A previous version of this section carried a schart.exe DGROUP-layout
trace — that was a mis-filed duplicate of the gap-16 investigation, since
corrected and moved to the gap-16 section above; schart.exe is unrelated
to this byte-06/by-ref-param gap.)

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
