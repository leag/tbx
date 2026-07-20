# Wild-corpus gap campaign — handoff

Status as of 2026-07-19 (session gaps 46-66: line-table epic, nested
block-IF, DO un-synthesis, computed-int-array element family, array-element
SWAP (int + SINGLE), the modern `OPEN...FOR mode AS #n` syntax, LOF,
file-channel LINE INPUT, mixed-type relational compare, BLOAD with no
offset, `^` under TB 1.0, `SUB...INLINE` (embedded machine code, a new
feature not a gap), bare-value `DO...LOOP UNTIL/WHILE`, `CLOSE #variable`,
and a third materialized-boolean-test loop topology (tail-test loop body
ending in a nested `FOR...NEXT`)), branch `claude/claude-md-docs-mr8ssz`.
Standing instruction: close the most common decoder gap first, in frequency
order, over the 84 wild PC-SIG Turbo Basic EXEs in `wild/hits/` (untracked,
gitignored, copyrighted shareware — **never commit them**).

Machine-readable runtime-revision classifications are persisted separately from
generated scan checkpoints in `gap_reports/runtime-revision-assessments.json`.
Candidate status is not decoder authorization; each entry records its promotion
criteria and points back into this handoff for the full investigation.

Oracle performance checkpoint (2026-07-20): the vendored v86 harness now polls
for the DOS prompt, stable editor screen, and a stable compiled EXE instead of
sleeping a fixed 5+4+9 seconds. `compile_bas` uses a private temporary workspace,
so concurrent compiles cannot race on floppy/output paths. `batch_probe.py` adds
dependency preflight, immediate output, `--keep DIR`, and `--jobs N`. Byte-exact
verification passes for both dialects and `t1_nestif2`; a small compile improved
from roughly 25 seconds to 8.8 seconds, and two concurrent compiles finish in
8.9 seconds on this machine.

## Where things stand

84 wild EXEs: **14 decode OK** (ck, onelab87, onelabel, mm, autonum, rev,
startup, schart, r, book, inv87, invoice, metric, strpfind); the DEFxxx recovery
completed metric.exe. Every
closure below advanced files further into previously-unreachable territory
without fully finishing a NEW file, which is expected once the easy/common
gaps are gone and each file needs several more fixes to reach the end.
vhfprop.exe remains the only file blocked purely by the line-table epic
(see "vhfprop status" below, unchanged this session).

**`OPEN file$ FOR mode AS #n` was the session's biggest single closure**:
16 of 84 files were blocked on it alone (tied top of the tally at session
start). Fresh tally (2026-07-19, after LOF/LINE INPUT#/array-SWAP/
OPEN-FOR-AS/icomp/bload0/pow10/inline/orax/closevar/nestfor — re-scanned
via `uv run python tbx/tools/scan_wild.py wild/hits`, still 72 TB-but-fail):

| count | error | status |
|---|---|---|
| 6 | byte 90 | confirmed unwitnessable (prior sessions) — not actionable |
| 5 | byte ea | ">64K" theory refuted (prior session) — undiagnosed, not just "big lift" |
| 4 | byte 89 | INVESTIGATED THIS SESSION, NOT LANDED — 3 of the 4 (catalog/pfl/process/kinder — a 4th, kinder.exe, joined mid-session) share one root cause, see the gap section below: generic `movrr`'s register table is missing `di`; fix written, tested (advances cleanly), then REVERTED per the calibration rule since no probe reproduces it. A STRONG new lead (SCREEN()+`\`/MOD) was found for kinder.exe specifically, narrowing the search a lot — see the gap section's addendum. CVT2TB.EXE's own byte-89 hit is UNRELATED — it's actually gap 19/byte-06 (CGA blitter) in disguise. |
| 3 each | INT EC sub 4c; INT 8c; byte 06; INT EC sub 38; "unreferenced pooled string literals" | sub 4c undiagnosed (file#+ax-int statement, LOCATE/WIDTH-file guesses both ruled out); INT 8c / byte 06 extensively probed in prior sessions, still undiagnosed; INT EC sub 38 (gap 33) grew 2→3 this session — varamort.exe joined once its unrelated BLOAD-offset gap closed, see Gap 33 below; the pooled-string-literals one is the known FRE(s$) case (hfprop/number/tamstart), undiagnosed, no dedicated writeup yet |
| 2 each | INT EC sub ac/42; INT ce; FP dc/04, da/1c; byte f7/8c/8b/1e/0b; system cell 0x8a | mostly untouched |
| 1 | "codeless DO...LOOP WHILE/UNTIL ... unwitnessed" (vhfprop) | unchanged, see "vhfprop status" below |
| singles | see scan output | untouched; freshest one is metric.exe's new stop, "error-trap line table has a codeless-statement entry but no DATA pool was found (unsupported zero-length-statement shape)", surfaced immediately by this session's nested-FOR-loop fix, not yet investigated |

## THE LINE-TABLE EPIC (read this first)

Real wild programs have **multi-statement lines**, original line numbers
that are BYTE-SIGNIFICANT (error-trap line table present: ON ERROR/
RESUME/ERR), **codeless statements** (DATA, static-array DIM — REM and a
bare `::` are NOT codeless, confirmed NOT to produce a table entry), and
**numbered block-IF interior lines** jumped into from anywhere (gap 51
closed the single-level case; inv87's remaining stop needs the nested
case, still open).

### CLOSED this session: DATA and static-DIM orphan recovery

`_line_table` (layout.py) now returns `(ent, orphans)` instead of a bare
dict: a codeless statement borrows the code offset of whatever REAL
statement follows it, so two-or-more table entries can share ONE offset
(`_line_table`'s old strictly-increasing check rejected the whole table
outright over this — now tolerates equal offsets, last-entry-per-offset
wins for `ent`, the superseded ones collect in `orphans` in table order).

Two DIFFERENT statement kinds turned out to be codeless-with-a-table-entry
(both witnessed against vhfprop.exe's actual "500,500,502" triplet at file
offset 0xc2c8, decoded via a temporary debug patch to `_finalize` — see
git history of this commit for the probe/patch technique if needed again):

- **DATA with no READ/RESTORE anywhere in the program** (`core.py`
  `_finalize`): previously `_read_data_pool` only fired when Read/Restore
  IR existed, so such DATA silently vanished from the IR. Now an early
  `_line_table` probe (computed BEFORE dims/DATA/COMMON/TRON synthesis
  touches `state.addrs`, since `state.stmt_addr` is already fully
  populated by then) also triggers recovery from orphan evidence alone.
  The item/statement split point among recovered items is UNRECOVERABLE
  from the pool itself (probe q_lt4, saved as fixture material: `DATA 1:
  DATA 2,3,4` compiles BYTE-FOR-BYTE identical to `DATA 1,2: DATA 3,4` —
  only the STATEMENT COUNT and each one's LINE are byte-significant), so
  every recovered statement but the last gets exactly one item. DATA also
  compiles in TEXTUAL/compile order, not pool order (probe q_lt3: naively
  prepending it at the top, the pre-existing convention for the READ-
  triggered path, byte-diffs the table once DATA's own line matters) — it
  now gets spliced immediately before whichever statement shares its
  borrowed offset. Fixture `t1_dataorph`/`v10_t1_dataorph`.
- **Static array DIM declarations** (`core.py` `_finalize`, the `dims`
  list): these are recovered from array bookkeeping records, not a
  scanned op at all, and were ALWAYS repositioned to a canonical spot
  ("static DIMs follow any proc definitions") — fine under free
  renumbering, wrong once DIM's own line is byte-significant. When
  `len(dims) == len(data_orphan_lines)` in a single offset cluster, dims
  are now repositioned + relined from that evidence instead (vhfprop:
  two static arrays, exactly two orphan "500" entries). Fixture
  `t1_dimorph`/`v10_t1_dimorph`.

Both fixtures byte-exact verified both dialects via the oracle. Multiple
SEPARATE codeless-statement clusters in one table, or a RESTORE split
colliding with orphan evidence, are explicitly rejected (fail loud, no
witness) rather than guessed — narrow the check if a future wild file
needs it.

### vhfprop status: bare-DO un-synthesis CLOSED for unconditional loops; the WHILE/UNTIL case is a genuinely new, still-open puzzle

`core.py`'s "bare backward jmps = infinite DO" path ALWAYS canonicalized
a backward jump loop into synthesized `ir.Do(None)` + `ir.Loop(None)`,
regardless of whether the ORIGINAL source spelled it `DO...LOOP` or was a
plain `GOTO`-based loop — both compile to IDENTICAL bytes. Fixed this
session (see "Un-synthesize bare-jmps DO..." in Recently Closed): DO,
like DATA/DIM, gets its OWN codeless line-table entry, so when the table
is active and shows NO orphan evidence at the loop's borrowed offset,
the Do/Loop pair is un-synthesized back to a plain Goto. Verified
byte-exact (fixtures `t1_gotoerr`/`t1_doerr`).

**vhfprop.exe itself is STILL blocked**, on a narrower, different case:
BOTH its loops turned out to be tail-test (`Do(None)` paired with a
CONDITIONAL `Loop("WHILE"/"UNTIL", cond)`, from `_lift_do_tail`'s
materialize-then-backward-jcc byte template — NOT the simple
unconditional case above), and NEITHER has orphan evidence (confirmed:
`ent[0xf62]=600`, `ent[0x1100]=722`, single entries, no duplicates, in
vhfprop's validated 734-real-entry table). The line-table EVIDENCE says
"no DO was here" just as clearly as for the unconditional case — but
**every constructed probe that reaches `_lift_do_tail`'s exact byte
shape does so ONLY via a genuine `DO...LOOP WHILE/UNTIL` in source**:
tried a plain `IF compound THEN GOTO earlier` with integer operands
(hit an unrelated gap, `int compound relational jcc 7f`, not yet
supported for signed comparisons), with float operands (single and
compound-OR condition, both resolved through the SHORT-CIRCUIT
compound-IF machinery — gap 47 — never through `_lift_do_tail`). No
witnessed non-DO construct produces the tail-test shape, so
un-synthesizing it (WHILE: a plain IfGoto; UNTIL: needs De Morgan
negation of what might be a compound LogOp, unwitnessed and harder
still) would be guessing against the calibration rule, DESPITE the
suggestive table evidence. `core.py` now raises a specific, clear error
for this case rather than either crashing obscurely or silently risking
a wrong byte. **Next step for a future session**: find what OTHER
BASIC construct (not yet tried: `WHILE...WEND`, an `EXIT DO/LOOP`
interacting with the tail test, a compound condition used as a VALUE
elsewhere that happens to feed into the same materialize infrastructure,
CALL/GOSUB-adjacent control flow) produces `_lift_do_tail`'s exact byte
template without a genuine DO — or, failing that, treat this as a
deliberately accepted gap and move to something else. vhfprop.exe was
also unblocked at fully decoding briefly during this session's
investigation and hit a SEPARATE, apparently pre-existing "Error 431:
End-of-line expected" issue elsewhere in the file when attempting the
oracle round-trip — bisection narrowed it to somewhere in BASIC lines
907–4600ish (large region, mostly array-literal DATA assignments, not
yet isolated further) — a DIFFERENT gap, unrelated to the DO work,
worth investigating once vhfprop reaches full decode again.

### CLOSED: inv87.exe/invoice.exe's nested block-IF GOTO target

inv87's error-trap line table turned out to NOT RESOLVE AT ALL
(`_line_table` returns `None` for it — confirmed via the debug-patch
technique) — so the originally-planned "use the line table to resolve
nested interior targets directly" path was a dead end for this file
specifically (never diagnosed WHY the table doesn't validate; wasn't
needed once the alternative path below worked). Went with generalizing
the EXISTING single-level `ir.BodyLine`/gap-51 mechanism to nested
blocks instead — see "Nested block-IF GOTO targets" in Recently Closed
below for the full four-part fix. inv87.exe and invoice.exe both decode
completely and byte-exact-verify now (fixture `t1_nestif2`).

### Reproducing the investigation

The probe technique that worked all session: monkeypatch
`tbx.decode0.core._finalize` (or just temporarily edit the `except
(KeyError, TypeError): raise ValueError(...)` block near the end of
`_finalize` to print `state.stmts`/`state.addrs` around a `None` entry)
to see exactly which statement/offset a wild file's table lookup chokes
on, then author a MINIMAL `.bas` probe reproducing that exact shape,
compile via `oracle.compile_bas`, and diff its raw line table (`struct.
unpack_from("<HH", exe, p)` scan for the `(3, first_line)` marker) against
hand-written hypotheses. Revert any temporary debug prints before
committing — `git diff tbx/decode0/core.py` should show only the
intended, permanent change.

## Ongoing plan (priority order — pick up at the first incomplete step)

1. **vhfprop's tail-test DO...LOOP WHILE/UNTIL un-synthesis gap** (above)
   — the ONLY file left blocked by the line-table epic; the unconditional
   case is closed, this narrower WHILE/UNTIL case needs a witnessed
   non-DO source construct before it can be un-synthesized safely.
2. **Byte 89 / missing `di` spill register (4 files)** — see the gap
   section below FIRST, before touching any code: the exact fix (4
   small diffs) is already written out verbatim there, tested working
   against real wild files, but reverted for lack of a witnessed probe.
   Start with kinder.exe's SCREEN()+`\`/MOD lead (the addendum at the
   end of the gap section) — it's the most tractable of the four by far,
   already reproduces the shallow 2-register case exactly, just needs
   one more nesting level found. This is almost certainly the fastest
   actionable closure in this list if a probe can be found — don't
   re-derive the mechanism, just find the trigger construct.
3. **INT EC sub 4c (3 files, NEW)** — see the gap section below. Evidence:
   `[0060]=1 (file#); mov ax,<int var>; INT EC sub 4c` (raw 0x4A in TB
   1.0), immediately after an `X = LOF(1)` + `ON ERROR` pair, with no
   inline operand bytes on the INT itself. Ruled out: `WIDTH #n,cols`
   (compiles to a DIFFERENT unhandled sub, EC f0 — a distinct future
   gap, not this one) and bare `LOCK #n` (not valid TB syntax without a
   range). Untried: `LOCK #n, range`/`UNLOCK #n, range`, `RENAME`-
   adjacent ops, a record-count/position statement tied to the
   just-computed LOF result.
4. **INT ce (2 files, NEW)** — see the gap section below. Evidence:
   `LOCATE 20,1; CURSOR 1; bx=0; ax=7; INT CEh` (canonical, 2 raw bytes,
   no inline operand) in billadd.exe/file.exe. Ruled out: not the
   single-byte `INTO` (0xCE, no CD prefix) which is already handled
   separately. Untried: full probe sweep of screen-attribute/character-
   at-cursor statements with a fixed bx=0,ax=7 argument shape.
5. **Byte ea (5 files)** — the ">64K" theory is refuted (see the gap
   section below); try reproducing elec87.exe's exact shape (a large
   FLAT string-comparison chain alongside whatever else that 155KB
   program does) before guessing further.
6. **INT 8c (3 files)** — ON KEY GOSUB lead; a follow-on statement INSIDE
   the trap handler body (not more traps/toggles) is the next untried
   category.
7. **Byte 06 / gap 19 (3 files)** — CGA snow-avoidance blitter; VIEW
   PRINT and PCOPY are ruled out (not real TB keywords); text GET/PUT is
   the remaining untried candidate.
8. **The 2-tier** — re-tally after each closure; for FP gaps check the
   `[si]` FP table for missing rows first.
9. Singles last, same workflow. Byte 90 (6 files) and INT cd (formerly
   16, now CLOSED — was `OPEN...FOR mode AS #n`, see Recently Closed)
   — byte 90 remains fully confirmed unwitnessable, skip it.

## Recently closed (this campaign, newest first)

- **Bare `FILES` / canonical INT EC sub 42** (2026-07-20): both TB 1.0
  wild hits call the dispatcher with no prepared operand; `styled.exe` also
  contains the adjacent, already-known sub 44 form with a pushed filespec in
  the same routine. A minimal `FILES` probe reproduces sub 42 directly. `Files`
  now carries an optional spec, renders the bare spelling, survives canonical
  rename, and maps to `*.*` in the behavioral C backend. Fixtures `t1_files0`/
  `v10_t1_files0` are oracle byte-exact. Both wild files advance to the same
  later `cursor call without open LOCATE` fold gap. Full suite: 2193 passed,
  14 skipped.
- **Binary `GET$ #file,count,string$` / INT EC sub 4c** (2026-07-19):
  the previously unknown sub is the binary-file string read. `GetString`
  carries the file number, AX count expression, and following string target;
  fixture `t1_getstr` is oracle byte-exact. `strpfind.exe` now decodes fully;
  `be.exe` and `pwinst.exe` advance to their next distinct gaps.
- **Large shared literal/DATA pool and multiple codeless clusters**
  (2026-07-19): the framed character record uses a 15-bit
  `length|0x8000` word, not an 8-bit length. Unreferenced descriptors in
  that shared pool are DATA items when no `fre_str` sites exist; they are
  stored in reverse source order. `_finalize` now places DATA statements at
  multiple borrowed offsets and canonicalizes excess payload-free entries
  as DEFxxx declarations. Fixture `t1_databig` combines a >255-byte pool,
  DATA+DEF at one host, separate DEF clusters, READ, and an error table;
  oracle byte-exact. This closes the former six-file “unreferenced pooled
  string literals” bucket (file/hfprop/kinder/number/pfl/tamstart), all of
  which advance to later gaps, while metric.exe remains fully decoded.
- **Five-argument `LOCATE row,col,cursor,start,stop` / INT CE**
  (2026-07-19): the previously unknown two-byte INT CE immediately follows
  LOCATE's existing INT CF row/column and INT D0 cursor calls; its bx/ax
  operands are the cursor scan-line start/stop arguments. `ir.Locate` now
  carries and renders both optional fields. Fixture `t1_locate5`, oracle
  byte-exact. All three wild hits advance: file.exe and kinder.exe reach the
  shared unreferenced-FRE-string gap; billadd.exe reaches INT C2.
- **Three-argument `SCREEN(row,col,color)` / INT ED sub 44** (2026-07-19):
  row/column/color arrive in cx/bx/ax. Fixture `t1_screen3`, oracle byte-exact.
  kinder.exe advances to the LOCATE/INT-CE gap above and sabpcv3.exe advances
  to byte EA.
- **Deep integer-expression spill through DI / byte 89** (2026-07-19):
  `movrr` now recognizes DI as the fifth symbolic register; both shuttle
  sites and relational-value lookahead handle arbitrary spill runs. Minimal
  fixture `t1_dispill` uses a nested SCREEN call while a divisor is live,
  oracle byte-exact. pfl.exe advances to the FRE-string gap; kinder.exe to
  SCREEN sub 44. catalog.exe/process.exe advance to their separately
  documented deeper memory-backed spill (`mov [disp],di`), still open.

- **`DO...LOOP WHILE/UNTIL` whose body ends in a nested `FOR...NEXT`**
  (2026-07-19): a third loop topology for the "materialized boolean
  test" byte template (`movax 0xFFFF; jcc; incax; orax; jcc[; jmp]`),
  alongside the existing head-test (`_lift_while`) and tail-test
  (`_lift_do_tail`) cases. This one syntactically matches `_lift_while`'s
  6-op head-test template (trailing jmp present) but with INVERTED
  polarity: the jcc exits forward, and the trailing jmp -- itself
  backward -- IS the retry edge, rather than a separate `jmps` found via
  `_has_jmps_back` elsewhere in the body. The trigger (a nested
  `FOR...NEXT` as the last thing in the DO-loop body, which leaves no
  separate backward-jmp for `_has_jmps_back` to find) was only found by
  reading the full `stmts` context leading up to the failure, not just
  the raw `ops` -- several earlier probes (SUB-ending, DEF FN-ending,
  GOSUB-ending tail-test loops) had ruled out simpler theories without
  reproducing it. `_lift_while` gained the new branch ordered BEFORE the
  existing inline-IF branch (a backward `exit_jmp` can never legitimately
  be a genuine inline-IF's forward body-skip, so this doesn't shadow real
  inline-IF cases -- confirmed via full suite, zero regressions, plus two
  dedicated probes covering both polarities). Closed wild metric.exe's
  blocking gap (the file now surfaces a new, not-yet-investigated one).
  Fixtures `t1_nestfor`/`v10_t1_nestfor` (WHILE polarity),
  `t1_nestfor2`/`v10_t1_nestfor2` (UNTIL polarity).
- **`CLOSE #variable`** (2026-07-19): `CLOSE` had only ever been
  witnessed with a literal file number. `ir.Close.num` now holds either a
  plain `int` (existing literal case) or an `Expr` (new variable/
  expression case), mirrored across rename.py/render.py/c0.py. Fixture
  `t1_closevar`/`v10_t1_closevar`.
- **`DO...LOOP UNTIL/WHILE` on a bare numeric value** (2026-07-19): `or
  ax,ax` testing a just-computed value's truthiness directly, no
  preceding compare -- wild metric.exe, `DO: K$=INKEY$: LOOP UNTIL
  LEN(K$)`. Shorter than `_lift_do_tail`'s usual template (which needs
  an explicit compare to materialize -1/0 first); byte-exact confirmed
  the explicit `LOOP UNTIL LEN(K$) <> 0` form compiles DIFFERENT bytes,
  so the bare-vs-explicit distinction must be preserved, not
  normalized. `ir.Loop.cond` can now hold a bare expression;
  rename.py's `walk_cond`/render.py's `unparse_cond` needed a fallback
  (both crashed loudly on the first attempt -- exactly the fail-loud
  behavior wanted over a silent wrong render). Also added `SUB ...
  INLINE` support (embedded raw machine code, Appendix C of the
  handbook) at the user's request -- see the dedicated `$INLINE`
  reference section below for the full story, including a false
  positive the mechanism's safety check caught and fixed against
  CVT2TB.EXE. Fixtures `t1_orax`/`v10_t1_orax`, `t1_inline`/
  `v10_t1_inline`.
- **`^` (exponentiation) under TB 1.0** (2026-07-19): dialect.py's own
  docstring predicted this ("TB 1.0 encodes ^ without an ED sub"; TB 1.1
  uses ED sub 3A/fpow). TB 1.0's actual mechanism is INT 3Eh
  (transcendental dispatcher) selector 0x14 -- byte-identical operand
  push order to fpow's, so it aliases onto the existing `fpow` op kind
  rather than needing new logic. Closed wild banker.exe/kinetics.exe.
  Side finding, waived in test_c0.py rather than chased: TB's own `^`
  runtime rounds the exponent to the nearest integer before computing
  (confirmed via the oracle: 2.5^1.5 AND 2.5^1.9 both print 6.25 =
  2.5^2) -- a genuine bug in Borland's math library, not handbook
  semantics; c0 keeps true fractional exponentiation via C's `pow()`.
  Fixture `t1_pow10`/`v10_t1_pow10`.
- **BLOAD f$ with no offset argument** (2026-07-19): INT EC sub 04, a
  genuinely distinct compiled shape from sub 06's with-offset form (no
  FP-stack pop at all). `ir.Bload.offset` now defaults to `None`; the
  emitter omits the trailing comma when unset. Closed wild
  varamort.exe/kinder.exe's `DEF SEG = &HB800` + bare `BLOAD` video-
  memory-load idiom. (Tangent worth knowing about: the ORIGINAL probe
  used `DEF SEG = &HB800`, and recompiling the DECOMPILED source, which
  necessarily re-emits that as plain decimal `-18432`, did NOT
  byte-match -- TB compiles a negative HEX literal as a direct pooled
  constant but a negative DECIMAL literal as `mov ax,imm; neg ax` at
  runtime, two different byte shapes for the identical value. Sidestepped
  by using a positive DEF SEG value in the fixture instead of chasing
  that separately; it's a real, currently-undocumented-elsewhere
  literal-spelling gap that could bite a future DEF SEG/negative-literal
  fixture -- worth a dedicated look if it resurfaces.) Fixture
  `t1_bload0`/`v10_t1_bload0`.
- **Mixed-type relational compare (int var vs FP-stack value)** (2026-07-19):
  `IF A% > B THEN` where A% is INTEGER and B is SINGLE/DOUBLE forces
  int->FP promotion for the comparison: B pushed via `fld`, then A%'s
  slot compared via ESC DEh /3 (modrm 1E) -- the m16-int compare sibling
  of D8h /3's already-handled `fcomp`, simply missing from the disp16
  kind table. New `icomp` op resolves its memory operand (var slot or
  pooled int literal) via the exact same expression already calibrated
  for `ifold`/`ifold_n`. Closed wild grdscn/kinder/night/pfl/stat (all
  advance further). Fixture `t1_icomp`/`v10_t1_icomp`.
- **LINE INPUT #n, var$** (2026-07-19): the file-channel sibling of
  console LINE INPUT. `cd ec 66` (canonical; no operand -- unlike sub
  64's `cd ec 64 <prompt_desc> 40`, there's no prompt for a file read)
  + the same `movsi; strassign` consumer, with `[0060]` carrying the
  file number like OPEN/PRINT#/INPUT#. `ir.LineInput` grew a `file`
  field (mutually exclusive with `prompt`). c0.py gained
  `tb_finput_line` (whole line, no comma/quote parsing, unlike
  `tb_finput_str`). Closed wild billadd/crossref/file/grdscn/strpfind
  (all also needed for the earlier gaps in this session's chain).
  Fixture `t1_lineinf`/`v10_t1_lineinf`.
- **LOF(n)** (2026-07-19): surfaced immediately by the OPEN-FOR-AS fix
  below. INT ED sub 26, filenum in ax like EOF (sub 10), but unlike
  EOF's boolean the file length can exceed 16 bits, so the result comes
  back on the FP stack (`fn_axfp`, same shape as FRE(n)/sub 18) instead
  of in ax. c0.py gained `tb_lof` (ftell/fseek round trip). Fixture
  `t1_lof`/`v10_t1_lof`.
- **`OPEN file$ FOR mode AS #n`** (2026-07-19) — **the session's biggest
  single closure, 16 of 84 files**. All 16 hit "unhandled INT cd"
  (canonical; raw C7 in TB 1.0) at wildly different addresses, but the
  preceding bytes were byte-identical across every one: `movsi <str>;
  rt 9C` (push a filename) then `mov word[002Eh], (char<<8 | 1); INT
  CDh`. The packed word's high byte is always an uppercase letter --
  confirmed via oracle probes (`OUTPUT`/`INPUT`/`APPEND`/`RANDOM`/
  `BINARY` -> `O`/`I`/`A`/`R`/`B`) to be the FOR-keyword form of OPEN
  desugaring its mode to a compile-time 1-char string at a fixed
  scratch cell instead of a real pooled literal, materialized by a new
  bare `INT CDh` ("shortstr") vector. NOT byte-identical to the comma
  form (different push order, +16 bytes), so `ir.Open` grew a `for_as`
  flag and the emitter reproduces the original FOR-keyword spelling
  rather than normalizing. **Trap for next time**: `rename.py` rebuilds
  IR nodes on the rename pass and had ALREADY silently dropped a new
  field once before (`for_as` itself, caught by the oracle byte-exact
  check) — when adding a field to an existing IR node, grep
  `rename.py` for that node's rebuild site immediately, don't wait for
  the byte-exact check to catch it (it *did* catch it here, so no
  wrong output shipped, but it cost a debugging round trip). Fixture
  `t1_openfor`/`v10_t1_openfor`.
- **SWAP of two computed SINGLE (4-byte) array elements** (2026-07-19):
  extends the int-array SWAP tail (below) to 4-byte elements -- after
  the low-word swap, a second round at a fixed +2 byte offset handles
  the high word (`far_movax_bx2`/`xchgsi2`/`far_movm_ax_bx2`). Gated on
  `ao==2` (double `shl si,1`, the existing 4-byte-stride signal); 8-byte
  DOUBLE (`ao==3`) is left to raise, unwitnessed. Fixture
  `t1_arrswapf`/`v10_t1_arrswapf`.
- **SWAP of two computed static-int-array elements** (2026-07-19):
  closes number.exe's next stop after the array-access family below.
  The compiler can't XCHG two memory operands directly, so it spills DS
  to a scratch cell (`movm_ds`, `mov [disp16],ds`) while the first
  operand's index chain is still live in SI, computes the second
  operand's address, restores DS into ES from that cell (the existing
  `moves_m` op, now ALSO a valid shlsi consumer), then does the swap
  through the ES alias: `mov bx,ax` (a second, `8B D8` encoding of the
  existing `movbxax`) / `mov ax,es:[bx]` (`far_movax_bx`) / `xchg
  ax,[si]` (`xchgsi`) / `mov es:[bx],ax` (`far_movm_ax_bx`). New
  `DecodeState.pend_swap` stages the first ArrayRef across the second
  operand's own shl/addsi chain. The new `movm_ds` byte pattern (`8C
  1E`) collides with bare DEF SEG's `mov [001C],ds` -- reordered so the
  disp==0x1C-specific check keeps priority. Also fixed c0.py's SWAP
  lowering, which assumed both operands were plain Vars. Fixture
  `t1_arrswap`/`v10_t1_arrswap`.
- **Computed-int-array cmp/add + shlsi gatekeeper fix + compound
  subtract** (2026-07-19): `cmp ax,[si]`/`add ax,[si]` complete the
  computed-static-INTEGER-array-element family alongside movm_ax_si/
  movax_si. Exposed a foundational bug: shlsi's gatekeeper required 2-3
  consecutive `shl si,1`, silently barring the single-shl (2-byte
  INTEGER stride) case PROJECT-WIDE -- fixed to accept 1-3 shifts. Also
  `sub [disp16],ax` (subm_ax), the subtract sibling of addm_ax. Wild
  number.exe. Fixtures `t1_arrwrite`/`t1_arrread` (rebuilt -- the
  originals accidentally used default-SINGLE `DIM A(10)`, masking the
  gatekeeper bug via the unrelated float path), `t1_arrcmp` (new),
  `t1_subm` (new).
- **Un-synthesize bare-jmps DO when the line table shows no DO** (2026-07-18):
  the "bare backward jmps = infinite DO" canonicalization (an explicit
  `DO...LOOP` and a plain `<n> ... GOTO <n>` compile identically, so the
  decoder always picked DO) turns out to be lossy once a line table is
  active, same root cause as the DATA/DIM orphan work: DO gets its own
  codeless table entry a plain GOTO loop never had. `core.py` now pairs
  every synthesized bare Do with its closing Loop by nesting order (a
  stack tracking ALL Do/Loop pairs, including head-test ones, so a
  head-test DO's own bare closing Loop can't get mismatched to an
  unrelated bare Do sitting deeper on the stack), and un-synthesizes an
  UNCONDITIONAL Do/Loop pair to a plain Goto when the table shows no
  orphan at the loop body's borrowed offset. Byte-exact verified.
  Fixtures `t1_gotoerr` (the un-synthesized case) / `t1_doerr` (a
  genuine DO, confirming it's untouched and still gets its own line
  from real orphan evidence). Deliberately does NOT cover the
  conditional (WHILE/UNTIL) tail-test case — see "vhfprop status" above
  for why that one stayed open despite the same suggestive table
  evidence. Wild scan stayed at 12 (this fix's own witnessed case
  doesn't happen to be the thing blocking any currently-failing wild
  file, including vhfprop, which needs the WHILE/UNTIL case).
- **Nested block-IF GOTO targets** (2026-07-18, closes wild inv87.exe/
  invoice.exe): a GOTO into a numbered line nested TWO block-IF levels
  deep needed four compounding fixes (gap 51 only reached a single-arm
  block IF's direct body): (1) `_fold_body_ifgotos` (the "IF c THEN
  <line>" nested-inline-IF negation) discarded the consumed IfGoto's
  own recorded address when replacing it with the negated IfInline,
  orphaning `stmt_addr`'s id-based lookup for anything at that position
  — now propagates the address to the replacement node; (2)
  `_fold_if`/`_fold_body`'s "second leg" (forces a still-inline IF into
  block form when its interior is a jump target) only checked DIRECT
  body children, not recursively through an already-nested-but-still-
  inline IF — new `_body_has_target` helper recurses; (3)
  `_resolve_targets`'s BodyLine-mapping walk was single-level only — it
  now recurses into a nested single-arm no-else IfBlock (header +
  recursed body + END IF are fully accounted for, so flat phys counting
  safely continues past it — unlike multi-arm/ELSE/SelectCase/SubDef/
  DefFn, whose width still isn't computed, so those keep blocking
  further counting exactly as before); (4) emit0's free-renumbering
  used a flat 10-line stride, too narrow for a deep phys offset — now
  widened only for statements that actually need more room (no golden
  changes; only kicks in once phys >= 10). c0 doesn't support this
  shape yet (its label loop tracks a local per-body position, not the
  decoder's flat phys count) — raises `_Unsupported`, waived in
  test_c0.py. Byte-exact verified both dialects. Fixture `t1_nestif2`/
  `v10_t1_nestif2`. Wild scan: 10 → 12 decode-ok — this was ALSO the
  line-table epic's other open sub-problem, now closed, leaving
  vhfprop.exe as the epic's only remaining file.
- **Gap 54: COLOR's third (border) argument** (2026-07-18): the
  3-argument GW-BASIC-style `COLOR fg,bg,border` sets an extra mask bit
  (0x01, cell 0xA0) that `color_commit` never accounted for (only fg
  0x04/0x88 and bg 0x02/0x94 were known), tripping the "unaccounted
  cells" check. `ir.Color` gained a `border` field; `render.py` now
  builds the comma list up to the highest set argument generically
  (handles a border-only `COLOR ,,n` too) instead of special-casing a
  third slot; c0 raises `_Unsupported` for a set border (CGA border
  strip has no visible effect in the PPM/SDL surrogate, but silently
  dropping an explicit source value would be a mistranslation) — waived
  in `test_c0.py`. Fixture `t1_color3`/`v10_t1_color3`. Closed wild
  r.exe/book.exe fully. Wild scan: 8 → 10 decode-ok.
- **Byte 90, all 5 occurrences confirmed unwitnessable** (2026-07-18):
  rstprint.exe's occurrence (the one HANDOFF previously flagged
  "undiagnosed whether it's the same shape") hexdumps to the EXACT same
  `90 90` (two real x86 NOPs) immediately before `mov ax,[002C]` as the
  other 4 already-set-aside files — same CINT-style float-to-int
  round-trip synchronization point, same runtime-revision-skew category
  as the documented INT CD gap (see `wild-tb-corpus.md` memory for the
  original investigation). No code change; just settles the "is it the
  same shape" question. Not actionable without a differently-revisioned
  oracle.
- **Line-table epic, DATA/DIM orphan recovery** (2026-07-18, see the full
  "THE LINE-TABLE EPIC" section above for details): `_line_table` now
  tolerates codeless-statement duplicate offsets instead of rejecting the
  whole table; DATA-without-READ and static-array-DIM statements are both
  now recovered/repositioned from that evidence when a line table is
  active. Fixtures `t1_dataorph`/`t1_dimorph` (+v10). Did NOT close any
  wild file outright — vhfprop advances to a narrower, still-open bare-DO
  issue; inv87/invoice not yet retried against this fix.
- **Gap 53: cmpax_m AND-chain 2nd+ term ax<->bx shuffle** (2026-07-18):
  an OR-compound IF condition (t1_orchain, gap 47) resolves by pure
  short-circuit jumps, no accumulator. An AND-compound condition's 2nd+
  term genuinely combines via a real `and ax,bx`, so the compiler
  round-trips the running boolean through bx with a byte-exact no-op
  shuffle (`mov ax,bx; mov bx,ax`) sandwiched between `cmpax_m` and the
  `mov ax,-1` value materialization; `cmpax_m`'s value-form lookahead now
  recognizes that shuffled shape too, letting the generic movrr/movbxax
  handlers process the housekeeping before the existing pend_icmp ->
  pend_cmp -> `_lift_bool_tail` chain resumes unchanged. Fixture
  t1_andchain/v10_t1_andchain (`IF ERR = 25 AND ERR = 27 AND ERR = 57
  THEN ...`). Closed wild schart.exe's "cmpax_m without a value/IF
  consumer" stop — schart now decodes COMPLETELY (9th wild decode-ok) but
  does NOT round-trip byte-exact yet (multi-statement ON ERROR line
  table, `Program.lines` stays `None` — the same line-table epic blocker
  as vhfprop, not a new issue).
- **Gap 52: leading/doubled PRINT commas** (2026-07-18): schart.exe opens
  PRINTs with bare zone-advances (`PRINT ,,X`) and doubles commas between
  items. `ir.Print.commas` migrated from items-aligned bools to GAP-aligned
  comma counts (len(items)+1 slots); C1 handler opens a pend_print on a
  leading console comma. `PRINT A$,,` (trailing) merges with the next
  statement's items byte-identically — canonicalized to the merged form.
  Fixture t1_pcomma2.
- **Gaps 50-51: 64KB segment wrap; GOTO into block-IF interior**
  (2026-07-18): (50) GOTO/GOSUB spanning >32KB encode wrapped signed rel16;
  scan now normalizes e9/e8 targets into [start, start+64K) — fixture
  t1_bigjmp, a 2800-statement program. (51) TB accepts a NUMBERED line
  inside IF..END IF as a jump target; inline-IF regions force block form
  when a body statement's addr is jump-targeted (_fold_if grew a stmt_addr
  param), short backward jmps into folded bodies lift as Goto("addr"),
  _resolve_targets extends ir.BodyLine to single-arm IfBlock interiors,
  emit0's existing body-line numbering renders it; c0 uses a function-
  scoped C label. Fixture t1_blkgoto. Both from inv87.
- **Gap 49: 3-arg MID$ clobbered DecodeState.start** (2026-07-18): the
  MID$(s$,start,len) branch wrote the start ARG into state.start (the
  user-code start address); any later error-trap line-table use crashed.
  One-line fix; vhfprop.exe then decoded COMPLETELY (8th wild decode-ok).
  Fixture t1_miderr.
- **Gap 48: _is_for_header crash on trailing string assigns** (2026-07-18):
  GOTO after three consecutive string assigns probes the FOR-header shape;
  vdisp can't parse "$" placeholders — and string slots are also 4 bytes
  apart, so string targets now reject the probe outright (teaching vdisp
  "$" would risk false-positive FOR detection). Fixture t1_strgoto.
- **Gap 47: integer relationals in compound bool chains** (2026-07-18):
  `IF ERR = 25 OR ERR = 27 OR ...` materializes cmpax_m through the same
  6-op template the FP compound machinery lifts; pend_icmp now hands the
  compare to pend_cmp when orax/andaxbx follows the incax. RESTRICTED to
  jcc 74/75 (equality): _JCC_RELOP_TRUE's signed rows are cmpax_bx-forward
  and would silently flip cmpax_m's reversed (mem, ax) order — other codes
  stay fail-loud until witnessed. Fixture t1_orchain.
- **Gap 46: INPUT# integer targets via the fistp bridge; PRINT# comma**
  (2026-07-18): the fistp FP->int bridge fed the _FREAD/_READDATA sentinels
  straight to ir.Assign instead of _fread_target/_readdata_target. Also
  witnessed INT C3 = PRINT#'s comma separator (console is C1). Fixture
  t1_fileint (writes a T.DAT file golden).

- **Gap 32: variable-indexed static string array element as a string
  value** (2026-07-17, follow-up session): the shl-si/addsi computed-
  element-access chain (`int_alu`, arith.py) only recognized a fixed set
  of terminal ops right after the index resolves (fld_si/fstp_si/fold_si/
  fcomp_si/strassign/far_spush/...) — a static STRING array element read
  at a VARIABLE index and used as a string value (a PRINT item) instead
  ends in `rt 0x9C` ("push var desc"), the same push op the constant-index
  case already goes through via `movsi` (core.py), just reached via a
  computed si. Added an `rt`/0x9C branch: push the resolved `ArrayRef`
  onto the sstack and let the ordinary dispatch loop handle whatever
  consumes it next, mirroring the movsi+0x9C push-then-consume shape.
  Fixture t1_svaridx (`PRINT A$(I)`). Closed inv87.exe/invoice.exe/
  onelab87.exe/onelabel.exe's "unexpected op rt" failures.
- **Gap 31: COLOR/VIEW cell target for the FP->int assign bridge**
  (2026-07-17, same session): COLOR fg,bg (and the VIEW/WINDOW coordinate
  cells) had only ever been witnessed with a plain immediate or an
  ax-computed value; a non-integer argument compiles through the generic
  FP->int assign bridge (FISTP [2C]; FWAIT; MOV AX,[2C]; MOV [tgt],AX),
  whose fallback unconditionally routed the target through `state.loc()`
  — these cells aren't in the scalar/array layout, so it raised
  "displacement ... is neither scalar nor array element". Also fixed a
  SEPARATE, previously-unreachable bug this surfaced: canonical_rename's
  per-statement walk never had an `ir.Color` case at all (every other
  graphics statement is walked), invisible before because COLOR's args
  were always Lit/None, never a Var needing re-lettering. Fixture
  t1_colorfp (`COLOR A,B` both single). Closed vhfprop.exe/inv87.exe/
  invoice.exe's "displacement 0x88 ..." failures.
- **Gap 30: re-anchor the string char-record search past the descriptor
  table** (2026-07-17, same session): the char-record search bracket
  (`(len|0x8000) 00 00 00 00 <chars> (len|0x8000)`) anchored its 0x400-
  byte window at align16(pool_base) — fine for a short pooled-literal
  descriptor chain, wrong once the chain runs long (many literals, or a
  static string array whose per-element descriptors chain into the SAME
  table — witnessed 469/513-entry chains). The chain-walk loop's own `d`
  variable already sits exactly past the last matched descriptor when the
  loop breaks — anchor the search there instead of re-deriving from
  pool_base. Fixture t1_strch (260 pooled PRINT literals; bisected
  minimum). Closed vhfprop.exe/inv87.exe/invoice.exe's "string char
  record not found" failures.
- **Gap 29: compound-IF second term ending in a tail-test DO..LOOP**
  (2026-07-17, same session): `LOOP WHILE/UNTIL A relop B AND/OR C relop
  D` materializes its second term with a BACKWARD Jcc (the loop's own
  back-edge) instead of the dispatch jcc+jmp pair every other compound-IF
  tail uses — same 5-op shape `_lift_do_tail` already handled for a bare
  single condition, just with the AND/OR combining op where a bare
  tail-test always has a plain self-test `or ax,ax`. New
  `_lift_bool_do_tail` in lift.py, tried before the existing dispatch-pair
  `_lift_bool_tail`. Fixtures t1_boolwh/t1_booluntil. Closed onelab87.exe/
  onelabel.exe/schart.exe's "compound-IF tail mismatch" failures.
- **Gap 28 follow-up: stamp path generalized to ALL no-runtime-array
  programs** (2026-07-17, same session): corpus-wide survey showed every
  one of the 615 no-rt fixtures carries the ordinary-scalars stamp and it
  reproduces the solved layout exactly — including the n_static=0 form
  (the tail collapses to `(0, num_base, 0, num_base)`, i.e. the COMMON
  `read_stamp` shape) and the LINE box-fill fixtures, whose stamp counts
  the runtime's own 4-byte cell inside the band (`gb == b1 == 0x120`
  while user slots start 0x124 — the hand-calibrated `vb+4` shift is
  literally in the stamp). Two hardening invariants, both verified on
  every no-rt fixture + all gap-16 probes: the ordinary stamp is DIRECTLY
  preceded by the COMMON band stamp, and that stamp is degenerate exactly
  when the program has no COMMON (non-degenerate routes to
  `_bands_layout` as before). Runtime-array programs carry NO stamp
  (all 28 rt fixtures checked, loose-shape scan) — the grid-anchored rt
  path stays evidence-based. With the walk loop experimentally disabled,
  all 643 decodable corpus EXEs still solve — the descending-n walk, the
  pool-runaway retries and the phantom bridges are now pure fallback for
  unwitnessed shapes. Zero golden drift; spot byte-exact re-verified
  t1_poolrun/t1_lineb/t1_linevb/t1_common1/tier0_trivial/t1_arr1/
  t1_sstat/v10_t1_common2 through the oracle. Possible later stages (not
  scheduled): unify `_bands_layout` with the stamp band-builder; study
  the rt init image for an equivalent anchor.
- **Gap 28, stamp-anchored DGROUP layout + rank-4 arrays — GAP 16 FULLY
  CLOSED** (2026-07-17, this session): the whole offset-formula hunt
  (traces 1–3 + the static-analysis pass, previously a ~370-line section
  here) was superseded by reading the pre-grid bytes: the compiler stamps
  the **ordinary-scalars band descriptor** into the init image as 8 LE
  words `(num_size, num_base, str_size, num_base+num_size, n_static,
  grid_base, 0, num_base)` with `num_base == grid_base + 0x36*n_static`,
  **directly followed by the n_static populated slot records** at
  ARR_BLOCK stride. The COMMON `read_stamp` shape is this stamp's
  degenerate `n_static=0` form — one mechanism all along. The record run
  FLOATS past variable-length init data (error-trap line table, zero
  padding), by 32..720 bytes across the witnesses, which is why every
  `grid_start - VAR_BASE` formula failed (the n=9 probe measured offset
  32 where the linear fit predicted 64 — refuted on the first new data
  point, as the static-analysis pass itself expected). Scalars are
  SEGREGATED numerics-first with strings in a trailing sub-band
  (`str_size`, witnessed wild schart s2=76). New stamp-anchored solve in
  `layout.py` runs BEFORE the walk paths (required: a wide band lets the
  greedy walk "solve" a wrong-but-finish-passing layout — witnessed
  t1_bandwide reading a phantom pooled double past EOF); on the existing
  corpus the stamp and walk layouts agree everywhere both apply (44
  fixtures, zero golden drift, ir_snapshot additions only). Plus rank-4
  static array records in `_parse_static_slot` (same cumulative-span
  model; the 0x36 slot is exactly a rank-8 record; c0's DIM guard raised
  to 4), needed by wild hfprop. Byte-exact verified both dialects across
  three new fixtures: `t1_bandwide` (wide numeric band, vhfprop shape),
  `t1_bandstr` (interleaved string scalars, schart shape), `t1_dim4`
  (rank 4), + v10 variants, pinned in `test_wild_batch3.py` +
  `test_tb10_dialect.py` PAIRS. Probes saved as
  `wild/probes_gap16/q_gap16{v,w}.bas`, `q_dim4.bas`. Wild re-scan: the
  "DGROUP layout not solvable" bucket went 5 → **0** — schart advanced
  into compound-IF tail mismatch, vhfprop/inv87/invoice into "string char
  record not found", hfprop into the known FRE(s$) unsupported case. The
  scratchpad tracer technique (brute-force ARR_BLOCK-spaced record scan +
  stamp-by-shape search) is reproducible from this entry if needed again.
- **Gap 27, `find_statics` window too tight for FOR-loop/array-grid
  overlap** (2026-07-17, this session): a literal-limit FOR loop's control
  variable and the scalar band allocated with/after it can land inside the
  DGROUP array grid's own trailing bytes — specifically the LAST static
  array's `ARR_BLOCK` (0x36) slot, whose bookkeeping record is otherwise
  dead at runtime once its constant-base `addsi` is compiled. Confirmed via
  5 oracle-compiled probes (`wild/probes_gap16/q_gap16{p,q,s,t,u}.bas`):
  the overlap is position-fixed (always the grid's last slot, regardless
  of which array the loop actually indexes — retargeting the loop to a
  different array produces byte-identical scalar evidence) and can span
  more than one slot when the scalar band is wide (confirmed 2-slot
  spillover at a 62-byte band). `find_statics`'s window (`pos < end - 11`,
  `end = ds + sb`) assumed the static-record run always finishes within
  `[ds+VAR_BASE, ds+sb)`; widened by one `ARR_BLOCK` of slack, comfortably
  covering every overlap witnessed (32/48/32 bytes at `n_static=9/10/11`
  respectively — NOT simply `align16(scalar_band_width)`, an earlier
  3-data-point hypothesis that a 4th point at a different `n` refuted;
  the full investigation history is condensed into the gap-28 entry
  above, which found the real mechanism). `walk_run` and `find_statics`'s
  per-record advance logic were never wrong — only the window bound.
  Byte-exact verified both dialects, fixture `t1_for10arr`/
  `v10_t1_for10arr`, pinned in `test_wild_batch3.py` +
  `test_tb10_dialect.py`. Closed 2 of 7 wild "DGROUP layout not solvable"
  files (onelab87.exe/onelabel.exe, advancing into a new "compound-IF tail
  mismatch" gap); schart/hfprop/vhfprop/inv87/invoice remained and were
  closed by gap 28 above (the same floating-record mechanism at larger
  scale, solved from the stamp instead of a window heuristic).
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

## Reference: `$INLINE` / `SUB ... INLINE`, confirmed via the real handbook + oracle (2026-07-19)

Not a gap -- a piece of ground truth worth keeping, since it came up while
investigating whether any of this session's stuck gaps (byte 89, byte 06,
byte ea, INT 8c) might secretly be hand-written embedded assembly rather
than compiler output. Short answer: **no**, none of them are (see the
reasoning below) -- but the signature of a REAL `$INLINE` is now precisely
known if a future gap ever does look like this.

TB's inline-assembly mechanism is real (`Error 492: $INLINE requires SUB
INLINE`): the correct syntax is `SUB name INLINE` (a trailing modifier
keyword on the SUB declaration, NOT a sub literally named "INLINE" --
tried and correctly rejected with `Error 471` first). Inside, `$INLINE
byte, byte, ...` (integers 0-255) or `$INLINE "filespec"` (a separately-
assembled, relocatable .COM-style blob) inserts raw machine code
verbatim. Compiled and disassembled the handbook's own worked example
(the PC-speaker "Shriek" SUB) via the oracle to confirm the EXACT
compiled shape:

```
SUB Shriek INLINE
$INLINE &HBA, &H00, &H07, &HE4, &H61, &H24
$INLINE &HFC, &H34, &H02, &HE6, &H61, &HB9
$INLINE &H40, &H01, &HE2, &HFE, &H4A, &H74
$INLINE &H02, &HEB, &HF2
END SUB
```
compiles to: the ordinary SUB-skip `jmp` (present on every SUB/DEF FN,
nothing special) immediately followed by -- **no `push bp`/`mov bp,sp`
frame setup at all**, unlike every other TB SUB -- the exact 20 bytes
listed, copied byte-for-byte with zero transformation across all four
`$INLINE` lines (the multi-line split has NO separate byte-level
representation, consistent with this session's DATA/orphan-statement
findings elsewhere: source-level statement boundaries the compiler
doesn't need for anything are frequently unrecoverable, i.e. genuinely
lossy, from the compiled bytes alone), then TB **auto-appends a bare
`CB` (far RET)** -- confirming the handbook's explicit warning not to
write your own trailing RET.

**Why this rules out $INLINE for the gaps chased this session**: a real
`$INLINE` block would show up as an ISOLATED byte run inside one SUB,
with NO frame-setup prologue before it, ending in a bare `CB`, containing
bytes specific to whatever that one program's author hand-wrote --
i.e. NOT recurring identically across unrelated files. Every stuck gap
this session (the `di`-register `89 CF/89 D9/89 C3` shuffle, the byte-06
CGA-blitter template, etc.) is the OPPOSITE of this signature: interleaved
with fully-recognized, already-calibrated compiler ops on both sides, and
byte-IDENTICAL across multiple independent wild files -- the signature of
a shared compiler template, not hand-authored assembly. Confirmed, not
just assumed.

**If a future gap DOES match the real signature** (isolated unrecognized
bytes, no proc-enter framing, inside a SUB, non-recurring across files):
**IMPLEMENTED as of 2026-07-19** (`SUB ... INLINE` / `$INLINE`, the
byte-list form -- user-requested, added despite no wild file needing it
yet, since it's a real documented language feature). `_scan` gained a
retry mechanism (`_try_inline_rescue`): on any scan failure, it checks
whether the most recent `jmp`'s target has a bare 0xCB right before it
(TB's auto-appended far RET for an inline body); if so, it discards
whatever bogus ops the raw bytes partially matched, replaces them with
one opaque `inline_sub` blob, and resumes from the target -- every other
gap stays exactly as fail-loud as before, since this only fires after
the ordinary scan has already given up. New `ir.Inline(data: bytes)`
node; `ir.SubDef` with a single-`Inline` body renders the `INLINE`
header keyword. Confirmed byte-exact against the handbook's own worked
example (the "Shriek" PC-speaker routine) both dialects, fixture
`t1_inline`/`v10_t1_inline`. The filespec (`$INLINE "file"`) form is
NOT implemented (no external .COM-style blob to test against) -- only
the byte-list form. c0 raises `_Unsupported` for `ir.Inline` (no CPU in
the emulated machine to run arbitrary code on).

**The first version of the rescue check (target-1 byte is bare 0xCB, no
other condition) DID false-positive on the first full wild-corpus
re-scan**: CVT2TB.EXE's OWN unrelated gap-19 construct (the `push bp; mov
bp,sp` CGA-blitter shape, using the alternate `89 E5` mov-bp,sp
encoding -- see that gap's addendum below) legitimately ends in `pop bp;
retf` (`5D CB`), which coincidentally ALSO satisfies "byte right before
the jmp target is 0xCB". The rescue fired, silently swallowed 60 bytes
of what is actually recognizable-shape procedure code as an opaque
blob, and let the file advance to a LATER, different failure instead of
its correct one -- caught only because the file's failure ADDRESS moved
on the standard post-change re-scan (part of this workflow for every
change, not something added specially for this). Fixed by also
requiring the body NOT start with `55` followed by either known
mov-bp,sp encoding (`8B EC` or `89 E5`) -- a real proc-enter shape,
genuine $INLINE content has no framing at all (confirmed from the
Shriek probe, which starts directly with its first real byte). Re-ran
the full 84-file corpus after the fix: zero files produce ANY
`inline_sub` op now, and CVT2TB.EXE is back to its original, correct
`unhandled byte 89 at 0xa286`. This is worth remembering as a general
lesson for this rescue mechanism specifically: it is a heuristic over
raw bytes, not a calibrated vocabulary match, so ANY future change
touching it needs the SAME full-corpus re-scan discipline, not just a
check against the one fixture that motivated it.

Confirmed (after the fix above) that none of this session's other stuck
gaps are secretly `$INLINE`: an `inline_sub` rescue never fires for ANY
of the 84 wild files (byte 89/di-register, byte 06, byte ea, INT 8c all
still fail exactly where they did before this whole feature landed) --
consistent with the earlier reasoning that those are shared compiler
templates, not hand-authored assembly.

## Gap byte 89 / the missing `di` spill register, DI LEVEL CLOSED; MEMORY-SPILL LEVEL OPEN (2026-07-19)

**Current status:** the DI-register fix described below is now landed and
oracle-witnessed by `t1_dispill` (nested SCREEN arguments reproduce it).
pfl.exe advances past the gap. catalog.exe/process.exe now stop at the
deeper `mov [disp],di` memory-spill form described below; CVT2TB.EXE remains
an unrelated byte-89 opcode. The remainder of this section preserves the
investigation history that preceded the fixture.

**Root cause is IDENTIFIED with high confidence** (not a guess -- grounded
in real x86 semantics and confirmed byte-for-byte against 3 independent
wild files), but no minimal witnessed probe was found after extensive
trying, so per the calibration rule the fix was written, verified to
advance real files, then **reverted** rather than committed unwitnessed.
This section exists so the next session doesn't have to redo the
byte-level archaeology.

(This tally bucket originally showed a 4th file, CVT2TB.EXE -- that one
turned out to be UNRELATED to the `di` register and has since been
identified as a repeated instance of the already-tracked gap 19/byte-06
CGA blitter mystery instead, with its own separate encoding wrinkle; see
the addendum at the end of the "Gap 19 — byte 06" section below. Don't
go looking for it here.)

**The mechanism**: `decode0/scan.py`'s generic `mov reg,reg` recognizer
(`_scan`, ~line 891) has:
```python
if b == 0x89 and (exe[p + 1] & 0xC0) == 0xC0:  # mov reg,reg: the far-index
    rm, rg = exe[p + 1] & 7, (exe[p + 1] >> 3) & 7  # spill protocol
    names = {0: "ax", 1: "cx", 3: "bx", 6: "si"}
    if rm in names and rg in names:
        ops.append((p, "movrr", names[rm], names[rg]))
```
`names` is missing `7: "di"`. Real x86 `MOV r/m16,r16` (opcode 0x89) is
ONE uniform instruction format across all 8 general registers -- TB's
existing "spill-protocol shuttle" mechanism (`movrr` in
`handlers/arith.py`, already calibrated for ax/bx/cx/si as a symbolic
4-register file in `DecodeState`) clearly also uses `di` as a 5th slot
once register pressure runs deep enough, and this specific reg is simply
unrecognized -- confirmed by disassembling ALL FOUR wild hits: `89 CF` /
`89 D9` / `89 C3` (`mov di,cx; mov cx,bx; mov bx,ax`) in catalog.exe,
process.exe, and pfl.exe, byte-identical across all three. (CVT2TB.EXE's
own byte-89 hit, `89 E5` = `mov bp,sp`, is a COMPLETELY different,
unrelated stack-frame-setup shape that only shares the tally bucket by
having the same leading byte -- do not conflate the two when re-diagnosing.)

**The fix** (written and tested this session, then reverted -- reapply
verbatim once a probe lands):
1. `scan.py`: `names = {0: "ax", 1: "cx", 3: "bx", 6: "si", 7: "di"}`.
2. `core.py` `DecodeState`: add a `di: Any = None` field (next to `cx`
   alphabetically) and `state.di = None` in the setup block (next to
   `state.cx = None`).
3. `handlers/arith.py`'s `movrr` dispatch: extend the `regs` dict/tuple
   unpack to include `"di": state.di` (5-way instead of 4-way swap).
4. `handlers/arith.py`'s `cmpax_m`'s `shuffled` detection (~line 202) is
   ALSO too narrow -- it hard-codes the exact 2-op `movrr(ax,bx);
   movbxax` shape. Generalize to a forward-scan loop that skips ANY run
   of consecutive `movrr`/`movbxax` ops (they're pure register
   bookkeeping; MOV never touches FLAGS, so any length is safe to skip)
   and checks whether the op right after is `movax(0xFFFF)`:
   ```python
   j = state.k + 1
   while j < len(state.ops) and state.ops[j][1] in ("movrr", "movbxax"):
       j += 1
   shuffled = (
       j > state.k + 1
       and j < len(state.ops)
       and state.ops[j][1] == "movax"
       and state.ops[j][2] == 0xFFFF
   )
   ```
   Without this, even with `di` recognized at scan level, catalog.exe/
   process.exe's DEEPER 4-op shuffle (`movrr(ax,bx); movrr(bx,cx);
   movrr(cx,bx); movbxax`) still fails dispatch with "cmpax_m without a
   value/IF consumer" since the original code only matched the simple
   2-op case witnessed by the EXISTING `t1_andchain` fixture.

With all 4 changes applied: pfl.exe advances CLEANLY past its byte-89
stop into the ALREADY-KNOWN "unreferenced pooled string literals"
gap (same open issue number.exe/pfl.exe both hit -- see below).
catalog.exe/process.exe advance to a SECOND, deeper byte-89 occurrence
(see "what's still missing" below). CVT2TB.EXE is unaffected (different
root cause, still fails at the same address). All 2109 existing tests
still pass -- this is a pure ADDITION to the vocabulary, nothing
existing changes shape.

**What's still missing even with the fix**: catalog.exe/process.exe's
SECOND occurrence goes deeper still -- `mov [7Eh],di` (a NEW disp16-store
form, `89 3E dispLO dispHI`, spilling `di` to a MEMORY scratch cell, not
just another register) followed later by a matching `mov cx,[7Eh]`
reload INTO A DIFFERENT REGISTER than it was stored from, plus a
still-unrecognized `INT EDh sub 22`. This is a real, GENUINELY DEEPER
mechanism (a memory-backed spill slot on top of the register one) that
would need its own new `DecodeState` field (something like
`mem_spill: dict[int, Any]`, populated on the disp16 store and consumed
on reload) -- do not attempt this without first nailing the `di`
register case's own probe, since the memory-spill case only ever
appears ON TOP OF it in the evidence gathered so far.

**Extensive probing did NOT find a witness** (all tried via
`oracle.compile_bas`, dialect 1.1, none reproduced the `di` shuffle):
- Plain 2-D and 3-D static-array element access (`DIM A%(5,5)` /
  `DIM A%(3,3,3)`, computed and mixed literal/computed indices,
  standalone and nested inside an `IF`, plain and with a `+1` sub-
  expression in one index) -- ALL decode fine already via the EXISTING
  single-`si`/`addsiax` accumulator machinery, no `di` needed at any
  rank/nesting tried.
- AND-chains of local INTEGER variables, 2/3/4 terms deep
  (`IF A=1 AND B=2 AND C=3 [AND D=4] THEN`) -- ALL compile via the
  `andaxbx` combinator (a DIFFERENT, simpler mechanism: right operand
  evaluated first into bx, left into ax, `AND` them), NEVER via
  `cmpax_m`'s shuffle-chain path, regardless of chain length.
- The EXISTING `t1_andchain` fixture's own construct (`IF ERR = 25 AND
  ERR = 27 AND ERR = 57 THEN`, using the special ERR pseudo-variable,
  disp 0x74) extended to a 4th term -- still only the shallow 2-op
  shuffle, no escalation to `di` even at 4 terms.
- SUB by-ref scalar parameters: single param compared against a
  literal inside a 2-3 term AND-chain (mixed with locals, mixed with
  other by-ref params, all-by-ref); two by-ref params compared against
  EACH OTHER. None reproduced `cmpax_m`'s shuffle at all (by-ref-vs-
  by-ref comparisons take a yet-different path with no `cmpax_m`
  either); the mixed local+by-ref 3-term chain reached a genuinely
  DIFFERENT pre-existing gap instead (`cmpax_bp without an IF
  jcc+skip-jmp`) without ever touching `di`.
- A `FOR`-loop-plus-by-ref-parameter linear-search shape (closer to
  what process.exe's SUB actually appears to implement, given the
  `movax(65535)` "not found" sentinel initialization pattern in its
  evidence) -- hit an unrelated gap (`unhandled byte 36`, an SS-segment
  override prefix) before reaching anything relevant.
- A deep, purely-arithmetic nested expression (`((A+B)*(C+D)) +
  ((E+F)*(G+H))`, 8 variables) -- decodes fine with only 30 ops and NO
  register spilling at all, consistent with the theory that pure
  arithmetic nesting routes through the 8-deep x87 FP stack instead of
  general-purpose registers, so expression depth alone is not the
  trigger for `di`.

**What the evidence actually suggests, unconfirmed**: pfl.exe's fuller
trace (disassembled past the scan failure point with iced-x86 directly,
bypassing `_scan`) shows something structurally stranger than a plain
multi-dim subscript: after the `di`-shuffle, the code does `mov ax,[si]`
(reading a VALUE from the array position just computed), THEN `mov
si,di` (recovering an EARLIER-stashed partial index), THEN `imul word
[456h]` (multiplying that JUST-READ ARRAY VALUE by a span constant) and
accumulating it into `si`. That is: **the array element's own VALUE
appears to feed into computing a FURTHER index** -- something shaped
like `B%(A%(i) [* k], j)`, a value-dependent/indirect subscript, not a
plain multi-dimensional one. This is a substantially different, rarer
BASIC construct if the reading is right, and would explain why simple
2-D/3-D probes never came close. catalog.exe/process.exe's shape, by
contrast, looks like an AND-chain where at least one term is a by-ref
SUB parameter, nested inside something ELSE that already has bx/cx live
(the trace shows `movbxax`/`movax_m`/`movrr(cx,bx)` bookkeeping BEFORE
the by-ref comparison even begins) -- i.e. the trigger is likely about
REGISTER PRESSURE FROM SURROUNDING CONTEXT (a larger expression or an
outer `andaxbx` whose right-hand operand is itself this whole by-ref
comparison), not something reproducible from a short, flat snippet.
Next probe ideas, untried: a genuinely NESTED `andaxbx`, e.g. `IF (X = 1
AND Y = 2) AND Z% = 3 THEN` with explicit grouping, or a SUB with LOCAL
variables ALREADY holding live boolean state from an earlier statement
in the same body before the AND-chain begins; for pfl.exe, an explicit
`B%(A%(I), J) = ...` (array value used directly as another array's
index) compiled and diffed against the exact byte shape above.

**MAJOR LEAD, found later the same session, NOT YET CLOSED**: a 4th wild
file, kinder.exe, was found to hit this SAME `di`-shuffle gap too (its
own `unhandled byte 89` only surfaced after the unrelated `t1_bload0` fix
let the file decode further) -- and its surrounding context is dramatically
more tractable than catalog/process/pfl's: no by-ref params, no arrays,
just `SCREEN(row,col)` (the ax-returning intrinsic, INT ED sub 0x42, row
in bx/col in ax) combined with `\` (integer divide) and `MOD`. Probe
`X = SCREEN(3,1) \ 16` reproduces kinder.exe's shape EXACTLY at the
2-register level (`movrr(cx,bx); movbxax; ...; fn_screen; movrr(bx,cx);
cwd; idivbx` -- cx alone preserves the divisor across the SCREEN() call's
own bx/ax setup) -- confirming SCREEN()+`\`/MOD is unambiguously the
right construct FAMILY. But kinder.exe's actual trace goes one level
DEEPER (needs `di` too), and no variant tried this session reproduced
that extra depth:
- Two chained `SCREEN(...) \ SCREEN(...)` calls (right operand evaluated
  first per TB's usual convention, saved to bx, then the left operand's
  own SCREEN() call reuses cx as its OWN internal scratch) -- still only
  2 registers deep, `di` untouched.
- Using VARIABLES (loaded from a preceding `LOCATE R, C` whose R/C values
  matched kinder.exe's literal 16/3) instead of literal SCREEN() args --
  adds FP-bridge ops (fild/fistp/movaxmem) but does NOT add register
  depth; still 2 levels.
- A THREE-way chain, `SCREEN(a,b) \ SCREEN(c,d) \ SCREEN(e,f)` -- did NOT
  reproduce `di` either; instead hit a completely different, new,
  unrelated gap (`unhandled byte 93` at a different address) before
  reaching anything relevant. Worth investigating on its own merits
  later, but a distraction from this specific gap -- noted here only so
  it isn't mistaken for progress on the `di` question if re-tried.

Next probe idea, untried and HIGH-PRIORITY: kinder.exe's actual second
occurrence used SCREEN(42,1) MOD 16 (not `\`) -- try MIXING `\` and MOD
in the SAME compound expression (`SCREEN(a,b) \ 16 + SCREEN(c,d) MOD 16`
or similar), or embedding the SCREEN()-div expression as ONE operand of
a LARGER arithmetic expression whose OTHER operand is already using bx
(so that "16" alone isn't the only thing needing cx-preservation -- an
outer, already-in-progress computation would need the extra `di` slot).
Also untried: SCREEN() with a 3rd argument (color-plane selector) --
TB's `SCREEN(row,col,color)` 3-arg form might itself need an extra
register beyond what the 2-arg form in every probe above used.
(`W + SCREEN(3,1) \ 16` tried and RULED OUT for the "outer expression"
idea specifically -- pure arithmetic wrapping routes the SCREEN/DIV
result through the FP stack via a trailing `fold '+'`, never touching
general registers at all, consistent with this session's earlier finding
that plain arithmetic nesting doesn't pressure the register file the
way comparisons/function-call argument evaluation does.)

## Gap INT EC sub 4c (be.exe/pwinst.exe/strpfind.exe), UNDIAGNOSED (2026-07-19)

Surfaced fresh this session once the OPEN/LOF/LINE INPUT# gaps ahead of it
closed. All three hits are TB 1.0 (raw sub 0x4A, canon_sub +2 -> canonical
0x4C). Full evidence, pwinst.exe at 0x81f4:

```
8b 06 0e 02        mov ax,[020Eh]      (movax_m, disp=526 -- a plain int var)
cd ec 4a           INT EC sub 4Ah (raw) = canonical 4C -- THE GAP
```

Immediately BEFORE this (pwinst.exe): `movax(1); fn_axfp LOF; fstp(520)`
(i.e. `X = LOF(1)`) then `on_error(35379)` then `movm_imm(96,1)` ([0060] =
file# 1). So the shape is: `X = LOF(1)`, `ON ERROR GOTO ...`, `[0060]=1`,
`ax = <int var>`, then this INT with **no inline operand bytes** (a plain
3-byte `cd ec 4a`, argument entirely in ax) -- same "[0060] + ax" calling
convention as WIDTH's `[0060]`-scoped sibling would use, but NOT WIDTH
itself (see below). Right after, unrelated code resumes with a fresh
`movsi`+`strcmp` (a SELECT CASE string arm) in the ops actually captured,
so this is a clean, complete, single statement.

**Ruled out this session**:
- `WIDTH #n, cols` (plain `WIDTH n` is a DIFFERENT, already-implemented
  sub 0xEC with an ax operand) -- compiles fine but scans to a
  **different** unhandled sub, `EC f0` (a distinct, not-yet-tallied
  future gap -- worth a probe of its own later, but it is NOT this one).
- Bare `LOCK #n` -- not valid TB syntax at all (`Error 414: "=" expected`,
  the parser reads `LOCK` as an assignment target). TB's LOCK likely
  needs a range operand (`LOCK #n, r1 TO r2`?) which would change the
  byte shape (probably 2 args, not 1) -- untried.

**Untried candidates**: `LOCK #n, range`/`UNLOCK #n, range` (proper
syntax, needs the manual or more probes to find the right grammar);
something record/position-based that consumes the just-computed LOF
result (though the two aren't provably linked -- could be coincidental
adjacency in source); a RENAME-family statement. Since ax carries a
PLAIN INTEGER (not a file position/record on the FP stack like GET/PUT/
SEEK, which all pop `state.stack`), whatever this is takes its argument
via a DIFFERENT, ax-based convention from the existing random-access
family -- narrows the search but doesn't pin it down. Next step:
compile candidate one-liners after `OPEN ... AS #1` and diff the exact
`[0060]=n; ax=<expr>; cd ec 4a` shape.

## Gap INT ce (billadd.exe/file.exe), UNDIAGNOSED (2026-07-19)

Also surfaced fresh once LINE INPUT# unblocked these two files further.
A genuine 2-byte `INT CEh` (`cd ce`, canonical -- do not confuse with the
UNRELATED, already-handled single-byte `0xCE` = raw `INTO`, the
Overflow-toggle check, which has no `cd` prefix). Evidence, billadd.exe
at 0xf0b3:

```
movbxax; movax(20); locate     -- LOCATE 20, 1  (row=bx, col=ax convention)
movax(1); cursor                -- CURSOR 1  (cursor visible/blink arg)
xorax; movbxax                  -- bx = 0
movax(7)                        -- ax = 7
cd ce                            -- THE GAP: 2-byte INT CEh, no inline operand
```

So: position the cursor at row 20 col 1, turn the cursor on, then call
something with bx=0, ax=7 and no further operand bytes. Screen/cursor
context strongly suggests a text-mode attribute or character write at
the (now-positioned) cursor, but nothing has been tried yet this
session -- no probes attempted, no keywords ruled out. VIEW PRINT and
PCOPY are already known non-keywords in this dialect (ruled out for the
UNRELATED byte-06 gap, but the same "not real TB keywords" fact applies
here too if either comes up as a candidate again). Next step: probe
sweep of statements that take two small integer args and run right
after LOCATE+CURSOR in a "draw at cursor" context (candidates worth
trying: `WRITE` in some special zero-arg-adjacent form, a low-level
`OUT`/`WAIT`-family statement, or something PLAY/SOUND-adjacent that
happens to follow a LOCATE call textually but isn't actually screen-
related -- the LOCATE/CURSOR proximity could be coincidental source
adjacency rather than a causal link).

## Gap "unhandled materialized test" (metric.exe) — CLOSED (2026-07-19)

Was UNDIAGNOSED earlier in this same session (several SUB/DEF FN/GOSUB
probes tried and ruled out) -- the actual trigger turned out to be a
DO...LOOP WHILE/UNTIL whose body ends in a NESTED FOR...NEXT (none of
the ruled-out probes had one). See "Recently closed" above
(`t1_nestfor`/`t1_nestfor2`) for the full writeup: `_lift_while` gained
a third branch, mirroring `_lift_do_tail`'s tail-test recognition but
with inverted jcc polarity, for when the retry edge is the materialized
test's own trailing jmp rather than a separate `jmps` found by
`_has_jmps_back`. Kept as a heading here (rather than deleted) so a
future `grep` for this error string still finds where it was solved.

## Gap "codeless-statement entry but no DATA pool" (metric.exe), SOLVED (2026-07-19)

Surfaced immediately by the nested-FOR-loop fix directly above, in the
SAME wild file. `core.py` `_finalize`'s DATA-pool fallback (~line 582):
after DO-unsynthesis claims every bare-Do's orphan and the static-DIM
count-match runs, 3 of metric.exe's 56 error-trap-line-table orphan
entries remained unclaimed, and `_read_data_pool` appeared to find nothing.
The original diagnosis treated them as `DEFINT`/`DEFSTR`/`DEFSNG`/`DEFDBL`
declarations because the DATA reader incorrectly rejected metric's >255-byte
shared literal pool. After the 15-bit frame fix, all three recover as
separate DATA clusters. DEFxxx remains a real, oracle-witnessed codeless
construct (`t1_deftype`), and mixed DATA+DEF recovery is pinned by
`t1_databig`; metric itself canonicalizes these three entries as DATA.

**The table itself is a genuine oddity worth knowing before diagnosing
further**: EVERY one of metric.exe's 1733 real entries AND all 56
orphans show line number **0** -- not just the leftover 3. Confirmed
this is not a false-positive table match (the walk requires reaching the
exact epilogue offset with a matching trailing line, which cannot
realistically happen by chance over ~1789 consecutive 4-byte groups; the
real-entry count, 1733, exactly equals the file's own decoded statement
count). Probed and CONFIRMED harmless/expected, not itself the bug:
plain `ON ERROR GOTO`+`RESUME NEXT` with every line numbered compiles a
fully correct, non-zero table (`10,20,30...`); a program mixing numbered
and UNNUMBERED statements shows each unnumbered statement inheriting the
MOST RECENT preceding numbered line (never 0) -- so metric.exe's
all-zero table most likely just means its source has NO (or almost no)
explicit line numbers ANYWHERE, i.e. it's written in the unnumbered/
label-sparse style, which is a separate, self-consistent finding, not
obviously connected to the 3 unclaimed orphans. (Whether an all-zero
table is even byte-significant at all -- i.e. whether `prog.lines` needs
to preserve it or could safely fall back to free renumbering -- is
itself unresolved; nothing in this investigation reached the point of
testing that.)

**The 3 unclaimed orphans, precisely located** (via a temporary spy on
`core._finalize` capturing `state`/`addr`, then re-running `_line_table`
directly -- see git history of this commit for the technique):
- Offset 9: the codeless statement immediately precedes `state.stmts[2]`,
  `OnError(target=('addr', 67481))` -- the program's `ON ERROR GOTO`
  itself, preceded by `Cls()` and `Key(on=False)`.
- Offset 1137: immediately precedes `state.stmts[83]`, a SELF-referential
  `IfGoto(cond=LEN(INKEY$)=0, target=(same address))` -- the classic
  "wait for any key" busy-loop idiom, `<n> IF LEN(INKEY$)=0 THEN GOTO
  <n>` (a bare-line, non-DO-loop spelling of the SAME idea this
  session's `t1_orax` fixture closed for the DO-loop spelling).
- Offset 26103: the SAME self-referential-IfGoto shape again, near the
  very end of the program (inside what looks like the error handler's
  own body, given `on_error`'s target 67481 and 3 separate `resume_pre`
  ops all land nearby, ~25750-26014). This one immediately follows the
  program's "THANK YOU FOR EVALUATING METRIC.EXE... PLEASE SEE
  METRIC.DOC..." shareware nag screen -- i.e. the error handler
  plausibly displays this nag and waits for a key before ending.
  `state.stmts` confirms only 1 `OnError` and each mystery target
  address is referenced exactly once (ruling out a "multiply-referenced
  target gets an extra entry" theory).

**Ruled out this session** (all via `oracle.compile_bas`, dialect 1.1,
none produced an orphan):
- A bare numbered line with NO statement at all (`900` alone, nothing
  after it) -- produces NO table entry whatsoever, not even an orphan;
  the compiler elides it completely and resolves any GOTO/RESUME target
  straight through to the next real statement. Consistent with REM/`::`
  already being confirmed non-codeless; genuinely empty lines carry no
  recoverable payload at all, unlike DATA/DIM.
- A plain, fully-numbered `IF LEN(INKEY$)=0 THEN GOTO <same line>`
  self-loop, alone or preceded by unnumbered statements (matching
  metric.exe's likely mostly-unnumbered style) -- decodes clean, no
  orphan, in both cases.
- A realistic multi-branch handler (`IF ERR=5 THEN RESUME NEXT`, `IF
  ERR=6 THEN RESUME 40`, THEN the nag-screen-and-self-loop shape,
  mirroring metric.exe's 3-RESUME structure) -- still no orphan.
- Explicit `OPTION BASE 0` (redundant with the default) was tried directly
  before `ON ERROR GOTO`: it produces no orphan and is elided on decode.
  The DEFxxx family was the matching lead.

**batch_probe.py** (`tbx/tools/batch_probe.py`, new this session) is a
good fit for sweeping the OPTION-BASE/DEFxxx family and any other small
variations in one pass once there's a concrete list of candidates --
this investigation mostly predates the tool's construction and was done
one probe at a time; a future pickup should batch it.

## CLOSED 2026-07-20 — missing runtime-revision three-argument INSTR (`INT ED sub 1e`)

`INT ED sub 1e` is the runtime entry for the three-argument form
`INSTR(start, haystack$, needle$)`. This is a missing Turbo Basic runtime
variant, not `CINT` and not a new IR intrinsic: the existing `ir.Call("INSTR",
args)` already supports both arities, the renderer preserves the argument list,
and the C backend already maps arity three to `tb_instr(start, haystack,
needle)`.

### Byte-level calling convention

Four independent executables hit the same canonical dispatcher sub across both
compiler dialects: `be.exe` (1.0), `crossref.exe` (1.1), `hebrew.exe` (1.0),
and `invent.exe` (1.0). At every site:

1. the search start is evaluated into AX;
2. the haystack string descriptor is pushed;
3. the needle string descriptor is pushed;
4. `CD ED 1E` executes (after dialect canonicalization); and
5. the integer result remains in AX and is immediately stored or consumed.

Representative raw shapes (addresses are file offsets in the untracked wild
executables; no executable bytes are tracked):

- `be.exe @ 0x7ee3`: `mov ax,[002c]`; push strings at displacements `0188` and
  `0208`; `INT ED,1e`; `mov [002c],ax`.
- `crossref.exe @ 0xa6bd`: load the start expression, push the two string
  descriptors, `INT ED,1e`; `mov [002c],ax`. A second occurrence follows near
  `0xa6ef`, showing the same two-string-plus-AX contract.
- `hebrew.exe @ 0xcbc3`: form AX as `1 + [02cc]`, push strings `02f2` and
  `0760`, call `ED/1e`, then store AX back to `[02cc]` inside a loop.
- `invent.exe @ 0x8ddf`: load literal start `63` into AX, push strings `02be`
  and `03d8`, call `ED/1e`, then store the result through `[002c]`.

This matches the neighboring, already oracle-verified `ED/1c` two-argument
`INSTR(haystack$, needle$)` entry exactly, with the sole additional live input
being AX. It also explains why the existing C runtime had an unused `start`
parameter and why `c0.py` already contained separate arity-two and arity-three
mappings.

### Negative evidence and evidence classification

The earlier `CINT` hypothesis is ruled out: literal and variable `CINT` probes,
plus general numeric-conversion probes, compile to inline x87 `FISTP/FILD`
sequences and never emit `ED/1e`.

The vendored Turbo Basic oracle rejects all common three-argument spellings
tested (`INSTR(2,A$,"C")`, `INSTR(A$,"C",2)`, and the latter with a variable
start). Therefore no minimal oracle fixture can honestly be claimed. The entry
is classified as **runtime-revision evidence**: four independent binary
witnesses, both dialect paths, a consistent register/string-stack ABI, adjacency
to the known two-argument entry, and pre-existing semantic support in the IR and
C runtime. The scanner accepts only canonical `ED/1e`; the fold requires the
existing AX value and exactly consumes haystack then needle from the string
stack. No generic unknown-dispatch fallback was added.

### Validation and unlock result

Focused scanner/fold coverage pins `CD ED 1E` to an `ir.Call("INSTR",
(start, haystack, needle))`. The full suite passes at **2188 passed, 14 skipped**;
Ruff passes, and `git diff --check` is clean. A before/after gap-report comparison
reported **four advanced, zero regressed**, removed the `unhandled INT ED sub
1e` signature, and kept the strict corpus result at 14 decode OK / 70 blocked.

Newly exposed blockers:

- `crossref.exe`: `unhandled byte 8b at 0xbda5`;
- `hebrew.exe`: `unhandled byte 36 at 0xdd02`;
- `be.exe`: later `pop from empty list` structural fold;
- `invent.exe`: later `READ chain closed without any stored target` structural
  fold.

The latter two are new gaps, not evidence against the `ED/1e` identification:
both programs scan and fold beyond every former dispatcher site before failing.

## Gap 33 — INT EC sub 38 (catalog/football/refund/varamort), UNDIAGNOSED

Grew from 2 files to 3 in the prior session when varamort.exe joined once its
unrelated BLOAD-with-no-offset gap closed (see "Recently closed" above)
and it advanced far enough to hit this same `cd ec 38` signature. It now blocks
four files: `catalog.exe` independently reaches it after the opaque-helper and
selector-cleanup closures. Otherwise unchanged from the investigation below.

Both original wild hits are TB 1.1/1.0 respectively (`canon_sub` already
normalizes the dialect difference, so it's genuinely the same feature).
Byte shape at football.exe 0x9e64:

```
be 8c 01     mov si, 018Ch        -- block disp (a runtime-DIM'd array)
ba 1a 0a     mov dx, 0A1Ah        -- relocated segment (exe reloc entry)
8e c2        mov es, dx
cd ec 38     int ECh, sub 38      -- FAILS HERE, no operand byte follows
be f0 06     mov si, 06F0h        -- next statement starts cleanly after
cd 9c        int 9Ch (rt push)
```

The `movsi <block>; movdx <reloc-seg>; movesdx` prefix is the SAME runtime-
array-block-reference convention used by `dim_begin`(0x2C)/`dim_end`(0x2E)/
`erase`(0x36) (core.py ~line 1716) and by GET/PUT graphics blit on a
runtime array (confirmed via probe `q_dynget.bas`: `DIM A(N)` then
`GET/PUT ..., A` emits this exact prefix before `get_gfx`/`put_gfx`). So
sub 0x38 is a FOURTH runtime-array-block operation, block-only (no operand
byte after the sub, no stack push before or after it in the 15-op window
captured) — same argument-shape as `erase`.

**Ruled out this session** (all compiled clean through the oracle with
ZERO occurrences of `cd ec 38`, so none of these are it):
- `ERASE A$` on a runtime-DIM'd STRING array (both 1-D and 2-D) — decodes
  fine via the EXISTING `erase` (0x36), no separate string variant exists.
- `ERASE A, B` (multiple arrays in one statement) — just repeats `erase`
  once per array.
- A runtime array declared/erased inside a SUB body (local scope) — same
  `dim_begin`/`erase` ops, no scope-exit auto-cleanup op emitted.
- `SWAP A, B` on two runtime arrays (array-level swap, not element-level)
  — compiles to the generic inline register-swap template (`swap:400:396`
  in the ops dump) using the arrays' own descriptor-pointer cells
  directly, not this ES:SI convention at all.
- `SUB SUB1(B())` (array by-ref SUB parameter) — TB rejects the syntax
  outright (`Error 425`), confirmed unsupported (same finding as gap 19).
- `REDIM A(N)` — TB doesn't have this keyword (`Error 414: "=" expected`
  parsing `REDIM` as a bare variable assignment target).

**Context captured but not yet exploited**: the statement immediately
before the mystery op is a COMPLETE, separate statement — `fild:3706;
movsi:1728; rt:156 (push string); str2num:LEN; movmem_ax:44; fild:44;
popop:/; fistp:44; fwait; movaxmem:44; movm_ax:1512` — i.e. `X% = <FP
expr> / LEN(S$)`, committing to scalar disp 1512, BEFORE the block-396
statement starts fresh. This confirms sub 0x38 takes no stack-pushed
argument at all (unlike a hoped-for "resize array to this new size"
operation, which would need to consume something at disp 1512) — whatever
0x38 does, it acts on the array block alone.

**Context AFTER the failure point, captured this session (2026-07-19)**
via iced-x86 directly on the raw bytes (properly re-aligned past the
3-byte `cd ec 38` this time -- an earlier attempt in the same investigation
misaligned by 3 bytes and produced garbage). Immediately following the
mystery op, football.exe has a LONG straight-line (no loop/jump) run of
`mov si,<src>; int 9Ch (push string desc); mov si,<dst>; int A0h (pop-
assign)` pairs -- i.e. many individual `<dst> = <src>` string assignments,
NOT a loop. The destination disps are perfectly sequential (FC4, FC8,
FCC, FD0, FD4, FD8, FDC, FE0 -- +4 each, a string array filled element by
element). The SOURCE disps looked scattered at first (6F0, 6D8, 6EC, 6D4,
6E8, 6D0, 6E4, 6CC) but interleave into TWO cleanly-descending sequences
four apart (odd positions: 6F0, 6EC, 6E8, 6E4; even positions: 6D8, 6D4,
6D0, 6CC) -- i.e. TWO other arrays, each walked in REVERSE index order,
zippered together into the destination array in forward order. Very
plausibly a roster-merge idiom for a program like football.exe (e.g.
combining two parallel arrays -- first names/last names, or two team
rosters -- into one, back-to-front). This did NOT pin down what sub 0x38
itself does (still block-only, no operand, no stack push/pop directly
around it) but narrows what KIND of array it plausibly sets up: almost
certainly a STRING array, given everything downstream is string
assignments.

**Tried this session based on that lead, all compiled clean with ZERO
`cd ec 38` occurrences (ruled out)**:
- A runtime-DIM'd (`DIM A$(N)` with N a variable) STRING array: bare
  single-element assign+read, a 3-element batch assign+read (multiple
  individual `A$(i) = scalar$` statements in a row, matching the
  surrounding evidence's shape), an UNINITIALIZED read before any
  assignment (testing a "must zero-init the descriptor table" theory),
  and a 2-D runtime-DIM'd STRING array (`DIM A$(N,M)`) with one
  element assign+read. NONE of these needed anything beyond the
  already-working `dim_begin`/`dim_end` pair -- so "runtime string
  array, however it's used" alone is NOT sufficient to trigger sub
  0x38; something more specific about the SURROUNDING construct (the
  two-array-merge shape itself? a specific size/element-count
  threshold? something about the SOURCE arrays' own shape, not just
  the destination?) is the real trigger, still unidentified.

**Reconfirmed 2026-07-20 with the restored vendored oracle:** a minimal
runtime-DIM'd string array followed by `ERASE V0$` emits canonical EC sub 36,
the same entry as numeric ERASE, and round-trips through the existing handler.
Temporarily routing sub 38 through the ERASE fold made all four wild files scan
past the call, proving only that they share the same array-block ABI; it did not
establish source semantics and was reverted. `CLEAR` is also ruled out by the
owner's handbook: it is parameterless and already has the distinct zero-operand
sub 14 entry. Do not identify sub 38 as type-specific ERASE or CLEAR.

Next steps: try actually constructing the two-array reverse-merge
pattern explicitly (`DIM A$(N), B$(N), C$(N)`, loop or explicit
statements copying `C$(i) = B$(N-i+1)` interleaved with `C$(i+1) =
A$(N-i+1)` or similar) to see if THAT specific shape reproduces it.

**Tried, ruled out** (new tool this session, `tbx/tools/batch_probe.py` --
compiles a directory of candidate .bas files against the oracle and scans
each, batching what used to be one-at-a-time manual probes; see its
docstring): the two-array reverse-merge pattern literally as described
above, in THREE shapes -- straight-line statements matching the observed
post-failure evidence exactly (`zipmerge.bas`), the same merge driven by a
`FOR...STEP 2` loop with a hand-decremented index (`zipmerge_loop.bas`),
and a plain `FOR I%=N% TO 1 STEP -1` descending loop copying a single
array in reverse into a forward-ordered destination (`zipmerge_negstep.bas`,
`revidx.bas` for the single-array-only variant) -- all FOUR compiled clean
and decoded with zero `cd ec 38` occurrences. So the reverse-merge SHAPE
itself, however constructed, is still not sufficient; whatever triggers
sub 0x38 is something else again. Also tried, inconclusively: `GET #n,
r, A$()` / `PUT #n, r, A$()` (a whole runtime array as a random-file
record target) as a wildcard hypothesis (GET/PUT graphics already use
this array-block convention, so file GET/PUT might share it) -- the
oracle automation got stuck mid-compile for both (screen froze on
"Compiling: SOLVER.EXE / Line: 1 Stmt: 1" with no error banner and no
produced EXE), which reads more like invalid syntax (TB's random-file
GET/PUT normally targets a FIELD-defined buffer, not a bare array) than a
real result -- not informative either way, not worth more oracle cycles
without first confirming the correct FIELD-based syntax from the
handbook.

Also tried: a runtime string array SHARED into a SUB (`SUB FILLIT:
SHARED A$(): A$(1)="X": END SUB`, with `DIM A$(N)` and the CALL in main
scope) -- this compiled but hit a COMPLETELY DIFFERENT, new dispatch-
level error (`mov es from non-array cell 0x120`, not a scan-level
"unhandled byte/INT" at all), meaning it exercises SOME gap but not
gap 33's specific signature (`cd ec 38` never appeared in this probe's
ops). Noted but not chased further this session -- worth a fresh probe
sweep of its own if picked up (start by getting its ops dump and
comparing against the working plain-runtime-array-in-main-scope case
to see exactly what SHARED changes). Do not guess the gap-33 decoder-
side fix without an oracle-confirmed probe reproducing `cd ec 38`
exactly -- per the calibration rule, a byte pattern only joins the
vocabulary once witnessed.

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

**More ruled out this session (2026-07-18)**, using a traceback-frame
technique to extract the partial `ops` list `_scan()` had built before
raising (frame walk to the deepest traceback frame, `frame.f_locals
["ops"]` — faster than the earlier temporary-source-edit approach,
worth reusing): baby.exe's own immediate context before the fail point
is `... CLS; mov word[0078h],0; [trap_hook]; <FAIL>` — cell 0x78 first
looked like it might be a special system cell (it's WELL below the
usual VAR_BASE≈0x120), but since `movm_imm` decoded it successfully as
an ordinary scalar store with no special-casing anywhere in its
handler, it's almost certainly just a plain user scalar in THIS
program's particular layout, not a system cell — not a lead after all.
Tried, still zero `cd 86` in any output: **8 simultaneous `ON KEY(n)
GOSUB` declarations** (matching baby.exe's actual F1-F8 count, `q_
onkey8.bas` — previous sessions only tried 1-2), the SAME 8-trap probe
recompiled **with the Keyboard-break ('K') toggle** via the oracle's
`--toggles K --tb tb10_floppy.img` lower-level path (all three wild
files carry 'K'), and a **`CLS` + plain assignment before `RETURN`
inside two ON-KEY handler bodies** (mimicking the exact local shape
found above). The local-context finding (CLS then an assignment
directly preceding the fail point) suggests the trigger is something
inside a HANDLER BODY reacting to a SPECIFIC STATEMENT SHAPE that
follows CLS+assignment, not to trap count/toggles/K — still
undiagnosed; a genuinely different follow-on statement inside the
handler (e.g. an INKEY$ read, a LOCATE, a nested IF) is the next
category worth trying, not more ON KEY variations.

## Gap byte ea (elec87/mcmurphy/mf/swbb), UNDIAGNOSED — ">64K" theory REFUTED

The prior assumption ("likely multi-segment-code JMP FAR, >64K code, big
lift") does NOT survive scrutiny this session. `0xEA` is the raw x86 `JMP
FAR ptr16:16` opcode (5 bytes: `ea off_lo off_hi seg_lo seg_hi`) — but:

- **All 4 files have ZERO MZ relocation entries** (`e_crlc == 0` in the
  header). A genuine cross-segment far jump whose target segment depends
  on the program's LOAD segment would need a relocation entry to patch
  that segment field at load time; none exists anywhere in these files.
  So the segment field is either a self-relocating runtime-patched value
  (unconfirmed) or, more likely given the next finding, not really a
  segment at all in the usual sense.
- **The computed linear target (`seg*16 + off`) lands VERY CLOSE to the
  jump site**, not far away: elec87.exe's occurrence at file offset
  `0x10a82` (`jmp 0F9Eh:10D6h`) computes to linear `0x10ab6` — only 52
  bytes past the jump instruction itself. mf.exe's occurrence similarly
  computes to a target ~14.6KB forward — comfortably within ordinary
  `e9`/rel16 near-jump range. A genuine ">64K, can't reach with rel16"
  jump would need a target that's actually far in absolute terms; these
  aren't.
- Both distances are trivially reachable with a near jump, and this
  session's decoder ALREADY handles near jumps at much greater distances
  elsewhere in the very same files (ops immediately preceding the
  failure show ordinary `jmp` targets 15-17KB away, handled fine) — so
  raw distance isn't gating the near-vs-far choice either.
- Two of the four files (elec87.exe, mf.exe) show the SAME structural
  shape immediately before the failure: `Jcc rel8=5 (skip); jmp far
  seg:off` — a dispatch pair exactly analogous to the ordinary `Jcc
  rel8=3; jmp rel16` "skip this near jump" pattern used everywhere else
  in the decoder (cmpax_m's IfGoto, the compound-bool machinery, etc.),
  just with a 5-byte far jump standing in for the usual 3-byte near one.
  Confirmed NOT coincidental: `_scan()`'s byte-exact instruction-length
  bookkeeping means every byte before the failure was already consumed
  by a real, correctly-decoded instruction, so the preceding `Jcc`
  really does skip exactly this far-jump's length.
- Extracted the pre-failure op stream via the traceback-frame technique
  (see "Reproducing the investigation" above): elec87.exe's failure
  follows **100 `strcmp` ops** already scanned (out of 5839 total ops up
  to that point) — each `strcmp` paired with its own `Jcc`+`jmp`, i.e. a
  long chain of string comparisons (a big `SELECT CASE`-on-string or
  `IF ... ELSEIF A$ = "..." THEN ...` chain, or a command-word parser).

**Ruled out this session** (compiled via the oracle, decoded clean, no
byte-ea anywhere): a 60-arm `SELECT CASE` on strings (`q_bigselect.bas`,
37KB total); a 400-arm flat `IF/ELSEIF` chain on strings (`q_bigif.bas`,
56KB total — comparable to the SIZE where elec87 fails, ~68KB into its
user code, but the shape didn't reproduce); a 900-arm string chain hit
an UNRELATED pre-existing gap first (`"string char record not found"`,
likely a string-pool-scaling limit distinct from gap 30's fix — noted
but not chased, out of scope here); a 1400-arm chain on INTEGER (not
string) comparisons scanned cleanly with ordinary near jumps throughout
(16802 ops, no byte-ea) but hit a `RecursionError` in `_fold_if` at the
LATER block-folding stage (Python recursion limit from 1400 levels of
nested ELSEIF-as-nested-IF folding — a real but separate latent bug,
not relevant to wild files which won't nest anywhere near that deep).

**Not yet tried**: reproducing elec87.exe's specific shape more
precisely — STRING comparisons specifically (not integer, which didn't
reproduce it even at large scale) in a FLAT (not deeply-nested) chain,
at a size in the tens of KB, combined with whatever ELSE elec87.exe's
program does (its file is 155KB total, likely has arrays/SUBs/graphics
alongside the string-parser chain — the trigger might depend on
something in COMBINATION with the string chain, not the chain size
alone, since a bare 400-arm string chain at a comparable byte offset
did NOT reproduce it). Also worth checking: does the LAST arm of a
chain (the one immediately before `END IF`/`CASE ELSE`/`SELECT
END`) compile differently from earlier arms — the failure might be
specific to how the FINAL fallthrough is encoded, not to arm count.

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

**Two of those four candidates ELIMINATED this session (2026-07-18)**:
`VIEW PRINT` and `PCOPY` are not TB keywords at all — the oracle rejects
both (`Error 412: "(" expected` for `VIEW PRINT...` — the parser reads
`VIEW` as the graphics-viewport statement wanting `(x1,y1)-(x2,y2)`, with
no PRINT-region variant; `Error 414: "=" expected` for `PCOPY 0,1` — the
parser reads `PCOPY` as an undeclared variable name wanting an
assignment). Neither exists in this dialect at all, so neither can be
the trigger. Remaining untried: `WIDTH`-mode-dependent fast PRINT (tried
a bare `WIDTH 40` + `PRINT` combo this session, and separately a plain
`SCREEN 0` + `PRINT` combo — NEITHER produced the signature bytes
`55 8b ec 06 1e 8b 16 00 00`, so those specific minimal forms are ALSO
ruled out now, though a WIDTH-40-plus-something-else combination isn't
exhausted) and text-mode GET/PUT (not yet tried — TB's GET/PUT may only
exist for graphics arrays/file records, worth confirming it's even valid
syntax on a plain text "screen" before spending a probe on it, the way
VIEW PRINT/PCOPY just turned out not to exist).

(A previous version of this section carried a schart.exe DGROUP-layout
trace — that was a mis-filed duplicate of the gap-16 investigation, since
resolved by gap 28; schart.exe is unrelated to this byte-06/by-ref-param
gap.)

**CVT2TB.EXE identified as a 10x-repeated instance of THIS SAME gap, with
an encoding wrinkle (2026-07-19)**: while investigating a separate
"byte 89" tally entry, CVT2TB.EXE's occurrence turned out to be `push bp;
mov bp,sp; push es; push ds; les si,[bp+06/0Ah]; ...` -- byte-for-byte
this SAME gap-19 template, appearing 10 TIMES in the file, not a
different construct. The only difference: CVT2TB.EXE's compiler encodes
`mov bp,sp` as `89 E5` (the "MOV r/m,r" direction, reg=sp/rm=bp) instead
of gap-19's original witness's `8B EC` ("MOV r,r/m", reg=bp/rm=sp) --
the SAME two-encodings-for-one-instruction ambiguity already fixed
elsewhere this session for `mov bx,ax` (`8B D8` vs `89 C3`, see the
array-SWAP gap in Recently Closed). Both `89 e5` (10x) and `8b ec` (80x)
coexist throughout CVT2TB.EXE, so this isn't a wholesale different
compiler build -- something CONTEXTUAL selects the encoding, but
several DEF FN / nested-string-concat probes this session produced
`8b ec` in 100% of cases (42+ instances checked across one probe, zero
`89 e5`), so the specific trigger for the alternate encoding is still
unfound. **Do not add scan support for `89 E5` as mov_bp_sp in isolation
without a witness** -- it was tried this session and reverted (same
calibration-rule reasoning as the byte-89/`di` register section above:
mechanically obvious, zero risk, but no fixture). Once gap 19's actual
triggering BASIC construct is found (whatever compiles to this whole
push-bp/mov-bp-sp/push-es/push-ds/les template), check which encoding
IT produces and land that one first; the other encoding will still need
its own separate witness if it doesn't naturally appear too.

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
