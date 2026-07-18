# Wild-corpus gap campaign — handoff

Status as of 2026-07-18 (session gaps 46-53 + line-table epic progress),
branch `claude/claude-md-docs-mr8ssz`.
Standing instruction: close the most common decoder gap first, in frequency
order, over the 84 wild PC-SIG Turbo Basic EXEs in `wild/hits/` (untracked,
gitignored, copyrighted shareware — **never commit them**).

## Where things stand

84 wild EXEs: **8 decode OK** (ck, onelab87, onelabel, mm, autonum, rev,
startup, schart), 76 fail. vhfprop.exe DROPPED OUT of decode-ok this
session (was 9) — not a regression, see "vhfprop status" below: it now
fails LOUD on a real, previously-silent bug instead of silently emitting
wrong line numbers. Fresh tally (2026-07-18):

| count | error | status |
|---|---|---|
| 16 | INT cd | unwitnessable runtime-revision artifact — not actionable (see `scan_wild.py` docstring) |
| 5 | byte 90 | set aside (4, unwitnessable) + rstprint.exe (1, undiagnosed whether it's the same shape) — **next stop** |
| 4 | byte ea | likely multi-segment-code JMP FAR (>64K code) — big lift, not a small gap |
| 3 each | INT 8c; byte 06 | both extensively probed earlier, still undiagnosed (sections below) |
| 2 each | EC sub 66, EC sub 38 (gap 33, stuck), FP de/1e, FP dc/04, FP da/1c, byte 8c/8b/89/29/1e, system cell 0x8a | mostly untouched |
| 2 | "jump target 0x15740 is not a statement start" (inv87/invoice) | the LINE-TABLE EPIC below — a GOTO target nested TWO block-IF levels deep; single-level interior targets were closed as gap 51 |
| 2 | COLOR mask 07 != cells 06 (r.exe + one more) | untouched |
| 1 | "statements don't map 1:1" (vhfprop) | the LINE-TABLE EPIC below — DATA/DIM sub-problems now CLOSED; the bare-DO-normalization sub-problem is what's left |
| singles | see scan output | untouched |

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

### vhfprop status: NEW, narrower blocker found (bare-DO vs line tables)

After the DATA/DIM fixes, vhfprop.exe advances to a NEW error:
`"error-trap line table present but statements don't map 1:1 to its
entries"` — a REAL bug, not a regression. Root cause (confirmed via a
temporary debug patch, then a matching probe q_lt8): `core.py`'s "bare
backward jmps = infinite DO" path (~line 1217-1221, comment: `elif op[2]
< addr and op[2] in state.addrs`) ALWAYS canonicalizes a backward jump
loop into synthesized `ir.Do(None)` + `ir.Loop(None)`, regardless of
whether the ORIGINAL source spelled it `DO...LOOP` or was a plain
`GOTO`-based loop — both compile to IDENTICAL bytes, so the decoder can't
tell which from the op stream alone. Probe q_lt8 proved an EXPLICIT
`DO...LOOP` (no WHILE/UNTIL) DOES get its own codeless orphan entry in
the table (same borrowing convention as DATA/DIM) — but vhfprop's TWO
`Do` statements (prog indices 259, 281; body starts at file offsets
0xf62/0x1100) have NO matching orphan anywhere in vhfprop's validated
734-real-entry table (confirmed: `ent[0xf62]=600`, `ent[0x1100]=722`,
single entries, no duplicates). So vhfprop's loops were almost certainly
plain `GOTO`-based in the original source, not `DO...LOOP` — meaning the
EXISTING bare-DO canonicalization is ALREADY lossy in a way that's
invisible under free renumbering but genuinely non-byte-exact once a line
table is active: emitting our canonicalized "DO" would introduce an EXTRA
table entry the original never had.
**Not fixed this session** — this needs either (a) reproducing literal
`GOTO`-loop syntax instead of canonicalizing to DO when the table shows no
orphan there (invasive: touches the existing, previously-untested-against-
line-tables DO-canonicalization convention), or (b) accepting the
combination as unsupported for now. Diagnose fresh with `_line_table`
before guessing.

### Still open: inv87's nested block-IF GOTO target

inv87's "jump target 0x15740": a Goto nested inside an IfInline inside
another IfInline (nested numbered block-IFs). The single-level BodyLine
mechanism (gap 51) doesn't reach it; with the line table now closer to
usable, interior targets should resolve naturally to original line
numbers instead of phys arithmetic once inv87 itself is retried (it
wasn't this session — pick up here next: does inv87 even reach this stop
now, or does it hit a NEW DATA/DIM/bare-DO-shaped stop first?).

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

1. **vhfprop's bare-DO-vs-line-table gap** (above) — narrower now than the
   original "line-table epic," but still open; OR **inv87's nested
   block-IF** (also above, needs a fresh retry first) — pick whichever
   turns out smaller once inv87 is retried against today's fixes.
2. **Byte 90 (5 files)** — diagnose rstprint.exe's occurrence (one hexdump
   settles whether it matches the set-aside NOP-pair shape).
3. **Byte ea (4 files)** — scope the JMP FAR multi-segment theory on
   mcmurphy/mf/swbb before deciding attempt vs set-aside.
4. **INT 8c (3 files)** — ON KEY GOSUB lead; untried probes listed in the
   gap section below.
5. **Byte 06 / gap 19 (3 files)** — CGA snow-avoidance blitter; probe
   VIEW PRINT / WIDTH PRINT / PCOPY / text GET/PUT one at a time.
6. **The 2-tier** — re-tally after each closure; for FP gaps check the
   `[si]` FP table for missing rows first.
7. Singles last, same workflow.

## Recently closed (this campaign, newest first)

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

## Gap 33 — INT EC sub 38 (football.exe/refund.exe), UNDIAGNOSED

Both wild hits are TB 1.1/1.0 respectively (`canon_sub` already normalizes
the dialect difference, so it's genuinely the same feature). Byte shape at
football.exe 0x9e64:

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
0x38 does, it acts on the array block alone. Worth re-examining: get much
more context AFTER the failure point (patch scan.py's `raise` line to a
temporary `continue`+print, as this session did, then revert — do NOT
commit a "handled" stub without an oracle-verified probe) to see what
STATEMENT-LEVEL pattern (not just the immediately-preceding one) precedes
this block reference in the actual source, since neither file's `.bas` is
recoverable. Untried candidate statements: `CLEAR` variants that also
touch a specific array, `COMMON`-shared dynamic array cleanup, an
ON-ERROR-triggered implicit ERASE, or a GET/PUT FILE (not graphics)
`#n, rec` where `rec` is itself a runtime-DIM'd array element buffer
(distinct from the already-working FIELD-based GET/PUT). Do not guess the
decoder-side fix without an oracle-confirmed probe reproducing `cd ec 38`
exactly — per the calibration rule, a byte pattern only joins the
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
resolved by gap 28; schart.exe is unrelated to this byte-06/by-ref-param
gap.)

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
