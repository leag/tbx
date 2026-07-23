# tbx wild-corpus gap campaign — combined plan & handoff

This file merges what used to be three separate documents into one:
`REMAINING_GAPS_PLAN.md` (the forward-looking work queue), `HANDOFF.md`
(the chronological investigation log), and
`docs/intra-inline-if-goto-spec.md` (a deep-dive spec for one specific
open gap). They're combined here so a session picking up this work has
one file to read instead of three. The original three-way split was
intentional (see Part I's own note below on why the plan and the handoff
were kept apart) — this merge is a readability/discoverability call, not
a reversal of that reasoning; the sections below still play the same
roles they did as separate files.

## Table of contents

- **Part I — Execution plan** (formerly `REMAINING_GAPS_PLAN.md`): what
  to do next, in what order, and how a session proves it made progress.
  Start here.
- **Part II — Spec: intra-inline-IF-body GOTO targets** (formerly
  `docs/intra-inline-if-goto-spec.md`): a focused investigation spec for
  one specific open gap (state.exe/state87.exe), referenced from Part I's
  work queue and from Part III's investigation log.
- **Part III — Investigation history / handoff log** (formerly
  `HANDOFF.md`): the full chronological record of discoveries, closures,
  and dead ends across the campaign. Newest entries are at the top.

---

## Part I — Execution plan


This is the resumable work plan for finishing the Turbo Basic decoder campaign.
It plays a deliberately different role from Part III below: Part III preserves
discoveries and historical evidence; this part says what to do next, in what
order, and how a future session proves that it made progress. (The two used to
be separate files for exactly this reason — see the top of this document for
why they're now merged into one.)

### Project scope

The project target is **all Turbo Basic syntax**, across documented language
editions, compiler dialects, and compatible runtime revisions—not merely the
constructs currently listed in the Borland handbook. The handbook is a reference
and source of semantics, not a whitelist or completion boundary.

Track support in three dimensions: source syntax recognition, bytecode decoding,
and semantic/runtime fidelity. A construct may be source-known but bytecode-
unwitnessed, or bytecode-known but absent from the handbook; neither case is
silently discarded. Every new fixture and gap-ledger entry records its dialect,
edition/runtime tag, and evidence provenance.

### Live checkpoint

- Updated: 2026-07-23 (fifth round, same day)
- **Oracle correction**: earlier rounds this session incorrectly believed
  no `TBX_ORACLE` was available -- a stale relative-path `ls` check gave a
  false negative. The vendored oracle at `tbx/vendor/turbo_basic_oracle`
  works fine (`oracle.preflight()` passes, `oracle.compile_bas` compiles
  real programs). This unblocked a proper, byte-exact-verified fix -- see
  Part III's newest entry ("mixed-precedence compound-IF chains").
  Summary: `_match_bool_term1`/`_lift_bool_tail` (the AND/OR compound-IF
  folder) had TWO real bugs, found via 7 oracle-compiled probes
  (byte-exact round-trip confirmed for all): (1) it only ever recognized
  a mixed-precedence switch when the differently-combined continuation
  was the SINGLE immediately-next term, not a multi-term inner GROUP
  (`A OR B AND C` = `A OR (B AND C)`, wild wb.exe/grdscn.exe/mcmurphy.exe
  shape) -- fixed via a new `pend_bool_outer` deferred-fold mechanism
  (control.py + lift.py); (2) the join operator was being derived from
  WHICH candidate matched during the lookahead search instead of the
  term's own fixed dispatch polarity, silently swapping AND/OR in the
  outer join for exactly the multi-term-group case. Two of the 7 probes
  promoted to fixtures (`t1_mixedbool2`, `t1_mixedbool3` + `v10_`),
  pinned in `test_compound_if.py`. `mcmurphy.exe` advanced fully past
  this family into a SEPARATE, newly-exposed bug (a corrupted `Gosub`
  target, `jump target 0xe989b00 ...` -- an obviously-wrong huge address,
  unrelated to compound-booleans). DIAGNOSED (not fixed): the raw op is
  `('call', 244882176)` from scan.py's stack-test-GOSUB path (`vec==0x8A`,
  reads a 4-byte i32 start-relative offset, `+= 6` per site --
  `fst_t1_gosub` witnesses this cleanly with the 'S' toggle ALONE). But
  mcmurphy.exe's toggles are `'KBOS'` (Keyboard break + Bounds + Overflow
  + Stack test ALL active) -- a combination no existing fixture
  witnesses. The i32 read at this exact site (`00 00 98 0e`) produces
  garbage, meaning either another toggle inserts extra bytes before this
  callsite that the scan doesn't account for (a drift, not a parsing
  bug in this function itself), or the multi-toggle interaction changes
  the encoding directly. Needs its own oracle probe compiled with ALL
  FOUR toggles together (`node tb_v86_compile.js probe.bas --compile-exe
  --toggles KBOS --tb <floppy>`, per this repo's memory notes -- the
  `oracle.compile_bas` wrapper has no toggle parameter) before touching
  anything -- flagged as the concrete next step for mcmurphy.exe
  specifically, separate from the compound-IF fix above. `wb.exe`/
  `grdscn.exe` still fail on "materialization template mismatch" at the
  SAME addresses as before -- their actual shapes aren't among the 7
  verified probes (possibly the explicitly-parenthesized-group case,
  `probe6`/`mixchain6.bas` in scratch, which decodes but visibly
  mis-orders terms -- a separate, pre-existing bug, untouched).
  `number.exe`/`hfprop.exe` ("ax,bx combine with empty regs") and
  `process.exe` ("empty di spill") DIAGNOSED PRECISELY this round (a
  SIXTH round, same day): a compound boolean used as an assignable
  VALUE, not a branch condition (`V% = (A%=1) AND (B%=2) OR (C%=3)`),
  compiles with NO dispatch-pair template at all for 3+ terms -- each
  term materializes straight into ax with no self-test, gets combined
  via `andaxbx`/`oraxbx` directly, and the FINAL combine's result stores
  straight to the target (`movm_ax`). control.py's existing "no dispatch
  pair" handler (already witnessed for a 2-term case, `wild process.exe/
  tamstart.exe`) sets `state.ax = Group(BinOp(term))` and defers the
  ACTUAL combine to `int_bitwise_bx`'s generic `andaxbx`/`oraxbx`
  handler -- which orders operands `ax op bx` (current term op
  accumulator), correct for a 2-term case but WRONG once a 3rd term
  chains on: it silently reorders to e.g. `C OR (A AND B)` instead of
  `(A AND B) OR C`. Confirmed via a clean oracle probe (`valuebool.bas`,
  scratch) that decodes without crashing but fails byte-exact
  recompilation. NOT fixed: the correct repair needs a new way to
  distinguish "bx holds an accumulated chain value" from "bx holds an
  ordinary arithmetic operand" without perturbing `int_bitwise_bx`'s
  other callers (a shared, heavily-exercised function) -- `isinstance
  (state.bx, ir.Group)` looked promising but the accumulated result
  itself must NOT be Group-wrapped (no extra parens belong in the
  rendered source for the whole chain, only per-term), so that marker
  doesn't survive to the next fold. A dedicated state flag (mirroring
  `direct_bool_gate`) is the likely right shape but needs its OWN
  probe-verified lifecycle (when to set/clear) before landing --
  flagged as the concrete next step for this file family, not attempted
  this round given the risk of touching shared arithmetic-combine code
  without full verification.
- Wild tally: still **25/84** (no new full closure this round either --
  `mcmurphy.exe` got past one whole gap family into a fresh one). The
  fix itself is real, oracle-verified, and lands regardless.
- Current validation: 2449 passed, 16 skipped; Ruff clean.

### Historical checkpoint (fourth round, same day, believed no-oracle)
- Branch: `claude/claude-md-docs-mr8ssz`
- Baseline commit: `b22c0a4` (`Merge AGENTS.md into CLAUDE.md; split
  wild-probe corpus from wild/hits`)
- Corpus: `wild/hits/` (84 Turbo Basic executables found in the wild;
  gitignored, never commit) -- the 9 oracle-authored probes formerly
  mixed into this directory now live in the separate, git-tracked
  `wild/probes/`, per the tightened directive in `CLAUDE.md`.
- Current strict result: **25 decode OK, 59 blocked** (was 23/61) --
  `state.exe`/`state87.exe` newly close via the intra-inline-IF-body
  GOTO-target fix (see Part III's 2026-07-23 "RESOLVED" entry). Oracle
  verification/fixture promotion for that fix is explicitly deferred to
  a later phase (no `TBX_ORACLE` this session). A second 2026-07-23
  round (same day, "continue decoding wilds one at a time" directive)
  landed four more table-completion fixes without moving the strict
  tally (each advanced a file into its NEXT gap rather than closing it
  outright) -- see Part III's dated entries: `notax`-negated materialized
  loop/IF test (kinder.exe), `far_dec_si`/`far_subax_si`/`icomp_bp` (the
  DEC/SUB/mixed-compare siblings of already-calibrated by-ref-param and
  LOCAL-int op families, bmaster.exe/ifi.exe). `secure.exe` traced and
  confirmed a DEEPER, different gap (multi-arm/ELSE block interior GOTO
  targets, unwitnessed) -- explicitly not attempted. A RESTORE-past-
  last-DATA-item boundary bug (styled.exe/styllist.exe, `KeyError` on an
  unguarded dict lookup) was traced to the exact line but NOT fixed --
  the correct index convention affects the byte-exact RESTORE line
  number and isn't safely inferable without oracle verification.
  A THIRD 2026-07-23 round ("fully decode a wild" directive, still no
  oracle) landed seven more sibling-completion/relaxation fixes -- see
  Part III's newest dated entry. Still 25/84 strict (every advance again
  landed on a NEW gap): LINE's omitted-first-point form (`LINE
  -(x2,y2)`, cal87.exe) and LINE INPUT into a computed string-array
  element (cal87.exe, mirrors the already-calibrated INPUT/_INPUTREAD
  mechanism); `andax_bp`/`subax_si` (array-element)/`icomp_si`/
  `ifold_si`/`ifold_n_si` (filepatc.exe/hebrew.exe, more missing
  siblings in the same op-table families as the second round); a string
  relational-as-value assigned directly to a scalar (`V% = A$ = B$`,
  hebrew.exe); OPEN's reclen argument accepting any numeric expression,
  not just a literal (hebrew.exe). Each landed file advanced into a
  distinct next gap (`unhandled op testw`, `unhandled byte c4` x2,
  `unhandled materialized test`, `FIELD with no AS-entries`, `unhandled
  INT EE sub 08`) -- none fully closed this round. FIELD's width being a
  computed expression (hebrew.exe's newest blocker) needs a real
  redesign (the current parser assumes a fixed 5-op window per field
  entry; a computed width needs incremental expression evaluation
  instead) -- flagged, not attempted.
  A FOURTH 2026-07-23 round (still "fully decode a wild", still no
  oracle) DID implement the FIELD redesign (the third round's flagged
  next step) plus two more fixes -- see Part III's newest entry. Still
  25/84 strict. FIELD is now parsed incrementally (`state.pend_field`,
  closed lazily via `flush_pending` like READ/INPUT#/PRINT), so its
  width -- literal or computed -- accumulates through the ordinary
  per-op dispatch with no bespoke evaluator; this closed hebrew.exe's
  FIELD gap outright (advanced to a new, unrelated one) and is a strict
  generalization validated against the existing multi-entry `t1_field`
  fixture. A shared "far string variable read" gap (`movsi;movdx;
  movesdx;str2num`, reading a FIELD-buffer string variable as a CVL
  argument) turned out to hit THREE files identically (hebrew.exe,
  morcalc.exe, photo.exe) -- confirmed the movsi disp is always an
  already-tracked string scalar in all three before pushing `state.loc
  (disp)` onto sstack, advancing all three past a shared blocker at
  once. A structural bug in DEF-FN-region detection: `ON ERROR GOTO` as
  the program's literal first statement (before the entry skip-jmp)
  left `state.main_start` permanently unset, since the existing
  detection only recognized the skip-jmp AS op 0 or immediately after a
  closed proc/fn's ret -- added a third, narrowly-scoped case (exactly
  one prior statement, and it's `ir.OnError`) fixing wb.exe's `fold_bp`
  gap (advanced further). Three of the four newly-exposed follow-on gaps
  are in the SAME risky "3+-term compound-boolean register choreography"
  family already set aside earlier (grdscn.exe/wb.exe/mcmurphy.exe's
  `andaxbx`-combine shapes) -- confirmed via trace, not reattempted.
  photo.exe's new gap (`jump target ... not a statement start`) is
  freshly-exposed territory (only reachable after this session's OWN
  CVL fix) with a DIFFERENT signature than both state.exe's (fixed) and
  secure.exe's (deeper, unfixed) cases -- traced enough to rule out both
  known shapes but not fully diagnosed.
- Current validation: 2439 passed, 16 skipped (2026-07-23); Ruff passes.
  `t1_localarr`/`t1_localarrint` (+`v10_`) are byte-exact both dialects.
- Immediate target: the "3+-term compound-boolean register choreography"
  family (grdscn.exe/wb.exe/mcmurphy.exe/number.exe/hfprop.exe/
  process.exe) is now the single most-repeated blocker across the
  corpus -- worth a dedicated, carefully-evidenced investigation (oracle
  probes to pin down exact AND/OR/mixed-precedence register
  choreography) before the next attempt, rather than another one-off
  guess. `unhandled INT 8c` and `unhandled op testw` (both tied at 5)
  remain the next-largest untouched buckets.

### Gap: LOCAL DYNAMIC arrays (`LOCAL A()` + runtime `DIM A(n)` inside a SUB), CLOSED for rank 1 (2026-07-23)

Previously the single largest wild tally bucket (`unhandled byte 8b`, 4 files:
cleanup, crossref, filepatc, reformat, plus 2 retained oracle probes
`probe_localdecl*.exe` from a prior session's Gap 33 investigation). This is a
genuinely new decoder subsystem, not a small vocabulary addition: `LOCAL A()`
declares an array that's heap-allocated fresh on every call (unlike a static/
runtime DGROUP array, which lives in a fixed compile-time-sized region for the
program's whole lifetime).

Byte shape (probe `q_localarr.bas`: `SUB SUB1: LOCAL A(): DIM A(5): A(2)=7:
PRINT A(2): END SUB`): `local_init` reserves a fixed **30-word (60-byte)**
template regardless of rank/type (confirmed identical for rank-1 and rank-2
probes; only 5 of the 30 words are ever written -- the rest is dead padding
sized for whatever rank the runtime supports). The template's first word is a
handle cell (the heap segment, filled by the runtime); DIM's codegen writes
`(rank<<8)|tb` and the element byte-size into the SAME two words TWICE --
once before `dim_begin`, once after (as a `mov_bp_imm` pair each time) --
then the bound cell(s) (`lo`/`hi`) once, all bracketed by a NEW ES:SI setup:
`mov si,bp; add si,d8; [into;] push ss; pop es` (new op `far_ref_bp`, the
LOCAL-frame sibling of movsi's DGROUP-disp form that already fronts ordinary
`dim_begin`/`dim_end`/`erase`; the optional INTO is the Overflow-toggle skip
from Gap 21, witnessed interposed here in wild cleanup.exe). Element access
loads the heap segment via a NEW op `moves_bp` (`8E 46 d8` = `mov es,[bp+d8]`,
the LOCAL-frame sibling of `moves_m`), then falls straight through the
EXISTING `far_fld`/`far_fstp`/`far_fild`/`far_movm_ax_disp`/shlsi-chain
consumers unchanged, by registering the array into `state.r_arrs`/
`state.slot_info` keyed by its LOCAL frame disp (safe: only one SUB's local
array is ever "open" at decode time, and LOCAL scope means no cross-SUB
reference is possible). At SUB exit, `movsi <handle disp>; int EC sub 3A`
implicitly frees the heap block -- no BASIC source spelling, so it's a pure
compiler-generated marker (new op `local_arr_free`), consumed and dropped
like `local_init`'s own zero-fill prologue.

`ir.Local`'s declaration list gets the array's canonical `V#`-style name with
a literal `()` suffix appended (`"V0()"`), mirroring the EXISTING
`ir.Shared`/`ArrayRef` "array names are already canonical, don't re-letter"
convention (`rename.py`); the descriptor's other 29 reserved words are folded
into the SUB's existing `hidden_locals` mechanism so they don't leak as
phantom scalar declarations. `ir.Dim`'s `dynamic` flag is always `False` here
even for a constant bound (`dynamic` reconstructs whether the *DYNAMIC*
keyword was used in source, which this construct never spells -- unrelated
to whether the array happens to be heap-allocated).

Scope of this closure: **rank 1 only**, element type integer (`tb=0x00`) or
single (`tb=0x04`) -- the two shapes directly probed and oracle-verified
byte-exact (`t1_localarr` single, `t1_localarrint` integer, both dialects).
Rank 2 was probed (`q_locarr3.bas`, unpromoted) and confirmed to reuse the
SAME 30-word template with additional bound-cell writes at the expected
`ARR_BLOCK`-relative offsets, but its variable-index element access needs the
existing computed-index span machinery (`imul_bp`/`movsiax`/`addsiax`) taught
to recognize a LOCAL array's own span fields instead of treating them as
ordinary LOCAL scalars (`imul_bp`'s existing consumer calls
`state.loc_local` unconditionally) -- a real follow-on gap, deliberately left
fail-loud (`unsupported LOCAL DIM rank ...`) rather than guessed. String/
double element types are similarly unwitnessed and fail loud
(`unsupported LOCAL DIM element type ...`); `probe_localdecl.exe` (a
`LOCAL A$()` retained oracle probe from the prior session) hits exactly this
guard. A LOCAL array mixed with OTHER real LOCAL scalars in the same SUB
(changing `frame_words` away from the calibrated 30) is also unwitnessed and
guarded (`unsupported LOCAL frame shape ...`).

`c0.py` raises `_Unsupported` for this too, same as every other `ir.Local`
(true per-call locals need real non-static C storage, not modeled yet) --
waived in `test_c0.py` alongside `t1_local1`/`t1_local2`/etc.

Wild results: cleanup.exe/crossref.exe/filepatc.exe/reformat.exe all advance
past their `byte 8b` failure into four DIFFERENT new gaps (`INT 94` x2 for
cleanup/reformat, `INT 8c` for crossref, `byte 23` for filepatc) -- no shared
follow-on blocker, consistent with the campaign's usual pattern that closing
one gap exposes the next distinct one per file. `probe_localdeclnum.exe`
(retained integer-array oracle probe) advances all the way to a `jump target
... is not a statement start` structural-fold gap. Strict wild count stays
26/93 this round (no file happened to fully close), but 5 files advanced.

The number 70 is a count of blocked executables, not distinct missing features.
Every fix can reveal a later failure in the same executable. Completion therefore
means 84/84 decode OK (or an explicitly documented, policy-approved exclusion),
not merely exhausting the current first-failure list. Report two metrics:

- **Strict:** executables that decode completely. The final target is 84/84.
- **Calibrated:** strict successes plus patterns formally classified as runtime
  revision skew after exhaustive probes. This communicates useful coverage but
  never permits the decoder to accept unwitnessed bytecode.

Report regressions separately so calibrated exclusions cannot hide a previously
decoding file that has started failing.

### Resume procedure

At the start of every session:

1. Read this file's live checkpoint and latest entries in the progress log.
2. Check `git status --short --branch`; preserve unrelated user changes.
3. Generate a fresh machine-readable working report:

   ```bash
   UV_CACHE_DIR=/tmp/tbx-uv-cache uv run python tbx/tools/scan_wild.py \
     wild/hits --report /tmp/tbx-gap-report.json
   ```

4. Compare it with the latest tracked sanitized checkpoint under `gap_reports/`.
   The JSON `groups` array is sorted by descending affected-file count. Update
   the tracked checkpoint only after validation and include it in the closure
   commit. Reports contain names and diagnostics only, never executable bytes.
5. Continue the first unchecked work item whose prerequisites are satisfied.
6. Before ending, update the live checkpoint and progress log. Commit only a
   coherent, verified closure; never commit wild binaries or oracle executables.

### Definition of a closed gap

A gap is closed only when all applicable gates pass:

- The source construct is identified from compiler-oracle evidence, dialect
  documentation, surviving compiler/runtime artifacts, or an equally strong
  byte-level proof. Similar-looking opcodes are not sufficient.
- A minimal fixture is added under `tests/fixtures/corpus/` when the oracle can
  reproduce the byte pattern, with matching ops/user-code snapshots.
- Decoder and IR/render/C changes preserve fail-loud behavior for shapes that are
  still unknown.
- Focused tests cover the new construct and any dialect or arity variation.
- `ruff`, `git diff --check`, focused tests, and the full test suite pass.
- A fresh wild report demonstrates the expected files advanced or completed and
  shows no reduction in the decode-OK count.
- The change is committed independently with the progress log updated.

If the installed compiler cannot reproduce a wild pattern, classify it by the
strongest available evidence: `oracle-verified`, `dialect-verified`,
`documentation-backed`, `runtime-revision`, or `unresolved`. Runtime-revision and
documentation-backed constructs remain in scope; a missing local oracle is an
evidence limitation, not a scope exclusion. Preserve fail-loud behavior only for
genuinely unclassified bytes.

### Standard gap workflow

For each target signature:

1. **Reproduce:** list every currently blocked file and capture 64–128 bytes plus
   decoded ops before the failure. Determine whether all files share one shape.
2. **Form hypotheses:** use register/FP/string-stack state, adjacent runtime calls,
   dialect canonicalization, and likely source families to make a bounded probe
   matrix. Record ruled-out hypotheses, not just the winner.
3. **Probe:** batch-compile minimal `.bas` candidates with
   `tbx/tools/batch_probe.py`. Probe both 1.0 and 1.1 when the wild files span
   dialects. A scanner `clean` result only means the candidate did not reproduce
   the target.
4. **Confirm:** retain the winning executable long enough to compare exact bytes,
   decode it, and verify canonical source with the oracle. Copy only the minimal
   redistributable fixture into the test corpus.
5. **Implement:** add the narrow scanner op first, then explicit decoder state and
   IR/render/C support where required. Avoid catch-all acceptance of raw x86.
6. **Validate:** run the gates above, regenerate `/tmp/tbx-gap-report.json`, and
   compare affected files. Newly exposed failures enter the queue immediately.
7. **Commit and log:** one semantic closure per commit whenever practical.

### Work queue

Priority balances affected-file count, likelihood of oracle reproduction, risk,
and **unlock value**. Counts below are only the first-failure snapshot from
2026-07-19. When a fix advances a file, log both its old and new signature. Prefer
a lower-frequency gap when prior results show that it exposes shared downstream
work in several files. This blocker history is the campaign's unlock graph; do
not overwrite it with only the latest state.

#### Wave 0 — restore the validation baseline

- [x] Regenerate `tests/fixtures/ir_snapshot.txt` and confirm the only addition is
  the already-committed `t1_getstr` section.
- [x] Rerun the full suite and establish the first tracked sanitized corpus report
  at `gap_reports/2026-07-19-baseline.json`.

#### Wave 1 — bounded runtime dispatches

These have explicit opcode boundaries and are the best candidates for safe,
fixture-backed closures.

- [x] `INT ED sub 1e` — missing runtime-revision entry for
  `INSTR(start, haystack$, needle$)`. Four files (`be.exe`, `crossref.exe`,
  `hebrew.exe`, `invent.exe`) independently preserve the start position in AX,
  push haystack then needle, and consume the AX result. The adjacent `ED/1c`
  entry is the already-verified two-argument `INSTR`. See the full evidence and
  oracle limitation in `Part III`.
- [ ] `INT EC sub 38` — 3 files. Re-open Gap 33 evidence in `Part III`, build a
  statement-family probe matrix, and test both dialects.
- [x] `INT EC sub 42` — bare `FILES`; the adjacent sub 44 is `FILES spec$`.
  Oracle fixtures cover both 1.0 and 1.1. `styled.exe` and `styllist.exe`
  advance to the same later cursor/LOCATE fold gap.
- [x] `INT EC sub ac` — `PUT$ #n, s$` (binary-mode string write, the
  complement of the already-implemented `GetString`/`GET$`). Same
  filenum+pushed-string calling convention as `IOCTL`, which is what made
  it look like IOCTL at first (it's not — `IOCTL #n,s$` is `EC sub 50`,
  confirmed separately). Found via the handbook's own GET$ function entry
  cross-referencing "GET$, PUT$, and SEEK provide a low-level alternative
  ... byte-by-byte". Fixtures `t1_putstr`/`v10_t1_putstr`
  (`OPEN...FOR BINARY` + `SEEK` + `PUT$`), byte-exact both dialects.
  Closed the LAST occurrence of this signature: advanced all 3 wild files
  (nvginst, pwinst, secure) into 3 distinct new gaps (`byte f7`; `byte 36`;
  a jump-target error), 0 regressions.
- [x] `IOCTL #n, s$` / `IOCTL$(n)` — not in the original work-queue (found
  while chasing `EC sub ac` above), but a real Wave-5 gap: neither
  statement was implemented at all. `EC sub 50` (statement) / `EE sub 14`
  (function, alphabetically between `INPUT$F` and `LCASE$`). Fixtures
  `t1_ioctl`/`t1_ioctlfn` (+v10), byte-exact both dialects. Touches no wild
  file.
- [ ] raw `INT af` — 2 files; determine whether it is a string/array runtime vector
  by tracking stack and descriptor setup.
- [ ] raw `INT c2` — 2 files.
- [x] `INT EC sub ee` — `WIDTH device$, cols` (device string pushed, cols in
  ax; the handbook's own example literal, `WIDTH "LPT1:",130`, reproduced it
  on the first oracle probe). New `ir.Width.device` field (default `None`
  keeps the existing `WIDTH cols` form unchanged). Fixtures
  `t1_widthdev`/`v10_t1_widthdev`, byte-exact both dialects. Advanced wild
  `cal.exe`/`cal87.exe`/`kinetics.exe` past this signature into distinct
  later gaps (numeric INPUT without FSTP; LINE flag 00; a new raw-byte
  signature) — none fully closed by this fix alone. A sibling form, `WIDTH
  #filenum, cols` (canonical `EC sub f0`), was also identified via the same
  probe batch but not implemented: its filenum is read back from system
  cell `0x60` rather than passed in ax at the call site, and no wild file
  currently blocks on it — leave for a session that wants to chase the
  `0x60` cell convention.
- [ ] singleton dispatches: `INT d4`.

#### Wave 2 — repeated instruction and x87 templates

- [ ] FP `dc/04` — 2 files; compare memory operand addressing with supported x87
  arithmetic forms and add a fixture for the exact data type.
- [ ] FP `da/1c` — 2 files; determine whether it is integer multiply/compare or a
  compiler spill form before generalizing ModR/M handling.
- [ ] byte `89` — 3 files; verify these are not another register-spill topology
  already partly covered by the DI work.
- [ ] byte `8c`, `8b`, `0b`, `1e`, `f7` — 2 files each. Cluster by the complete
  instruction and nearby ops rather than by first byte alone.
- [x] `VARPTR$` pointer-string construction — direct `8c 06`/`89 36` stores
  into the runtime's pointer-string staging cells, calibrated for scalar
  variables and rank-1 integer array elements. Fixtures `t1_varptrs_scalar`,
  `t1_varptrs_arr` and their `v10_` pairs are byte-exact; the decoder keeps
  rank and chain shape checks fail-loud.
- [x] Reverse dynamic-array `SWAP` segment juggling — `mov es,[block];
  mov [scratch],es; mov es,[block]; mov ds,[scratch]` followed by the
  far/near descriptor exchange. Calibrated for STRING and DOUBLE elements;
  the four `t1_`/`v10_` fixtures are byte-exact.
- [x] Integer runtime-array direct constant-subscript stores/loads (`26 89 06
  disp16` and the matching `far_fild`) — `$DYNAMIC` integer arrays. Fixture
  `t1_dynconstnum`, byte-exact verified; the runtime-slot layout now accepts
  integer type `0x00` and preserves `DIM DYNAMIC` in emitted source.
- [~] relational/materialization gaps: the two apparent integer `IF jcc 7f`
  failures were stale `pend_cmp_str` state after a materialized string condition
  and are closed. Nested outer-AND forms now cover the `jcc 75`/`jcc 74`, BX/CX
  spill, direct-GOTO, and single-relation-right shapes witnessed by
  `styled`/`hfprop`; other materialization topologies remain fail-loud.
- [x] byte `36` — `mov ss:[si],imm16` (new op `movm_imm_temp`), the
  literal-argument sibling of the already-handled `movm_ax_temp`. Found via
  a DEF FN call nested as another DEF FN call's own argument
  (`FNFOO("text", FNBAR(3))`). Landing it exposed a REAL pre-existing bug,
  not just a missing op: `state.fn_args` had no nesting protection (unlike
  `sp_save_cell`, which already got `sp_save_stack` for exactly this
  reason) — a nested call's own `fn_call` was draining/clearing the OUTER
  call's partially-staged args, silently dropping an argument. Fixed with
  a parallel `fn_args_stack`, save/restored in `push_bp`/`pop_bp` alongside
  `sp_save_cell`. `movm_ax_temp`/`movm_imm_temp` now peek at the next op to
  route to `pend_args` (plain SUB CALL, `arg_push_temp` follows) or
  `fn_args[si]` (nested DEF FN call, `mov_bp_sp`/`fn_call` follows instead
  — SUB CALL structurally can't nest as an argument, so the split is
  exhaustive). Fixture `t1_fnargcall`, byte-exact both dialects (had to
  match the exact bare-identifier DEF FN convention the handbook documents
  and `t1_fnlocalint` already uses — an `FN name = expr` form with the `FN`
  kept as a literal token compiles to a materially different, ALSO-valid
  shape that isn't what canonical emission produces). Advanced wild
  `hebrew.exe`/`pwinst.exe` past this signature.
- [ ] singleton instruction bytes `ff`, `21`, `18`, `16`.

#### Wave 3 — decoder state and structural recovery

- [x] Recognize the exact 116-byte and 125-byte framed helpers shared by
  `catalog.exe`, `filepatc.exe`, `morcalc.exe`, `process.exe`, and `pw.exe` as
  explicit coverage-only `OpaqueHelper` IR. Both matches are full pinned bodies
  (`28bc583a260b9ef7...` and `77dcc7f864dcd116...`), not a generic
  framed-procedure fallback; source output carries a visible marker and the C
  backend rejects it.
- [ ] Identify the source/runtime semantics of that opaque helper if stronger
  evidence appears. Opaque coverage advances scanning but does not count as
  semantic closure or byte-exact source recovery.
- [ ] Decode the next signature now exposed immediately after these helpers in
  those same five files.
- [ ] unknown system cell `0x8a` — 2 files; correlate reads/writes and runtime
  consumers before assigning semantics.
- [ ] unknown system cell `0x110` — 1 file.
- [x] numeric `INPUT` read without `FSTP` — `INPUT A#` stores through the
  existing `fstp64` double-variable terminal; verified in both dialects by
  `t1_inpdbl`/`v10_t1_inpdbl`. `banker.exe` advances to a later USING fold.
- [x] `LINE INPUT` trailing byte `c0` — leading-semicolon `LINE INPUT;`, with
  or without a prompt; dual-dialect oracle fixtures are byte-exact.
- [ ] `LINE INPUT #` template mismatch.
- [x] cursor call without open `LOCATE` — cursor-only `LOCATE ,,cursor` and
  shape-only `LOCATE ,,,start,stop` emit independent runtime legs. Adjacent
  cursor/shape statements are byte-identical to one combined LOCATE and
  canonicalize accordingly. `pz.exe` now decodes fully.
- [ ] displacement neither scalar nor array element — revisit DGROUP symbol
  classification with local references.
- [ ] FP/DGROUP layout not solvable — isolate whether metadata calibration or a
  preceding scan error caused the bad layout.
- [ ] codeless `DO...LOOP` condition — keep fail-loud until a non-DO source shape
  or stronger orphan-line evidence is found.

#### Wave 4 — ambiguous control/data and runtime-revision patterns

- [ ] byte `ea` — 6 files. Separate genuine far jumps from inline data records;
  require control-flow reachability evidence before accepting either shape.
- [ ] byte `90` — 6 files. Existing evidence suggests an unwitnessable runtime
  revision pattern; repeat only probes that add a genuinely new source topology.
- [ ] byte `06` — 3 files and raw `INT 8c` — 3 files. Continue from the extensive
  negative probes in `Part III`; do not repeat the same ON KEY variants.

Wave 4 is intentionally last: permissive handling here could hide corrupt control
flow and produce plausible but wrong BASIC.

#### Wave 5 — syntax inventory beyond the handbook

- [ ] Build a versioned syntax inventory from all available Turbo Basic manuals,
  compiler media, sample programs, and existing IR nodes. Record aliases,
  edition/dialect tags, argument grammar, and runtime behavior.
- [ ] Add parser/IR coverage for inventory entries that are absent, even when no
  wild executable exercises them yet.
- [ ] Add dialect-specific fixtures or golden source cases for constructs the
  local oracle cannot emit, with explicit provenance.
- [ ] Maintain a compatibility matrix separating syntax, decoder, renderer, and
  generated-C/runtime support. A missing C primitive must produce a diagnostic,
  not erase syntax coverage.

### Tooling work

- [x] Add `scan_wild.py --report FILE`: JSON totals, per-file results, and stable
  address-normalized failure groups for cross-session comparison.
- [x] Commit-ready sanitized baseline under `gap_reports/`; `/tmp` is working storage,
  not a resumable checkpoint.
- [x] Add `compare_gap_reports.py` before the next decoder closure. It shows
  files newly decoded, regressed, advanced to a different signature, unchanged,
  signatures removed, and newly exposed signatures. Its advanced-file output is
  the input to the unlock graph.
- [x] Extend `batch_probe.py` with optional retained artifacts (`--keep DIR`) so a
  winning oracle executable can be inspected without recompiling. It now also
  preflights dependencies, flushes results immediately, and supports isolated
  concurrent oracle workers through `--jobs N`.
- [ ] Add a context dumper accepting `EXE OFFSET` that prints raw bytes, nearby
  scanned ops, dialect-canonical interrupt numbers, and decoder register/stack
  state where available. Reuse `insns.py`/`dump_ops.py` rather than duplicating
  disassembly logic.
- [x] Add report schema version, generator identity, and content-based corpus
  fingerprint so comparisons can reject incompatible formats or different corpora.
- [~] Assign stable IDs to active gaps and keep hypothesis, evidence, confidence,
  and disposition in a compact ledger. Runtime-revision candidates now live in
  `gap_reports/runtime-revision-assessments.json` with stable `RR-*` IDs and
  promotion criteria; extend the same model to every non-runtime gap. Error text
  remains a symptom and may change without creating a new logical gap.
- [ ] Extend gap records and fixtures with `edition`, `dialect`, `runtime_revision`,
  and `evidence_class` fields so non-handbook syntax remains traceable.
- [ ] Add stable syntax-inventory IDs alongside gap IDs, so source coverage can
  be tracked even before a bytecode gap appears.
- [ ] Make scanner runs re-entrant by clearing module-level counters at `main()`;
  this matters for tests and future programmatic use.
- [ ] Add tests for report normalization, deterministic group ordering, schema
  compatibility, and report comparison (especially regression versus advancement).

Tooling is subordinate to closures: implement an item when it saves repeated
manual work on at least two gaps, not as a prerequisite to investigating one.

### Validation commands

Use these after each implementation:

```bash
UV_CACHE_DIR=/tmp/tbx-uv-cache uv run ruff check tbx tests
git diff --check
UV_CACHE_DIR=/tmp/tbx-uv-cache uv run pytest -q <focused tests>
UV_CACHE_DIR=/tmp/tbx-uv-cache uv run pytest -q
UV_CACHE_DIR=/tmp/tbx-uv-cache uv run python tbx/tools/scan_wild.py \
  wild/hits --report /tmp/tbx-gap-report.json
```

For every new oracle fixture, also run:

```bash
UV_CACHE_DIR=/tmp/tbx-uv-cache uv run python -m tbx.tools.verify_fixture <name>
```

### Progress log

Append one concise row per committed closure or material tooling checkpoint.
Include newly exposed blockers because they are evidence of forward progress.

| Date | Commit | Closure/checkpoint | Corpus result | Next blocker |
|---|---|---|---|---|
| 2026-07-19 | `25fbe9c` | Decode `INP(port)` / ED sub 24 | 14 OK / 70 blocked; `be.exe` advanced | ED sub 1e |
| 2026-07-19 | pending | Add JSON scanner report, durable checkpoint design, resumable plan, and `t1_getstr` snapshot repair | 14 OK / 70 blocked | Green full suite, then ED sub 1e |
| 2026-07-19 | `796c9c0` | Preserve one fully fingerprinted framed helper as explicit coverage-only opaque IR | 14 OK / 70 blocked; 5 files advanced from byte `C5` to byte `8E` | Decode the shared `8E` continuation |
| 2026-07-19 | `01f8943` | Recognize the second 125-byte opaque helper variant and the emulated far `FIMUL` alias (`INT 3C DE 0C`) | 14 OK / 70 blocked; 5 files advanced beyond `DE/0C` to distinct next signatures | Triage the five newly exposed signatures |
| 2026-07-19 | `4e9769c` | Accept the exact selector-temp cleanup shape's `INT CC` runtime-revision alias | 14 OK / 70 blocked; `catalog.exe` advanced from byte `31` to `INT EC sub 38` | Re-open shared `INT EC sub 38` evidence |
| 2026-07-19 | `ecbb40f` | Decode signed integer division by a memory cell (`CWD; F7 3E disp16`) | 14 OK / 70 blocked; `filepatc.exe` advanced beyond byte `F7` | Triage its next exposed gap |
| 2026-07-19 | pending | Canonicalize TB 1.0 raw `CD A9` to the existing `CVL` string-to-number vector | 14 OK / 70 blocked; `morcalc.exe` and `pwinst.exe` advanced beyond `INT AF` | Triage their newly exposed gaps |
| 2026-07-19 | `fc24e04` | Decode near-array double FP folds (`INT 38 DC /r [SI]`) through the existing FP array fold path | 14 OK / 70 blocked; `morcalc.exe` advanced beyond `DC/0C` | Triage its next exposed gap |
| 2026-07-19 | `cb65dc2` | Decode far string assignment through a by-reference SUB parameter | 14 OK / 70 blocked; `morcalc.exe` advanced beyond `far_strassign` | Triage its next exposed gap |
| 2026-07-20 | pending | Identify missing runtime-revision `INSTR(start, haystack$, needle$)` entry at `INT ED sub 1e` | 14 OK / 70 blocked; four files advanced and the signature disappeared with no regression | `EC sub 38`; separately triage the later structural errors in `be`/`invent` |
| 2026-07-20 | pending | Decode bare `FILES` / canonical `EC sub 42` | 14 OK / 70 blocked; `styled` and `styllist` advanced to cursor-without-LOCATE | Triage their shared cursor fold; continue `EC sub 38` separately |
| 2026-07-20 | pending | Replace fixed oracle sleeps with readiness polling and isolate each compile workspace; add parallel/retained probe batches | Byte-exact checks pass for both dialects and a larger fixture; small compile ~25s → 8.8s, two concurrent in 8.9s | Consider warm snapshot workers only if probe throughput remains limiting |
| 2026-07-20 | pending | Decode cursor-only and shape-only optional `LOCATE` runtime legs | 15 OK / 69 blocked; `pz` fully decoded, `styled` → jcc 75, `styllist` → IF jcc 7f | Re-tally relational JCC gaps |
| 2026-07-20 | pending | Clear stale string-compare orientation when `cmpax_bx` starts a numeric relation | 15 OK / 69 blocked; `photo` → movsi continuation, `styllist` → later stack fold | Triage exposed blockers; investigate `styled`/`hfprop` jcc 75 separately |
| 2026-07-20 | pending | Lift direct JNZ dispatch of a fully parenthesized logical value as an inline `IF` | 15 OK / 69 blocked; both installed runtimes verify byte-exact; nested short-circuit targets remain fail-loud | Reproduce the nested spill topology independently before extending this rule |
| 2026-07-20 | pending | Decode nested logical outer-AND spill gates, including inline and direct-GOTO dispatch | 15 OK / 69 blocked; `hfprop` → displacement `0x2b2`, `styled` → RESTORE target 87 | Triage exposed structural gaps; retain fail-loud behavior for other nesting topologies |
| 2026-07-20 | `0ea9d98` | Preserve leading-semicolon `LINE INPUT;` flag C0 and close nested logical spill topologies | 15 OK / 69 blocked; `cal`/`cal87` → shared `EC sub ee`; no regressions | Probe `EC/ee` only if installed runtimes reproduce it |
| 2026-07-20 | working tree | Archive the current sanitized scan and verify report comparison | 15 OK / 69 blocked; 1 newly decoded, 26 advanced, 0 regressed versus baseline | Continue evidence-led triage; keep `EC/38` and `EC/ee` fail-loud |
| 2026-07-20 | working tree | Decode numeric console `INPUT` into a DOUBLE variable (`fstp64`) | 15 OK / 69 blocked; `banker.exe` advanced from numeric INPUT to stray USING emit; 0 regressions | Investigate the exposed USING-chain shape |
| 2026-07-20 | working tree | Preserve TAB/SPC as inter-item expressions inside PRINT/LPRINT USING | 15 OK / 69 blocked; `banker.exe` advanced to `unhandled op testw`; 0 regressions | Identify the next `testw` control-flow template |
| 2026-07-20 | working tree | Lift x87 FOR/NEXT sign tests with non-adjacent limit/step slots | 16 OK / 68 blocked; `banker.exe` newly decodes completely, 0 regressions, `testw` signature removed | Triage the seven-file `unhandled byte ea` group |
| 2026-07-20 | working tree | Decode runtime-revision far `JMP` (`EA`) transfers and fixed zero-offset handoffs | 16 OK / 68 blocked; all seven `byte ea` files advanced, 0 regressions, signature removed | Triage the newly exposed file-specific gaps |
| 2026-07-22 | pending | Decode `WIDTH device$, cols` (`EC sub ee`), found via the newly-added handbook's own worked example | 23 OK / 61 blocked; `cal`/`cal87`/`kinetics` advanced past this signature into 3 distinct later gaps, 0 regressions; `EC sub ee` signature removed | Triage the 3 newly exposed signatures |
| 2026-07-22 | pending | Decode `IOCTL #n,s$` / `IOCTL$(n)` (`EC sub 50` / `EE sub 14`), a Wave-5 syntax-inventory gap found while chasing `EC sub ac` | 23 OK / 61 blocked; 0 regressions; touches no wild file | `EC sub ac` is confirmed NOT `IOCTL` despite the identical filenum+string calling convention — still unidentified, see `Part III` |
| 2026-07-22 | pending | Decode `PUT$ #n,s$` (`EC sub ac`) — binary-mode string write, GetString's complement | 23 OK / 61 blocked; `nvginst`/`pwinst`/`secure` all advanced past this signature into 3 distinct new gaps, 0 regressions; `EC sub ac` signature removed | Triage the 3 newly exposed signatures (`byte f7`, `byte 36`, a jump-target error) |
| 2026-07-22 | pending | Decode `mov ss:[si],imm16` (byte `36`, new op `movm_imm_temp`) + fix a real pre-existing bug: `fn_args` had no nesting protection around a DEF FN call used as another call's own argument | 23 OK / 61 blocked; `hebrew`/`pwinst` advanced past this signature, 0 regressions; byte `36` signature removed | Triage `byte 2b` (hebrew) and `byte 26` (pwinst) separately |
| 2026-07-22 | pending | Decode `or ax,es:[si]` (new op `far_orax_si`), the OR sibling of the already-handled `far_andax_si` in the by-ref-int-param family | 23 OK / 61 blocked; `pwinst.exe` advanced past this signature, 0 regressions | `pwinst.exe`'s own `byte 26` occurrence is now closed; the SAME signature at `bmaster.exe`/`ifi.exe` is a DIFFERENT, harder shape (`26 ff 0c` = far DEC, needs `local_init` base-disp threading, see HANDOFF's "Investigated at length but NOT landed" writeup) — do not assume this closure fixes those two |
| 2026-07-22 | pending | SOLVE the multi-session `far_call(mid-flow)`/`KeyError: 86343` mystery: under active event trapping, `GOSUB` compiles to a far call/retf pair, not near — `_resolve_calls` now falls back to `ir.Gosub` when a far_call target isn't a known proc; also fixed an independent latent bug (`far_call` used the wrong statement address, silently corrupting `$EVENT ON/OFF` metadata recovery under trapping) | 23 OK / 61 blocked; `resume.exe` advances completely past this into a DIFFERENT jump-target-resolution error, 0 regressions | `resume.exe`'s new failure is NOT the same bug as state.exe/state87.exe's (corrected after further tracing — see `Part II`'s "out of scope" section); it targets compiler glue and needs its own trace. Target `86343`'s own large-near-call-displacement mechanism is also untested separately |
| 2026-07-22 | pending | Write `Part II`: a full investigation spec for the intra-inline-IF-body GOTO gap (state.exe/state87.exe), correcting an earlier same-day misdiagnosis ("SUB/DEF FN body" — state.exe has none) by cross-referencing an existing, more precise prior-session diagnosis and confirming it via fresh `id()`-tracing | No code change; 23 OK / 61 blocked unchanged | Follow the spec's phased plan (minimal probe first, trace `_fold_if`/`_body_has_target`, then fix) in a dedicated session |

### Completion checklist

- [ ] Wild corpus reaches 84/84 decode OK, or each remaining executable is
  explicitly classified with a byte-exact reason and concrete follow-up.
- [ ] No fixture, regression, lint, or formatting failures.
- [ ] The syntax inventory has no unclassified Turbo Basic language entry.
- [ ] The compatibility matrix shows source, decoder, renderer, and C-runtime
  status for every inventory entry.
- [ ] Every new IR node and intrinsic has render, rename, and C behavior (or an
  explicit unsupported-C diagnostic) as applicable.
- [ ] The final JSON report is archived in a tracked, copyright-safe summary that
  contains paths/signatures only, never wild executable bytes.
- [ ] `Part III` contains durable reverse-engineering findings; this plan records
  all work items complete and points to the final commits.

---

## Part II — Spec: intra-inline-IF-body GOTO targets


Status: **RESOLVED 2026-07-23** for `state.exe`/`state87.exe` (see the
dated writeup in `Part III`); the actual root cause was a FOURTH
mechanism, none of the three candidates guessed below. `secure.exe`
still fails on the same error message at a different target and was
NOT re-traced — do not assume it shares this fix's cause.

Original status: 2026-07-22, investigation-only — no code changes yet. This
supersedes the "SUB/DEF FN body" framing in `Part III`'s `6f1a9fb`
diagnosis commit, which was **factually wrong about the mechanism**
(corrected in `Part III` alongside this spec — see "Correction" below).

### Problem statement

Two wild files fail with `jump target 0x... is not a statement start`,
raised by `lift._resolve_targets`'s `fix()` (`tbx/decode0/lift.py:806-816`)
well after `decode0._scan` completes cleanly — this is not a
byte-vocabulary gap, it's a control-flow reconstruction gap:

- `state.exe` / `state87.exe`: target `0x1300d`. **Confirmed root cause**
  (see "Confirmed facts" below): a `Goto`/`IfGoto` lands on a statement
  that lives inside a large, still-inline (`ir.IfInline`) `IF` body — the
  compiled shape of a chain of `IF cond THEN <lineY>` statements with no
  `END IF`/block markers in the source — and the fold machinery that's
  supposed to convert such a body into an addressable `ir.IfBlock` does
  not fire for it.
- `secure.exe` also hits this exact message, at a different target,
  advanced into it by this session's `far_call`/GOSUB fix. **Not traced
  yet** — do not assume it's the same shape without checking; see
  "Open items" below.

`resume.exe`'s own newest failure (`jump target 0xa3dd ...`, exposed by
the same `far_call`/GOSUB fix) is a **different, unrelated root cause** —
see "Explicitly out of scope" below. An earlier commit message this
session incorrectly called it the same bug; it isn't.

### Confirmed facts (traced this session, `state.exe`)

1. `state.exe` has **zero** `proc_enter`/`proc_ret`/`fn_ret` ops in its
   entire op stream — there are no `SUB`s or `DEF FN`s in this file at
   all. The target is not inside a procedure body.
2. The target address (`0x1300d` = 77837) **is** a real statement
   boundary in the raw op stream (`decode0._scan`'s output has an op
   starting exactly there) and **is** present in `state.stmt_addr` (the
   `id(stmt) -> addr` map lift.py populates during folding,
   `tbx/decode0/lift.py:570` and `tbx/decode0/core.py:2099,2252,2350`).
3. But the specific object `id()` that `stmt_addr` recorded for that
   address is **not present anywhere** in the final `state.stmts` tree at
   the time `_resolve_targets` runs — not at top level, not inside any
   `IfBlock` arm/else, not inside any `IfInline` body, not inside any
   `SelectCase` arm. (Verified by monkeypatching `core._resolve_targets`
   to search the live tree for that exact `id()` in the same process —
   see the shell history in this session's transcript, or rerun: patch
   `core._resolve_targets`, collect `[k for k,v in stmt_addr.items() if
   v==target]`, then walk `state.stmts` recursing through
   `SubDef`/`DefFn`/`IfBlock`/`IfInline`/`SelectCase` looking for that
   `id()`.)
4. This matches an **existing, more precise diagnosis already in
   `Part III`** from an earlier session (search for "Intra-inline-IF-body
   GOTO targets" — currently around line 1428): a giant `ir.IfInline`
   (~40 statements, the compiled shape of an unbroken chain of
   `IF cond THEN <lineY>` lines with no block `IF`/`END IF` in the
   source — a flattened keyboard-input state machine) whose body contains
   a `Goto`/`IfGoto` targeting **another statement inside that same
   body**. `_resolve_targets`'s `index` only maps top-level `state.addrs`
   entries plus whatever the existing `ir.BodyLine` mechanism (gap 51,
   built for block-IF interiors jumped into **from outside** the block)
   adds — and this is a jump **within** the same already-flattened inline
   body, a case that mechanism was never built to cover.
5. `ir.For`/`ir.NextStmt`/`ir.While`/`ir.Wend`/`ir.Do`/`ir.Loop` are flat
   marker statements with no `body` field — a statement inside a loop is
   just an ordinary sibling in the same flat statement list. **Loops are
   not part of this gap.** Only `IfBlock` (multi-arm/`ELSE`),
   `SelectCase`, `SubDef`, and block `DefFn` are "opaque, unwalked"
   containers as far as `map_body` is concerned today
   (`tbx/decode0/lift.py:778`, confirmed by an Explore-agent read of the
   full function).

### The machinery that *should* already handle this, and doesn't (yet)

There's already a "second leg" in `_fold_if`
(`tbx/decode0/lift.py:653-660`) specifically for this: if a top-level
`ir.IfInline`'s own body contains an address in the program-wide jump-
target set (checked via `_body_has_target`,
`tbx/decode0/lift.py:481-495`), the whole `IfInline` gets converted to a
single-arm `ir.IfBlock` — which then goes through `_fold_body`, and (per
`_fold_body`'s own logic, `tbx/decode0/lift.py:498-516`) any *plain*
statement inside is carried over with its **original `id()` intact**
(only nested `IfInline`s needing further conversion get wrapped in a new
object). If that path fired correctly, the target statement would
survive with its address still traceable through the resulting
`IfBlock`'s arm — and `map_body`'s already-working single-arm-IfBlock
recursion (`tbx/decode0/lift.py`, the `map_body` function, confirmed to
recurse genuinely unboundedly, not capped at "one level" as the old gap-51
docstring note implied) would find it.

Since the object is missing entirely from the final tree, this path did
**not** fire for state.exe's giant IfInline. The precise reason is the
open question — plausible candidates, none confirmed:

- `_body_has_target`'s `targets` set (built once, up front, by
  `_jump_targets(stmts)`) might not include this specific target address
  at the time `_fold_if` runs, for some ordering or construction reason.
- The 40-statement chain might not be reachable as ONE `ir.IfInline` at
  the point `_fold_if`'s top-level loop visits it — e.g. it might already
  be nested inside something else that the top-level scan doesn't
  descend into before folding.
- Something about the specific `Goto`/`IfGoto` shape (backward vs.
  forward, or a computed `ON...GOTO` target instead of a plain `Goto`)
  might not be captured by `_jump_targets`'s walk in the first place.

**Do not guess at which of these it is — trace it.** This is exactly the
kind of thing a wrong guess makes worse: `_fold_if`/`_body_has_target`
are shared, heavily-exercised machinery (gap 51 and the "nested block-IF
GOTO targets" follow-on both live here), and any change risks silently
breaking an already-passing fixture whose shape happens to be adjacent.

### Recommended investigation plan

Follow the calibration rule's spirit even though this is control flow,
not byte vocabulary: understand the exact shape with a real, minimal,
oracle-verified reproduction before touching `_fold_if`/`_resolve_targets`.

1. **Reproduce the shape directly, minimally.** Build a `.bas` probe: a
   chain of several `IF cond THEN <lineY>` statements (no block `IF`,
   spelled as bare inline forms, ideally on distinct numbered lines so
   the compiled shape stays one flat `IfInline`-style chain rather than
   folding into something else), where a LATER one in the chain jumps
   BACKWARD to a line that is itself in the MIDDLE of an EARLIER
   statement's own body (i.e., the target is not the chain's first
   line). Model it on `t1_blkgoto.bas`/`t1_nestif2.bas`
   (`tests/fixtures/corpus/`) but keep everything inline — no `END IF`
   anywhere — since state.exe's shape has none. Compile with the oracle
   and confirm it reproduces `jump target ... is not a statement start`
   before touching any decoder code.
2. **Trace exactly where `_fold_if`'s second leg fails to fire** for the
   probe: instrument `_body_has_target`/`_fold_if` (temporarily, revert
   before committing — same throwaway-print-then-`git checkout --`
   technique already used elsewhere this session) to print whether the
   target address ends up in `targets`, and whether `_body_has_target`
   is even called with the right body/stmt_addr for this IfInline.
   Compare against `state.exe`'s own real trace (reuse the
   `core._resolve_targets` monkeypatch approach from "Confirmed facts"
   above, applied to the probe first, then cross-checked against
   `wild/hits/state.exe` once the probe reproduces the mechanism).
3. **Only once the exact failing condition is understood**, design the
   fix. It is very likely a small, targeted correction to `_body_has_target`
   or to how/when `targets`/`stmt_addr` reach `_fold_if` — NOT a rewrite
   of the fold algorithm — but don't commit to that shape until step 2
   confirms it.
4. **Validate broadly, not just the new fixture**: full test suite,
   `ruff`, byte-exact `verify_fixture` for the new probe fixture AND a
   handful of existing fixtures that exercise `_fold_if`'s other paths
   (`t1_blkgoto`, `t1_nestif2`, `t1_ifgoto2` if present, plus anything
   under `tests/tbx/test_cfg.py`/control-flow-focused tests), THEN a full
   `scan_wild.py` re-run (not just the affected files) to catch any
   regression the corpus test suite doesn't happen to exercise — this
   project's own established lesson (Part III, the `796c9c0`-era
   "re-run the FULL WILD SCAN before declaring done" note) applies
   directly here.
5. Once `state.exe`/`state87.exe` close, re-check `secure.exe`'s own
   occurrence of the same error message — confirm (don't assume) it's
   actually the same shape before declaring it closed too.

### Explicitly out of scope for this spec

**`resume.exe`'s `jump target 0xa3dd ...` failure is a different bug.**
Traced this session: target `0xa3dd` (41949) is the address of a bare
`jmp` instruction — specifically the inter-definition "skip past the next
SUB/DEF FN body" glue jump that TB emits right after a `proc_ret`
(`(41945, 'proc_ret', 46), (41949, 'jmp', 43163), (41952, 'proc_enter')`
in the raw op stream). It is not a user statement and was never given an
`stmt_addr`/`state.addrs` entry at all (confirmed: `stmt_addr` has zero
matching entries for this address, vs. `state.exe`'s case which had one
whose object was later lost). Something — likely another far_call/GOSUB
case related to this session's event-trapping fix, or a genuinely
different mechanism — is targeting pure compiler glue as if it were an
addressable line. This needs its own from-scratch trace; do not assume
fixing the intra-inline-IF gap above will also close it.

### Why this matters / acceptance criteria

- `state.exe`/`state87.exe` (and possibly `secure.exe`) decode completely.
- No regression anywhere in the existing 2407-test suite or the 84-file
  wild scan.
- The fix is provably narrow: it should be possible to point at the exact
  condition in `_body_has_target`/`_fold_if` that was wrong, with a
  before/after trace on the new minimal probe, not just "the crash went
  away."
- `Part III` gets a real, dated closure writeup (matching this
  project's own convention) once landed, including which of the three
  candidate causes above (or a fourth, if the trace finds something
  different) was the actual one.

---

## Part III — Investigation history / handoff log

### 2026-07-23 (fifth round, same day) — mixed-precedence compound-IF chains, WITH oracle

Discovered the oracle (`tbx/vendor/turbo_basic_oracle`) was actually
available and working all along this session -- `oracle.preflight()`
passes, `oracle.compile_bas` compiles real programs -- the "no oracle"
belief in earlier rounds today came from a stale relative-path `ls`
check giving a false negative. This unlocked proper, verified work on
the single most-repeated remaining blocker: the "3+-term compound-
boolean register choreography" family (number.exe/hfprop.exe/
process.exe/grdscn.exe/wb.exe/mcmurphy.exe).

**Method**: built and byte-exact verified 7 oracle probes
(`mixchain.bas` through `mixchain7.bas`, later promoted as
`t1_mixedbool2`/`t1_mixedbool3`) covering every combination of
AND/OR cascade-then-switch shape: `A AND B OR C`, `A OR B AND C`,
`A AND B AND C OR D`, `(A AND B) OR (C AND D)`, `A OR B OR C AND D`,
`(A OR B OR C) AND D` (explicit parens), and `(A AND B) OR (C AND D)
OR (E AND F)`. Each was decoded, re-emitted, and RECOMPILED through the
oracle to confirm byte-for-byte identity with the original -- the full
calibration-rule workflow, not a guess.

**Bug 1 -- single-term-switch tunnel vision.** `_match_bool_term1`
(lift.py, term1's own detection) and `_lift_bool_tail`'s existing
"combinator switch" lookahead (added in an earlier session for `A AND B
OR C`) only ever matched when the differently-combined continuation was
the term IMMEDIATELY after the just-processed one (`ops[k+6]`). For `A
OR B AND C` = `A OR (B AND C)`, B and C must resolve as their OWN
2-term chain FIRST (a fresh `_match_bool_term1` entry point at B) before
folding with A -- A's own short-circuit lands on (B AND C)'s
convergence point, not on B directly, so there's a genuine extra
materialization (B's own self-test) sitting between the switch point
and the match. Fixed by detecting this ("`seen_materialize`": any
`movax 0FFFFh` strictly between `ops[k+6]` and the matched position) and
DEFERRING the fold instead of raising: a new `state.pend_bool_outer`
frame holds the enclosing accumulator; `state.pend_bool` is cleared so
the ordinary dispatch loop naturally re-enters `_match_bool_term1` fresh
at `ops[k+6]`; that inner group's own eventual close folds
`LogOp(pend_outer["op"], pend_outer["r1"], inner_cond)` instead of
emitting directly.

**Bug 2 -- join operator derived from the wrong thing.** Once the
lookahead finds a match via `comb` (same as the incoming fold) or
`other_comb` (a switch), the ORIGINAL code returned the MATCHED
candidate's own operator as the new fold operator. This is only
correct by coincidence: for a SINGLE trailing term (t1_mixedbool's
witnessed shape), "the operator of the thing found" and "how the
accumulator joins it" happen to be the same value. For a multi-term
GROUP, they are NOT: the group's OWN internal operator (e.g. AND,
joining C and D inside the group) has nothing to do with HOW the outer
accumulator joins that whole group (e.g. OR). The join operator is
always this segment's OWN dispatch polarity (`f_jcc[2]`, independent of
`pb["op"]` or which candidate matched) -- computing it directly and
using it uniformly (for the immediate-continuation, single-switch, AND
deferred-group returns) fixed silently-swapped AND/OR in the outer join.
Symmetric fix applied to `_match_bool_term1` (always return the term's
own fixed `comb[1]`, never the matched candidate's label).

**Bug 3 -- cascades of GROUPS.** `(A AND B) OR (C AND D) OR (E AND F)`
(wild mcmurphy.exe's actual shape) needs a SECOND deferred group while
the first is still pending. Rather than a stack (unverified, would need
its own probe), the fix folds left-associatively: when a second defer
is needed while `pend_outer` is already set, fold it into `cond` right
away (`LogOp(pend_outer["op"], pend_outer["r1"], cond)`) and keep
waiting with the COMBINED result as the new accumulator -- the same
left-fold every other cascade in this file already uses, just one level
up. Verified via `mixchain7.bas`/`t1_mixedbool3`, byte-exact both
dialects.

**Fixtures**: `t1_mixedbool2` (`A$="L" OR B=15 AND C=1`) and
`t1_mixedbool3` (3-group OR-cascade of AND-pairs) promoted to
`tests/fixtures/corpus/` (+ `v10_`), pinned in
`test_compound_if.py::test_decode_t1_mixedbool2/3`, added to the
`PAIRS` dialect-invariance list. `t1_mixedbool`'s own comment (which
claimed "AND/OR equal precedence, left-associative") corrected -- that
framing only coincidentally matched its own single-trailing-term shape;
the real rule is standard AND-binds-tighter precedence, confirmed by
the mirror shape (t1_mixedbool2) producing a genuinely different tree.

**Wild corpus impact**: `mcmurphy.exe` now decodes fully PAST the
compound-boolean family into an unrelated, freshly-exposed bug: a
`Gosub` target of `244894073` (`0xe989b00`) -- an obviously-corrupted
huge address, nothing like a real 16-bit file offset. Not yet traced;
flagged as the new next step for this file specifically. `wb.exe`/
`grdscn.exe` are UNCHANGED (same "materialization template mismatch" at
the same addresses) -- their real compiled shape isn't among the 7
verified probes; the explicit-parens case (`(A OR B OR C) AND D`,
scratch `mixchain6.bas`) decodes without crashing but visibly
mis-orders terms in the output, a separate, pre-existing, untouched bug
that may be relevant if wb.exe's source uses explicit parens.
`number.exe`/`hfprop.exe` ("ax,bx combine with empty regs") and
`process.exe` ("empty di spill") are confirmed a DIFFERENT
register-choreography family (not this one) -- still unprobed.

Validation: full suite 2449 passed (10 new), 16 skipped, ruff clean,
full `scan_wild.py` re-run: still 25/84 (mcmurphy.exe traded one gap for
a different one, no file fully closed this round), no regressions
elsewhere.

### 2026-07-23 (fourth round same day) — FIELD redesign, shared far-string read, ON ERROR/main_start fix

Continuation of "fully decode a wild", no oracle. Picked up the third
round's own flagged next step (FIELD's computed width) and followed the
chain wherever it led.

**FIELD redesign (hebrew.exe).** Replaced the fixed 5-op-per-entry
lookahead loop (`movax;movsi;movdx;movesdx;field_as`, which only ever
matched a bare literal width) with the SAME lazy-close pattern already
used for READ/INPUT#/PRINT chains: `field` now just opens
`state.pend_field = {"fnum", "fields": [], "start"}` and returns. The
width -- whether a bare literal (`movax`) or a computed expression
(`movax_m;imul_m;negax;addax_m`, witnessed hebrew.exe) -- accumulates
into `state.ax` through the ordinary per-op dispatch with NO new code,
since every op in a width expression is already a fully generic,
context-free handler. A new check in `core.py`'s main loop (mirroring
the existing `movsi;movdx;movesdx;{dim_begin,dim_end,erase}` pattern)
recognizes `movsi;movdx;movesdx;field_as` as closing one AS-entry using
whatever's currently in `state.ax`. `flush_pending` emits the `ir.Field`
once the chain is proven closed by the next real statement (or EOF) --
this is a strict generalization, validated against the existing
multi-entry literal-width fixture `t1_field.bas` (`FIELD #1, 10 AS A$,
20 AS B$`) which still passes byte-for-byte through `test_goldens.py`.

**Shared far-string-variable-read gap (hebrew.exe/morcalc.exe/
photo.exe).** All three hit the identical `movsi <disp>; movdx <reloc>;
movesdx; str2num:CVL` shape at their "unhandled movsi continuation"
gap. Confirmed via direct inspection of `state.lay["scalars"]` in all
three that the movsi disp is ALWAYS an already-tracked, width-4 string
scalar (778/2070 in hebrew.exe -- the EXACT same disp as that file's own
FIELD statement's AS-target, strongly suggesting this is reading a
FIELD-buffer variable back as a value). Added a new check (same
location as FIELD's own terminal) recognizing this shape and pushing
`state.loc(op[2])` onto `sstack` -- the movdx/movesdx pair is the
compiler's segment-reload convention for FIELD-buffer variables, but
doesn't change WHICH variable is referenced (already proven correct
since FIELD's own write side uses the identical `state.loc(op[2])`).
Scoped narrowly to the witnessed `str2num` consumer only, not any
`movsi;movdx;movesdx` pattern in general.

**ON ERROR / main_start structural fix (wb.exe).** `state.main_start`
(marking the def-region/main-code boundary, gating whether a `fn_ret`-
terminated body auto-opens a `state.fn_frame`) was only ever set in two
cases: the entry skip-jmp IS op 0, or a skip-jmp immediately follows a
closed proc/fn's `ret`. wb.exe opens with `ON ERROR GOTO` as a genuine
first statement BEFORE the skip-jmp, which neither case covers, so
`main_start` stayed `None` forever and a DEF FN body's `fold_bp` fell
through to the "unexpected ... in main body" fail-loud raise. Added a
third, deliberately narrow case: exactly one prior statement, and it's
`ir.OnError` (not "any leading statement", to avoid ever swallowing a
genuine early GOTO as glue).

**Explicitly not reattempted, confirmed via trace.** `hebrew.exe` (now
`unhandled jcc 74`), `morcalc.exe` (`KeyError: 'idx'`, a `dec_m` FOR-step
patch hitting a FOR frame created by a DIFFERENT header path that never
sets `"idx"` -- a real bug in shared FOR-tracking machinery, not a
simple guess), `grdscn.exe`/`wb.exe`/`mcmurphy.exe`'s renewed
"materialization template mismatch" (confirmed via trace to be the same
"3+-term compound-boolean register choreography" family already set
aside this session for number.exe/hfprop.exe/process.exe -- `wb.exe`'s
specific case: `_match_bool_term1` requires the chain's OWN first
segment to end in a bare `orax` self-test, but wb.exe's first segment
ends in `oraxbx` (already a combine), meaning it's itself a cascaded
mid-segment of a 3+-term chain that gap 36's existing machinery doesn't
recognize as a valid entry point). `photo.exe`'s new "jump target ...
not a statement start" (exposed ONLY by this session's own CVL fix):
traced enough to confirm it's NEITHER state.exe's shape (no nested
IfInline containing the target) NOR resume.exe's shape (the target,
`fld:408`, is a real op with real semantics, not bare compiler glue) --
genuinely a third, undiagnosed variant.

Validation: full suite 2439 passed, 16 skipped, 0 regressions
(including the pre-existing multi-entry FIELD fixture); ruff clean;
full `scan_wild.py` re-run: still 25/84, no new failures elsewhere.

### 2026-07-23 (third round same day) — seven more fixes chasing a full close, no oracle

Continuation under "fully decode a wild" -- tried to push `cal87.exe`/
`hebrew.exe`/`filepatc.exe` all the way through, chaining fix after fix
as each one landed on the next gap. None fully closed, but the corpus
is measurably closer and the remaining blockers are now well-understood
enough to resume directly.

**`cal87.exe`, two real gaps.** (1) `LINE` flag byte 0x00: the decoder's
`fl & 0x40` check treated that bit as an always-set base flag (per the
original docstring), but it actually means "first point given
explicitly" -- when clear, the source omitted the first point entirely
(`LINE -(x2,y2)`, using the last graphics position). Confirmed by
instrumenting every OTHER `line` call in the file: all had `0x40` set
and non-None `color_cells[0x88]/[0x94]`; the one that failed had flags
0x00 and BOTH cells empty -- clean, unambiguous evidence. `ir.LineStmt.x1/y1`
now accept `None`; render.py omits the `(x1,y1)` group entirely when
so (`unparse` naturally produces `LINE -(x2,y2)`, matching universal
GW-BASIC-family syntax); c0.py raises `_Unsupported` for it (no
last-graphics-position surrogate modeled). Also gated the untested
STEP-with-omitted-first-point combination (bit 0x20 with 0x40 clear) to
stay fail-loud rather than guess a meaning for it.
(2) `LINE INPUT` into a computed string-array element: `line_input`
required the fixed `movsi; strassign` template; a computed index runs
an index-computation chain first. Mirrors `read_str`'s already-
calibrated `_INPUTREAD` mechanism exactly -- new `_LINEINPUTREAD`
sentinel, `state.pend_line_input` dict, `_lineinput_target` method.
After both, `cal87.exe` now fails on `unhandled materialized test`
(traced: a `jcc` code 0x76/JBE reaching `_lift_while`'s catch-all in a
shape involving two chained computed-array-element comparisons whose
second operand's provenance isn't yet clear -- genuinely unrelated to
LINE/LINE INPUT, needs its own fresh trace).

**`bmaster.exe`/`ifi.exe`/`filepatc.exe`/`hebrew.exe`, five more
sibling-table completions** (same risk profile as the second round's
three -- each is a documented, already-calibrated op family missing one
row):
- `andax_bp` ((0x23,0x46), AND ax,[bp+d8]): LOCAL-int sibling of
  `andax_m`, mirrors `addax_bp`'s existing bp-relative pattern
  (filepatc.exe).
- `subax_si` ((0x2B,0x04), SUB ax,[si], no ES prefix): the computed-
  array-element sibling of `far_subax_si` (added this session's second
  round) and of the plain `addax_si` -- mem on the right per
  `subax_m`'s convention, unlike `addax_si`'s mem-left (hebrew.exe).
- `icomp_si` ((0xDE,3) at `[si]`): the 16-bit-int sibling of `icomp`
  (disp16) and `icomp_si32` (LONG at `[si]`) -- the SAME missing-table-row
  pattern as this session's earlier `icomp_bp` find, just the `[si]`
  addressing mode instead of `[bp+d8]` (hebrew.exe).
- `ifold_si`/`ifold_n_si` ((0xDE,reg) at `[si]`, reg in `_FOLD_OPS`/
  `_FOLD_OPS_N`): the integer-array-element sibling of the disp16
  `ifold`/`ifold_n` pair that already existed -- the `[si]` FP dispatch
  table had `_FOLD_OPS`/`_FOLD_OPS_N` wired for D8 (float) and DC
  (double) but not DE (int), an oversight relative to the disp16 table
  which already had all three (filepatc.exe, reg=7=FIDIVR).

**`hebrew.exe`, two non-table-row fixes.** (1) A string relational used
directly as an assignable VALUE (`V% = A$ = B$`): materializes -1/0 into
ax with no dispatch pair (no `orax`/jcc/jmp), the next op stores ax
straight into a scalar via `movm_ax`. The existing FP-relational-as-value
branch in `control.py`'s `movax_family` explicitly excludes strings
("Strings stay fail-loud") because its shape needs an explicit `Group`
wrapper for byte-exactness in an ARITHMETIC context (`(A>0)*3` needs the
parens); this is a plain assignment where the whole RHS IS the
relational expression, so no Group is needed (`V% = A$ = B$` parses the
same either way) -- added as a narrowly-scoped SEPARATE branch, the
existing FP branch untouched. (2) `OPEN`'s reclen argument required a
bare `ir.Lit`; hebrew.exe computes it (`OPEN ... LEN = 18 - 50 * X%`) --
relaxed the check to accept any expression (the `== ir.Lit(0x80)`
default-detection already worked generically via `__eq__`, no change
needed there). After both, `hebrew.exe` now fails on `FIELD with no
AS-entries`: FIELD's width is ALSO a computed expression here, but
fixing that is a bigger lift than a guard relaxation -- FIELD's parser
assumes a fixed 5-op window (`movax; movsi; movdx; movesdx; field_as`)
per field entry and would need restructuring into incremental
expression evaluation to handle a variable-length width computation.
Flagged, not attempted this round.

Validation for all seven: full suite 2439 passed, 16 skipped, 0
regressions; ruff clean; full `scan_wild.py` re-run: still 25/84 (every
advance landed on a new gap, none closed outright), no new failures
elsewhere in the corpus.

### 2026-07-23 (later same day) — four table-completion fixes, no oracle

Continuation of the "decode a wild" work under an explicit "do not
advance recompiler" constraint (no `TBX_ORACLE` this session). Strategy
shift: instead of chasing new byte vocabulary (which the calibration
rule reserves for oracle-verified fixtures), hunted specifically for
gaps that are narrow, already-justified SIBLINGS of existing calibrated
op families -- same risk profile as the state.exe fix above, not new
semantics.

**`kinder.exe`'s `notax`-negated materialized test.** `_lift_while`
(`tbx/decode0/lift.py:421`) expects the fixed six-op materialization
template `movax FFFF; jcc; incax; orax; jcc; jmp`. `kinder.exe` inserts
a `notax` between `incax` and `orax`: `TIME$`-derived `strcmp` has no
direct-jcc-flip the way a numeric relop does, so a source-level `NOT`
wrapping the string comparison takes a real `F7 D0` (bitwise NOT of the
accumulator) to negate the already-materialized 0/-1 boolean before the
self-test. `notax`/`ir.Not` are BOTH already calibrated, verified
elsewhere (arith.py's plain unary-NOT dispatch) -- this only teaches
`_lift_while` to recognize the same already-verified op appearing in
one more position, wrapping `cond` in `ir.Not(cond)` when detected.
Verified: `kinder.exe` advances past this gap (into an unrelated
`unhandled op testw`, not yet closed). `grdscn.exe` shares the generic
"materialization template mismatch" message but for an UNRELATED reason
(a 3+-term OR chain, not a `NOT`) -- confirmed via separate trace before
touching anything, left alone.

**`bmaster.exe`/`ifi.exe`, three chained sibling completions.** All
three follow the same shape: an existing op family has a documented
sibling (INC has a DEC counterpart, ADD has a SUB counterpart, a
disp16/[si]-indexed compare has a bp-relative LOCAL counterpart
elsewhere in the SAME family) that was simply never added. Each fix
advanced both files into the NEXT gap in sequence (never fully closing
them this round):
1. `far_dec_si` (`26 FF 0C`, DEC word es:[si]): the STEP -1 sibling of
   the already-calibrated `far_inc_si` (`26 FF 04`, whose own comment
   already named bmaster.exe/ifi.exe as INC's wild witnesses). Mirrors
   `dec_bp`/`dec_m`'s existing NEXT-side step patch-up (rewrite the
   already-emitted `ir.For`'s step to `Lit(-1)`); outside a FOR context
   it fails loud, same as `inc_si`, since bare by-ref decrement compiles
   to the separate, already-handled `far_subm_ax_si`.
2. `far_subax_si` (`26 2B 04`, SUB ax, es:[si]): the subtractive sibling
   of `far_addax_si` (`26 03 04`). Orientation follows `subax_m` (mem on
   the right, `ax - mem`), NOT `addax_si`'s convention, since SUB isn't
   commutative.
3. `icomp_bp` ((0xDE,3) at `[bp+disp8]`): the LOCAL-int sibling of the
   already-calibrated `icomp` (disp16 scalar) and `icomp_si32` ([si],
   LONG) mixed-type-compare family -- a LOCAL int compared against an
   FP-stack value. Simply `state.pend_cmp = (state.loc_local(op[2]),
   state.stack.pop())`, mirroring `icomp`'s body with `loc_local` instead
   of `loc`.

After all three, both files hit a NEW, more complex gap: `LES di,[bp+N]`
(`c4 7e ..`) -- a by-ref access using DI as the pointer-index register
instead of the already-handled SI convention, immediately followed by
`AND cx, 0x7FFF` in bmaster.exe's case. `pw.exe` shares the generic
"unhandled byte c4" message but for a DIFFERENT shape (`LES bx,[bp+6]`
then a double-indirect `mov es, es:[bx]` reload) -- confirmed via direct
trace, not the same mechanism. This DI/BX-register-choreography family
is a genuinely new addressing convention, not a one-line sibling
completion -- left open, flagged for oracle-verified design work.

**`secure.exe` traced, NOT the same bug as state.exe.** Confirmed (per
Part II's own explicit warning not to assume): the interior GOTO target
lives inside a single-arm `IF...ELSE...END IF` block, which
`_resolve_targets`'s `map_body` only walks for single-arm NO-ELSE
blocks (its own docstring already calls multi-arm/ELSE interiors
"unwitnessed"). A real, different, deeper gap -- needs new IR/emit
design for numbering a line inside an ELSE arm, verified by oracle
before landing. Not attempted.

**`styled.exe`/`styllist.exe` traced, NOT fixed.** `core.py:832`'s
`item_to_stmt[s.target]` raises `KeyError: 87` -- an unguarded dict
lookup, not a deliberate fail-loud raise. Root cause: one `RESTORE`
target resolves to a raw item index (87) that is past the last DATA
item (86 items, valid indices 0..85) -- `RESTORE` to a line after all
DATA, a real, previously-unhandled boundary case in otherwise
well-established DATA/RESTORE splitting machinery
(`tbx/decode0/core.py:762-837`). NOT fixed: the render side
(`RESTORE {10 * (s.target + 1)}` in `tbx/ir/render.py:607`) means
whatever index this resolves to becomes an actual byte-significant LINE
NUMBER -- getting the boundary convention wrong (87 vs. 86, i.e.
one-past-end vs. some other offset) wouldn't crash, it would silently
mis-recompile, and I have no oracle to check which is correct. Needs a
minimal oracle-verified RESTORE-past-end probe before landing.

Validation for all four landed fixes together: full suite 2439 passed,
16 skipped, 0 regressions; ruff clean; full `scan_wild.py` re-run: still
25/84 (unchanged -- every advance landed on a NEW gap, not a closure),
confirming no regressions elsewhere in the corpus either.

### RESOLVED 2026-07-23 — intra-inline-IF-body GOTO targets (state.exe/state87.exe)

Traced live against `wild/hits/state.exe` directly (no oracle probe --
this is a control-flow/IR bug in already-scanned, already-verified op
data, not a byte-vocabulary gap, so the calibration rule's oracle-first
requirement doesn't gate it the same way; oracle-verified fixture
promotion is still pending, deferred to a later phase).

None of Part II's three candidate causes were right. The real mechanism:
`_fold_body` (`tbx/decode0/lift.py:498`) rewraps a nested `ir.IfInline`
`b` into a NEW `ir.IfBlock` object whenever `b`'s own body needs
block-folding (`_body_has_target(b.body, ...)`) -- but `b` ITSELF can
ALSO be a jump target (a GOTO landing on the header of this very nested
inline-IF, not on anything inside its body). The old code built the
replacement `ir.IfBlock` without transferring `stmt_addr[id(b)]` to the
new object's `id()`, so the address stayed keyed to the discarded `b`
and `_resolve_targets` could never find a live node at that address --
exactly the "address stays keyed to a discarded object" failure mode
`_fold_body_ifgotos`'s docstring already names (and already guards
against, in that other function) as the reason it transfers `stmt_addr`
on replacement. `_fold_body` was simply missing the same guard.

Fix: mirror `_fold_body_ifgotos`'s existing transfer -- after building
the replacement `ir.IfBlock`, copy `stmt_addr.get(id(b))` onto its new
`id()` before appending. `map_body` (`_resolve_targets`) already
recurses into single-arm no-else `ir.IfBlock`s looking exactly for this
entry, so no change was needed on the read side, only the write side
that was losing it.

Verified: `state.exe`/`state87.exe` both decode completely (2226 stmts
each) with zero other code changes. Full suite: 2439 passed, 16 skipped,
0 regressions. Ruff clean. Full `scan_wild.py` re-run: 25 decode-ok (was
23), 59 blocked, no new failures anywhere else in the 84-file corpus.
`secure.exe` still fails the same error message at a different target
(`0x82fe`) -- NOT re-traced, per Part II's own warning not to assume it's
the same shape without checking.

Not yet done (explicitly deferred, not an oversight): oracle-verified
minimal `.bas` reproducer + fixture promotion (`tests/fixtures/corpus/`),
per the calibration rule's normal promotion path. This session had no
`TBX_ORACLE` available and was directed to leave recompilation to a
later phase. The fix is a pure IR-identity bug (verified by direct
trace + full regression suite), not a new byte pattern, which is why it
was safe to land ahead of that verification -- but the gap should still
not be marked fully "closed" in the calibration sense until a fixture
exists.


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

### Session 2026-07-22: compiling array-parameter probe promoted to wild corpus

Per the campaign rule, the documented array-parameter probe
(`DIM A(3)` / `SUB F(B(1))` / `CALL F(A())`) compiled with the restored
oracle but failed decoding at an earlier `unhandled INT d4`. It does not
reproduce Gap 33's `INT EC sub 38`; the handbook's COMMON-array forms and
automatic local dynamic-array cleanup probes decoded cleanly. The retained
oracle executable is `wild/hits/arrayparam6.exe` (gitignored). The corpus is
now 85 executables: 23 decode OK and 62 blocked. This new `INT d4` witness
is preserved for the later singleton-dispatch work item.

### Session 2026-07-22 (later same day): the `far_call(mid-flow)` mystery SOLVED

The multi-session mystery from the entries below ("`KeyError: 86343`",
deepened to "a family of 6 targets, not 1", `$SEGMENT` ruled out) is
RESOLVED. Prompted by the user asking "does any wild file with an opaque
helper decode?" (no — checked directly, none of the wild files that hit
`OpaqueHelper` currently reach decode-ok) and then "maybe it's related?",
re-examined the actual bytes at all 6 mystery targets instead of reasoning
from old notes. One (`86343`) is genuinely a large-displacement outlier
(distance from its only caller is 39547 bytes, past a near call's signed
16-bit range) and is set aside separately below. The other five all land
on an IDENTICAL, fully-decodable shape: stage several literal arguments
into an unrolled `movm_ax_temp`-family temp frame (no `push_bp` needed
since the arguments are literals, not locals), open a nested `push_bp`
frame, do an `fn_call`, then keep staging more args (one of them the
`fn_call`'s own return value) before the REAL call fires. Nothing exotic
— just an ordinary multi-argument `CALL`/`GOSUB` with a nested `FN` call
as one argument, buried inside a big menu-dispatch routine.

The actual root cause, found by cross-checking the file's own event-trap
usage (`on_trap`: 3, `trap_ctl`: 3 in resume.exe's ops — this file
genuinely uses `ON KEY(n) GOSUB`) against `const.py`'s own pre-existing
comment: *"Any trap statement also makes the compiler emit a CC (INT 3)
event-poll hook before EVERY statement, and RETURN compiles as CB
(retf)."* Once ANY event trap is active ANYWHERE in a program, `RETURN`
compiles to a **far** `retf` (already correctly handled — `core.py`'s
`elif kind in ("ret", "retf"): state.put(ir.Return(), ...)` predates this
session). But its matching `GOSUB` must then ALSO compile to a **far**
`call` (a near call pushes only IP; a far `retf` expects `CS:IP` on the
stack — a mismatched pair would corrupt the stack), which was NOT
handled: `handlers/control.py`'s `far_call` case unconditionally treated
the target as a `SUB` name, raising `KeyError` in `_resolve_calls` when
the target was actually an ordinary GOSUB line. Reproduced cleanly with a
minimal, oracle-verified, non-shareware probe (`q_fargosub.bas`: an
`ON KEY(1) GOSUB` trap installed, PLUS one unrelated plain `GOSUB`
elsewhere in the same program) — the plain `GOSUB` alone reproduced the
identical `KeyError` shape.

Two-part fix, both in the existing `("addr", n)`-placeholder machinery
`CallStmt`s already use for forward SUB references:

1. `_resolve_calls` (`core.py`): when a far_call's target isn't in
   `proc_names`, don't raise — it's a GOSUB. Convert to
   `ir.Gosub(("addr", target))`, the exact sentinel the near `call` op
   already produces (`core.py`'s `elif kind == "call":
   state.put(ir.Gosub(("addr", op[2])), state.cur)`), so
   `_resolve_targets`'s ALREADY-WORKING `fix()` resolves the target with
   no further change needed. Raises if the "CallStmt" carries any
   arguments (a real GOSUB never does; this stays a loud contradiction if
   ever seen, not a silent misdecode).
2. A real, independent latent bug this surfaced: `handlers/control.py`'s
   `far_call` case called `state.put(ir.CallStmt(...), addr)` using the
   far_call INSTRUCTION's own address, not `state.cur` (the convention
   every other statement handler uses). Under active event trapping, a
   preceding `trap_hook` op claims `state.cur` as the STATEMENT's address
   (one position earlier than the far_call instruction itself) — the
   mismatch didn't crash, it silently fed the WRONG address into
   `state.addrs`, corrupting the `$EVENT ON/OFF` metadata-recovery pass
   (`state.cc_hooks` lookup) into inserting a spurious, byte-INEXACT
   `$EVENT OFF`/`$EVENT ON` pair around the statement. Caught only by the
   fixture's own byte-exact verification step, not by the scan succeeding
   — this bug has presumably always been latent for any trapping program
   with a `far_call`-compiled SUB call (not just the new GOSUB case), just
   never observed since no such fixture was ever byte-exact tested before
   (the `if state.cc_hooks or ...` $EVENT-recovery guard is a no-op for
   any non-trapping program, i.e. nearly the whole existing corpus).
   Confirmed the fix is exactly the needed correction, not overreach: an
   `assert state.cur is not None` in its place fails on ~100 existing
   fixtures (the ordinary, non-hooked case genuinely has `state.cur ==
   None` at this point, by design), so the fallback `state.cur if
   state.cur is not None else addr` is required, not decorative.

Fixture `t1_fargosub`, byte-exact both dialects. Advanced wild
resume.exe completely past this — its `_scan` and this fix together now
decode 100% of the file's control flow, up to a NEW, DIFFERENT error:
`jump target 0xa3dd is not a statement start`.

**CORRECTION (same day, follow-up): this is NOT the same bug as
state.exe/state87.exe**, despite sharing the same error message — traced
separately and they're unrelated. Target `0xa3dd` (41949) is the address
of a bare `jmp` instruction: specifically the inter-definition
"skip past the next SUB/DEF FN body" glue TB emits right after a
`proc_ret` (`(41945,'proc_ret',46), (41949,'jmp',43163),
(41952,'proc_enter')` in the raw op stream) — not a user statement at
all, and `stmt_addr` has zero entries for this address (vs.
state.exe's case, which had a real entry whose object was later lost —
see the correction on that entry, and `Part II`
for the full state.exe writeup and why the two are different). Something
is targeting pure compiler glue as if it were an addressable GOSUB line;
this needs its own from-scratch trace, not assumed to be fixed by
whatever closes the intra-inline-IF gap. No other wild file is currently
affected by the `far_call`/GOSUB fix itself (resume.exe is the only
corpus file combining event trapping with a `far_call`-compiled GOSUB so
far), but it is a correctness fix independent of that, not merely a
resume.exe-specific patch — it would trigger for ANY program mixing
event trapping with GOSUB, VERIFIED via the standalone, non-shareware
`t1_fargosub` fixture.

**Not yet resolved**: target `86343`'s own large-displacement mechanism
(does TB actually switch to far-call encoding for a near-call-range-
exceeding GOSUB target with NO `$SEGMENT` involved, purely as a
byte-savings/addressing-range fallback? Only one data point so far,
untested against a fresh oracle probe with a deliberately huge
displacement). And the `map_body` numbered-line-inside-a-SUB/DEF-FN-body
limitation two wild files (`state.exe`/`state87.exe`, now also
`resume.exe`) are blocked on — see the earlier diagnosis in this file for
why a speculative fix there is deliberately being deferred to a dedicated
session.

### Session 2026-07-22: four closures from the official handbook + three negative results

Prompted by the user adding a scanned/OCR'd copy of the 1987 Turbo Basic
Owner's Handbook to `docs/`, this session cross-referenced its Chapter 5
reference directory and appendices against the open-gap list above instead
of guessing blind. Four real, oracle-verified closures landed (23/84 wild
count unchanged — none happens to fully unlock a wild file on its own, see
below), plus three investigations that came up empty but are worth
recording so a future session doesn't repeat them. (Continued in a later
tick the same day: a fourth closure, `byte 36`, is appended near the end
of this section — it surfaced a real pre-existing bug, not just a missing
op.)

**CLOSED: `WIDTH device$, cols` (canonical `EC sub EE`).** The handbook's
own WIDTH entry documents `WIDTH device$, size` / `WIDTH #filenum, size`
(device options `SCRN:`/`LPT1:`-`LPT3:`/`COM1:`-`COM2:`) alongside the
already-implemented bare `WIDTH n`. Its own worked example is literally
`WIDTH "LPT1:",130` — compiling that exact line reproduced `unhandled INT
EC sub ee` on the first oracle probe. Byte shape: device string pushed
(`movsi <pooled-str>; rt 156`), then `mov ax,cols`, then `int EC sub EE` —
no new scan-time state needed. `ir.Width` gained a `device: object = None`
field (default keeps the old 1-arg `Width(cols)` call sites working
unchanged in `rename.py`/tests); `render.py` emits `WIDTH dev,cols` only
when `device is not None`. Fixtures `t1_widthdev`/`v10_t1_widthdev`
(`WIDTH "LPT1:",130`), byte-exact both dialects. Advanced wild
`cal.exe`/`cal87.exe`/`kinetics.exe` (all three independently hit this
exact signature) into three DIFFERENT later gaps (numeric INPUT without
FSTP; `LINE flag 00`; a new raw-byte signature) — none fully closes yet.
A sibling form surfaced in the same probe batch, `WIDTH #filenum, cols`
(canonical `EC sub f0`) — NOT implemented: unlike the device-string form,
its filenum is read back from system cell `0x60` (the same cell
`pend_fnum`/OPEN/SEEK already use) rather than passed through ax at the
call site, and no wild file currently blocks on it. Pick this up alongside
the `IOCTL`/`0x60`-cell material below if revisited.

**CLOSED: `IOCTL #n, s$` (canonical `EC sub 50`) and `IOCTL$(n)` (canonical
`EE sub 14`).** Neither statement was in `tbx`'s vocabulary at all before
this session (absent from `docs/decoder-statement-support.md`) — a genuine
Wave-5 "syntax inventory" gap, found while chasing `EC sub ac` below (see
next entry) on the theory that installer/security-utility wild files
(nvginst/pwinst/secure) doing `SEEK` then something with a filenum+string
might be `IOCTL`. That theory's specific target (`sub ac`) was WRONG, but
probing `IOCTL #1, A$` and `A$ = IOCTL$(#1)` directly (handbook: "IOCTL and
IOCTL$ communicate with a device driver... filenum ... string expression")
turned up two real, previously-unhandled sub-ops: `EC sub 50` (statement:
filenum via the `[0060]` cell like `WIDTH #n`/`SEEK`, then a pushed
string) and `EE sub 14` (function: filenum in ax, string result via the
ordinary `strfn`/`ir.Call` path — reuses the SAME ax-arg branch as
`CHR$`/`SPACE$`/`MKI$`/`INPUT$`, no new IR node needed). `sub 14` sits
alphabetically between `INPUT$F` (0x12) and `LCASE$` (0x16) in
`_EE_STRFN_SUBS` — exactly the kind of alphabetical dispatch-table gap
gap-17's precedent said to check first. New `ir.Ioctl(num, text)` statement
node (c0 raises `_Unsupported`, no device-driver surrogate on the emulated
machine). Fixtures `t1_ioctl`/`v10_t1_ioctl` (statement) and
`t1_ioctlfn`/`v10_t1_ioctlfn` (function), byte-exact both dialects and both
render forms (`IOCTL$(1)` renders fine even though the source used
`IOCTL$(#1)` — the oracle accepts either and compiles identically, i.e.
the leading `#` is source-level sugar with no separate byte encoding).
Does not touch any wild file (none currently reach either sub).

**CLOSED (same session, follow-up tick): `EC sub ac` was `PUT$ #n, s$`.**
The IOCTL lead above was a false positive on the exact sub value, but its
"filenum-cell + one pushed string" calling convention was the right shape
to keep searching for. `OPEN COM` (checked and ruled out — it's just
`OPEN`'s ordinary filename-string argument, no separate op) wasn't it;
the actual match came from the handbook's GET$ FUNCTION entry's own
cross-reference: "GET$, PUT$, and SEEK provide a low-level alternative...
byte-by-byte" — `PUT$ [#] filenum, string expression` (binary-mode write,
the complement of the already-implemented `GetString`/`GET$`). Compiling
`OPEN ... FOR BINARY AS #1` + `SEEK #1,1` + `PUT$ #1,"HELLO"` reproduced
`EC sub ac` exactly on the first probe — matching the wild files' own
`SEEK` immediately preceding it in all three. New `ir.PutString(num,
text)` node, consumed identically to the existing `ir.Ioctl` (no c0 case
added, same as `GetString` already has none — both fall through to c0's
generic `_Unsupported("statement ...")`). Fixtures
`t1_putstr`/`v10_t1_putstr`, byte-exact both dialects. Advanced all three
wild files (nvginst/pwinst/secure) into 3 DIFFERENT new gaps (`byte f7`;
`byte 36`; a jump-target error) — none fully closes on its own, each
needs its own triage.

**CLOSED (same day, autonomous-loop follow-up): `byte 36` (2 files:
hebrew.exe, pwinst.exe — the latter its OWN follow-on from the PUT$
closure above) turned out to be a real pre-existing bug, not just a
missing scan-level op.** Raw shape: `36 c7 04 <imm16>` = `mov
ss:[si],imm16` — visibly the literal-argument sibling of the
already-calibrated `movm_ax_temp` (`36 89 04` = `mov ss:[si],ax`, "staged
by-ref CALL arg"). First hypothesis (a literal by-ref `CALL SUB1(5)`
argument) was WRONG — that compiles through `ax` first
(`movax,5;movm_ax_temp`), never a direct immediate store. The real
trigger, found by widening the probe to "what ELSE uses this ss:[si]
store idiom": a DEF FN call used as ANOTHER DEF FN call's own argument,
where the inner call's OWN literal argument is staged via SI+SP
addressing (bp doesn't point at the inner frame yet) instead of going
through ax — `PRINT FNFOO("text", FNBAR(3))`.

Naively adding the new op (`movm_imm_temp`, appending to `state.pend_args`
like its sibling) made the crash go away but produced a SILENTLY WRONG
decode — `FNFOO("text", FNBAR(3))` decoded as `FNFN2(FNFN1("text"))`,
dropping an argument and misattributing "text" to the wrong function
entirely. Caught only because the recompiled source failed to compile at
all (`Error 454: Undefined function reference`) during the byte-exact
verification step — a reminder that "the scan no longer raises" is not
sufficient to ship without checking the round trip on a case with real
nested control flow. Root cause: `state.fn_args` (the DEF FN call argument dict,
keyed by bp offset, drained and CLEARED by `fn_call`) had no nesting
protection at all — unlike `sp_save_cell`, which already got a
`sp_save_stack` fix for the EXACT same class of problem (resume.exe,
documented earlier in this file: "a call used as its OWN outer call's
argument opens a NESTED push_bp/mov_mem_sp/.../pop_bp staging region").
When the inner DEF FN call's own `fn_call` drains+clears `fn_args`, it was
silently wiping out the OUTER call's own partially-staged arguments
too. Fixed with a parallel `fn_args_stack`, saved in `push_bp` and
restored in `pop_bp` right alongside `sp_save_cell`/`sp_save_stack`.
Separately, `movm_ax_temp`/`movm_imm_temp` needed to learn to ROUTE
correctly: a one-op lookahead (`state.ops[state.k+1]`) checks whether
`arg_push_temp` follows (plain SUB CALL — ordered `pend_args` list) or
not (nested DEF FN call closing straight into `mov_bp_sp;fn_call` —
offset-keyed `fn_args[state.si]`, using whatever the `si` offset was
computed as by the preceding `movsi`/`add_si_sp` pair, since that's what
becomes the new frame's own bp offset once `mov_bp_sp` repoints bp). SUB
CALL is a statement, not an expression, so it structurally can't nest as
an argument — making this two-way split exhaustive, not a heuristic.

Getting a byte-exact fixture took several tries and surfaced an
UNRELATED, separate, pre-existing gap in emit0's DEF FN canonicalization:
a "non-block" DEF FN body (a single assignment statement, even when
written across multiple physical lines with `END DEF`) does NOT round-trip
byte-exact through decode→emit→recompile AT ALL, regardless of nesting —
confirmed with the simplest possible 2-int-param, no-nesting case. Also,
per the handbook's own DEF FN syntax (`DEF FNidentifier` is one FUSED
token, not `FN` + space + name as a separate keyword), writing the
in-body result assignment as `FN Name = expr` (keeping the literal `FN`
prefix, space tolerated by the lexer) compiles to a materially DIFFERENT,
ALSO-valid shape than the bare `Name = expr` convention `emit0` always
canonicalizes to (extra `mov_bp_imm 2,0`, FP round-trip return via
`fild_bp`/`fstp_bp` instead of a direct `movax_bp`/`movm_ax_bp` int
return) — and if you decode+re-emit+recompile a `FN Name = expr`-sourced
EXE, you get the bare-convention bytes back, which legitimately differ
from the original. Neither of these is the nesting bug; both are
pre-existing, out of scope, and were avoided by building the final
fixture in the SAME bare, block-form (`LOCAL` + `Name = expr`) convention
`t1_fnlocalint` already uses and is proven to round-trip. Fixture
`t1_fnargcall`, byte-exact both dialects. New unit test
`test_nested_fn_call_argument_temp_staging` pins the `fn_args[si]` routing
directly; the existing `test_integer_call_argument_temp_staging` was
updated for the new lookahead signature. Advanced wild
hebrew.exe/pwinst.exe past this signature into 2 distinct new gaps (`byte
2b`; `byte 26`).

**CLOSED (same day, immediate follow-up): pwinst.exe's own new `byte 26`
was `or ax,es:[si]` — a mechanical, missing-vocabulary-table closure, NOT
the same hard problem as bmaster.exe/ifi.exe's pre-existing `byte 26`
(`26 ff 0c` = far DEC, needs `local_init` base-disp threading before it
can be implemented correctly — see the "Investigated at length but NOT
landed" writeup elsewhere in this file; don't assume this closure touches
that one).** Raw shape `26 0B 04` = `OR AX, ES:[SI]`, the OR sibling of
the already-calibrated `far_andax_si`/`far_addax_si`/`far_cmpax_si`
family (by-ref-int-param arithmetic/bitwise folds, gap-11's original
family plus gap-18's multiplicative addition) — checking that dispatch
table for a missing operator is still the first thing to try whenever a
new "byte 26 ..." gap shows up, per gap-18's own note. New op
`far_orax_si`, consumed identically to `far_andax_si` via the generic
`kind.endswith("_si")` table in core.py. Fixture `t1_byrefor`
(`SUB SUB1(N%): LOCAL Y%: Y% = N% OR 5`), byte-exact both dialects.
Closed pwinst.exe's `byte 26` failure entirely; advanced it to "DGROUP
layout not solvable (runtime slot grid anchor)".

**INVESTIGATED, NOT CLOSED (via a NEW, now-ruled-out angle): `INT 8c` (4
files: baby, help, prtguide, readme, all TB 1.0).** Previous sessions'
negative probes all varied the ON KEY(n) GOSUB shape itself (still
unresolved, see the existing `RR-INT-8C` entry). This session tried a
DIFFERENT angle first: all four wild files carry the Keyboard-break ('K')
IDE Options toggle (`_toggles()` confirms), matching the exact
"already-supported toggle can still hide an uncalibrated runtime-check
byte pattern if no fixture happens to exercise it" gotcha gap-21 (Overflow)
hit. Directly refuted: compiled a trivial program with `--toggles K`
(`frame/oracle`'s `tb_v86_compile.js`) against the SAME program without
the toggle and byte-diffed the two EXEs — for both a straight-line
program and a `FOR/NEXT` loop, the ONLY byte that differs anywhere in the
whole file is the toggle flag byte itself (`_toggles()`'s own read); ZERO
runtime-check code is inserted by 'K' for either shape. So Keyboard-break
does NOT explain `INT 8c` (whatever it does at runtime, it must read the
flag from ALREADY-existing dispatch code rather than emitting a new
instruction) — don't re-try this angle. The ON KEY(n) GOSUB shared-feature
observation from prior sessions still stands as the strongest lead;
untried per the existing note: a follow-on statement INSIDE the trap
handler body.

**INVESTIGATED, NOT CLOSED (exhaustively, this session): `EC sub 38` (4
files: catalog, football, refund, varamort — 2 dialects, so not a dialect
artifact).** Re-examined with a corrected trace (a broken debug patch in
an earlier pass of this same session had mislabeled the SECOND of two
back-to-back `sub 38` occurrences as `erase`/`sub 36` — they are BOTH
canonical `sub 38`; TB 1.0's raw byte is `0x36`, which `canon_sub`'s +2
shift maps to canonical `0x38`, coincidentally reusing ERASE's raw byte,
which is what caused the original confusion). With that corrected, ALL
FOUR files' occurrences are plain, standalone `movsi <block>; movdx
<reloc-seg>; movesdx; int EC sub 38` on a runtime dynamic-array block,
sometimes gated by a materialized-boolean `IF` (string- or numeric-compare
based), sometimes followed by a plain `RET` (end of a GOSUB'd
subroutine), never adjacent to a REAL erase. Ruled out this session (all
oracle-verified clean, zero `sub 38` occurrences): `CLEAR` with 1-3
dynamic arrays (any mix of numeric/string); `ERASE` of a 2-D or 3-D
dynamic array; `ERASE` of a `LONG`/`DOUBLE` dynamic array; `ERASE` inside
a conditional `GOSUB` (both string- and numeric-compare gated, both at
top level and inside the GOSUB body); re-`DIM DYNAMIC` of an array after
`ERASE`ing it (same size and a larger size); `ERASE A,B` with mixed
type (numeric+string) or mixed rank (1-D+2-D) in one statement (extending
the already-ruled-out same-type/same-rank case from a prior session).
`COMMON`-declared dynamic array + `ERASE` failed to compile in this
session's probes (syntax needs revisiting, not oracle-confirmed clean —
don't count this as ruled out). Genuinely still unidentified; the
"GET/PUT #n with an array-backed record buffer" candidate from
`Part I` was NOT tried (the handbook's own GET/PUT (files)
section only documents a FIELD-string-variable record buffer, no
array-typed one, casting doubt on this candidate specifically — but not
conclusively, since the handbook isn't a completeness guarantee per this
project's own scope statement). Next session: try the COMMON+dynamic
combination with correct syntax, and try ON-ERROR-implicit-cleanup paths
more thoroughly (a GOSUB'd error handler that erases/touches two arrays
in sequence, rather than a plain top-level `ON ERROR GOTO`).

**DIAGNOSED, NOT ATTEMPTED (same day, later tick; CORRECTED same day,
still later — the mechanism below was wrong, see the follow-up note):
`jump target ... is not a statement start` (state.exe/state87.exe,
identical target `0x1300d`; secure.exe's OWN occurrence at a different
target is a separate, untraced case — don't assume same root cause).**
This is NOT a byte-vocabulary gap: `decode0._scan` completes cleanly; the
failure is in `lift._resolve_targets`, well after scanning. Traced
precisely via a `core._resolve_targets` monkeypatch (import the function
BY NAME into `core.py`, so patching `lift._resolve_targets` directly has
no effect — patch `core._resolve_targets` instead): the unresolved
statement is a plain `IfGoto(cond=..., target=('addr', 77837))`, and
address `77837` (=`0x1300d`) genuinely IS a real op boundary
(`movsi,1630` starting a new statement).

**CORRECTION (same day, follow-up): the "lives inside a SUB or DEF FN"
framing above is WRONG.** `state.exe` has **zero** `proc_enter`/
`proc_ret`/`fn_ret` ops anywhere in its file — there is no SUB or DEF FN
at all. The real mechanism (confirmed by directly searching the live
`state.stmts` tree, within the same process, for the exact `id()`
`stmt_addr` recorded for this address — it is nowhere in the tree, not
even inside an `IfBlock`/`IfInline`/`SelectCase`) matches an EARLIER,
MORE PRECISE diagnosis already on record further down in this file under
"Intra-inline-IF-body GOTO targets (2 files: state.exe, state87.exe)": a
giant `ir.IfInline` (~40 statements, a flattened GOTO-based chain of
`IF cond THEN <lineY>` with no block `IF`/`END IF` in the source) whose
own body contains a jump landing on ANOTHER statement inside that SAME
body. The "second leg" fold in `lift._fold_if` that's supposed to catch
exactly this (converting such an `IfInline` into an addressable
`ir.IfBlock` via `_body_has_target`) does not fire for this specific
shape, for a reason not yet pinned down. A full spec for tackling this
(confirmed facts, the exact machinery involved, an investigation plan,
and an explicit note that `resume.exe`'s own DIFFERENT new failure below
is NOT the same bug despite an earlier commit message here claiming
otherwise) is at `Part II` — start there, not
from this entry, before touching `_fold_if`/`_resolve_targets`.

**Deliberately not attempted this session**: unlike every closure above
(purely additive new vocabulary ops, zero risk to already-passing
fixtures), a change to this fold/resolution machinery is a control-flow
change that could silently miscompile OTHER already-passing fixtures
whose shapes are adjacent to whatever the actual fix touches. Needs a
dedicated session — see the spec doc for the concrete next steps
(build a minimal oracle probe reproducing the exact intra-inline-body
jump shape FIRST, trace exactly why `_body_has_target`/`_fold_if` miss
it, THEN design the fix).

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

**A real alternate TB build was sourced and tested against `RR-SYSCELL-8A`,
negative result (2026-07-21)**: rather than patch the oracle's compiler
binary to fake the `RR-SYSCELL-8A` shift (circular evidence), a genuinely
different, independently-obtained TB.EXE was found and tested instead --
a German-market build (Oct 1987, 212524 bytes, from archive.org's
KryoFlux dump of `BorlandTurboBasic1.0German`, disk3), registered as
`vendor/turbo_basic_oracle/tb11_de_floppy.img` (the raw EXE sits
alongside it as `tb_german_d3.exe`, kept intentionally, not wired into
`oracle.py`'s dialect dict since it's investigative, not first-class).
Batch-compiled all 297 `t1_*` corpus fixtures with it and diffed each
against the verified English `.exe`, restricted to the user-code region
(every file differs earlier, from a harmless linked-runtime-library
reshuffle present in 100% of outputs): 272 byte-identical, 15 differ
only in whole-file size (user-code identical once offset), and exactly 3
(`t1_view`/`t1_wait`/`t1_window`) show real diffs -- but every one lands
strictly after the compiled program's `epilogue`, in trailing padding
the decoder never scans. This build is functionally identical to the
oracle's existing TB 1.1 everywhere that matters, including the exact
COLOR/SCREEN pairing that triggers the bill.exe/color.exe shift -- it
does not explain `RR-SYSCELL-8A` and does not narrow any other gap.
Don't re-test this same build; if pursuing this further, the French TB
1.1 disk exists on WinWorld/vetusware but needs an authenticated
download this session couldn't complete. Also corrected while doing
this: the oracle `oracle.py` actually resolves to (`oracle_dir()`) is the
vendored copy at `tbx/vendor/turbo_basic_oracle`, NOT the sibling
`../frame/oracle` checkout some earlier session notes assumed -- the
vendored copy's `tb_v86.js` properly honors `--workspace` where
`frame/oracle`'s silently ignores it (always writing to
`<oracle_dir>/SOLVER_v86.EXE`); `frame/oracle` is still needed for the
toggle-compile script (`tb_v86_compile.js`), which isn't vendored.

### Where things stand

**Updated 2026-07-21 (latest session): 23 of 84 wild EXEs decode-ok** (unchanged
count, but bmaster.exe/ifi.exe both advanced three gaps deeper without yet
finishing). Picked up the tied-top-of-tally "DGROUP layout not solvable"
gap (menu/night/sprogh/swbb) first per the frequency-order standing
instruction, but the hand-derive-`ds` promotion criteria in
`RR-DGROUP-BIGARR` led nowhere new this round: brute-force-scanning
menu.exe for `_parse_static_slot`-valid runs (both tightly-packed and
ARR_BLOCK-strided) only ever turns up the SAME false-positive family
already on record, clustered right before the pool marker with
implausible counts (3001/8002/etc) — extending the descending-n walk past
its current 31-array cap up to n=200 doesn't surface anything better
either. Left exactly as documented in the JSON entry; do not re-attempt
this exact brute-force without a new idea (e.g. actually reading what
`_is_rt_slot`/COMMON-adjacent shapes look like around the real 0x2f2-0x400
movsi run, which never got explained). Pivoted to `byte 8b`'s sibling
tally instead and found a clean, oracle-verified two-gap chain:

- **ESC DA modrm=1C, the `[si]` (computed-index) sibling of `icomp`**
  (2026-07-21): `mod=0,reg=3,rm=4` with `esc=DA` is a computed-index LONG
  (`&`) array element compared against an FP-stack value (`IF A&(J%) > 5
  THEN`) — reg=3 under the DA (m32 long-int) ESC family is FICOMP, and the
  `[si]` kind table already has the m64/m32-store/etc siblings but never
  this one. New op `icomp_si32`, consumed identically to `fcomp_si`/
  `fcomp_si64` (`state.pend_cmp = (ref, state.stack.pop())` — same
  handler branch, just added to the tuple). Fixture `t1_licomp`
  (`DIM A&(5)` + a variable-index compare), byte-exact both dialects.
  Closed the ORIGINAL blocker for wild bmaster.exe/ifi.exe (both fail at
  the identical file offset 0x8fdd — near-duplicate binaries), which then
  advanced to a new "LOCAL FOR, variable limit" gap immediately below.
- **Integer FOR over a LOCAL var with a VARIABLE (non-literal) limit**
  (2026-07-21): the bp-relative mirror of the already-working DGROUP
  `movax_m`/`cmpm_ax` variable-limit pair (`t1_fori`), using new ops
  `cmpm_ax_bp` (scan-level: `39 46 d8` = `cmp [bp+d8],ax`, the bp-relative
  sibling of `cmpm_ax`'s `39 06 disp16`) plus a NEXT-side continuation
  branch mirroring the existing `movax_m`+`cmpm_ax` FOR-test recognizer,
  both keyed off `cmp_at_t[1] in ("movax_m","movax_bp")` so the same
  header-fold code serves both frames (vdisp/`loc_local`'s L-names already
  disambiguate uniformly, same trick used by the variable-STEP LOCAL case
  and the literal-limit LOCAL case before it). The header reserves a
  [step-temp, limit-temp] word pair right after the loop var, same
  convention as those two prior LOCAL-FOR gaps: the step-temp (v+2) is
  unused here (literal step 1) and dropped immediately, but the
  limit-temp (v+4) is read again at every iteration's test (`movax_bp`
  reloads it) so it has to be stashed in `hidden_locals` and stripped only
  at `proc_ret`, exactly like the variable-STEP case's own step-temp.
  Fixture `t1_locforvarlim` (`SUB TEST(N%): LOCAL I%: FOR I% = 1 TO N% ...`),
  byte-exact both dialects. Advanced wild bmaster.exe/ifi.exe past this
  gap too (both now fail at the SAME later offset 0x9081 — see below).

- **Integer FOR over a BY-REF INTEGER PARAMETER used directly as the loop
  var, with a VARIABLE limit** (2026-07-21): the SAME "variable-limit FOR"
  family a third time, now via the ES:[SI] by-ref indirection instead of
  bp-relative LOCAL storage. Byte shape at the test: `les si,[bp+P]; 26 ff
  04` (`INC word ES:[SI]`, new op `far_inc_si`) then `mov ax,[limit-temp]`
  (`movax_bp`, unchanged) then `les si,[bp+P]` (reload) then `26 39 04`
  (`CMP word ES:[SI],AX`, new op `far_cmpm_ax_si` — the far mem-first
  sibling of `cmpm_ax`/`cmpm_ax_bp`). Since the loop var IS the parameter
  (never occupies its own LOCAL slot), the header only reserves the
  [step-temp, limit-temp] pair, with limit-temp == step-temp + 2 — the
  SAME relationship as the pure-LOCAL case above, where the loop var's own
  slot simply precedes them (`v`, `v+2`, `v+4` vs. here just `v+2`,
  `v+4`-equivalent starting from the pair's own base). The by-ref case
  needed its own header-recognition and NEXT-continuation branches (an
  extra `arg_ref` op sits between the limit reload and the far compare,
  breaking the two-op adjacency check the LOCAL case's combined branch
  used) but reuses `far_movm_imm_si`'s EXISTING init-statement production
  unchanged (`Assign(Var("Pxx%"), Lit(1))` already looks exactly like the
  scalar/LOCAL init shape the header recognizer expects — `vdisp` already
  strips any single-letter prefix uniformly, so no new machinery was
  needed there). `far_inc_si` is gated exactly like `inc_bp`/`inc_m`
  (silently consumed only when `state.fors[-1]["v"] == state.pend_arg`,
  fail-loud otherwise — unwitnessed as a bare `by-ref X% = X% + 1`, which
  already has its own op, `far_addm_ax_si`). Fixture `t1_byrefforvar`
  (`SUB TEST(N%,M%): FOR N% = 1 TO M% ...`), byte-exact both dialects.
  Advanced wild bmaster.exe/ifi.exe past this gap too (both now fail at
  the SAME later offset 0x935f, `unhandled byte 16 at 0x935f` — see next).

- **`CALL SUB2(A%)` where `A%` is a LOCAL var declared in the CALLING
  sub** (2026-07-21): the byte-16 gap above turned out to be UNRELATED to
  the FOR-loop chain — a THIRD wild file, resume.exe, hit the identical
  message independently, pulling the tally bucket up to 3 and making it
  worth chasing on its own. Byte shape: `push ss; mov ax,off; add ax,bp;
  push ax` — the LOCAL-frame sibling of the already-calibrated
  `arg_push_ref` (DGROUP scalars: `push ds; mov ax,off; push ax`, no
  `add ax,bp` needed since DGROUP disps are compile-time absolute; a
  LOCAL's bp-relative address needs the extra runtime add). New op
  `arg_push_ref_bp`, consumed identically to `arg_push_ref` via
  `state.loc_local` instead of `state.loc`. Found directly on the first
  probe try (`CALL SUB2(A%)` from inside a SUB with `A%` declared
  `LOCAL`) — an earlier guess (`MID$` statement mutating a LOCAL string)
  was a dead end that turned out to hit the ALREADY-documented "FP/string
  -typed LOCAL variables are unsupported" gap instead, one existing
  `loc_local` caveat away from being a false lead; the CALL-arg guess
  matched the byte shape exactly on the next attempt. Fixture
  `t1_localargcall`, byte-exact both dialects. Advances all three wild
  files further (bmaster.exe/ifi.exe to a NEW `unhandled byte 26 at
  0x9446`; resume.exe to a NEW `unhandled byte 29 at 0xa043`).

- **`N% = N% - <expr>` where `N%` is a by-ref INTEGER parameter**
  (2026-07-21): the byte-26 gap above (bmaster.exe/ifi.exe) turned out to
  bundle at least two DIFFERENT unrelated ops sharing the `26` ES-prefix
  byte. `26 29 04` = `SUB word ES:[SI], AX` is simply the subtraction
  sibling of the already-calibrated `far_addm_ax_si` (`26 01 04` = `ADD
  word ES:[SI], AX`) — new op `far_subm_ax_si`, consumed identically via
  `BinOp("-", ...)` instead of `("+", ...)`. Fixture `t1_byrefsub`,
  byte-exact both dialects.

**Investigated at length but NOT landed this session**: the OTHER byte-26
op at the SAME offset (0x9446 in bmaster.exe) is `26 ff 0c` = `DEC word
ES:[SI]` — the STEP -1 descending sibling of `far_inc_si` (just closed
above), for a by-ref INTEGER parameter used directly as a FOR loop
variable. A full probe (`SUB TEST(N%): FOR N% = 5 TO 1 STEP -1: ...`)
reproduces it exactly, alongside a literal-limit sibling of
`far_cmpm_ax_si`: `26 83 3C imm8` = `CMP word ES:[SI], imm8` (the far
mem-first analog of `cmp_mi8`/`cmp_bpi8`). Both ops' scan-level shapes,
consumers, and a full header/NEXT-continuation recognizer pair were
implemented and got the probe decoding completely — **but the emitted
source was WRONG** (`LOCAL B%, C%` appeared where the original source
declares no LOCALs at all), and the recompiled bytes did NOT match the
original EXE. Root cause: `local_init` still reserves a [step-temp,
limit-temp] word pair for this shape (exactly as it does for the
LITERAL-limit LOCAL-loop-var case, `cmp_bpi8`), but NEITHER word is ever
referenced anywhere in the ops stream when both the limit AND the
loop-var storage are unavailable as anchors (no `movax_bp` reload to
supply the limit-temp's disp, unlike the *variable*-limit by-ref case;
no loop-var LOCAL slot to compute `v+2`/`v+4` from, unlike the pure-LOCAL
case) — so there is genuinely no live evidence pointing at either
disp, and nothing in the header-fold code currently has access to
`local_init`'s own raw base displacement to hide them by direct
position. A follow-up probe (`SUB TEST(N%): LOCAL Z%: Z%=99: FOR N%=5 TO
1 STEP -1: ...`) confirmed the two phantom words are placed in SOURCE
DECLARATION ORDER right where a LOCAL slot for `Z%` was NOT needed for
the FOR (`local_init 3, 10`: disp 10 = `Z%` since it's declared first,
disps 12/14 = the FOR's phantom pair) — i.e. the phantom pair's position
depends on how many OTHER locals precede this FOR textually, which the
current header-fold code has no way to know without either (a) plumbing
`local_init`'s raw base/`disp` argument through to the fold logic instead
of just the derived `locals` dict, or (b) scanning the ENTIRE remaining
proc body for any reference to a candidate disp before deciding it's
dead. Given the fix didn't verify byte-exact, ALL of it (both new scan
ops, both new consumers, and both new header/NEXT branches) was reverted
before committing — only the unrelated, independently-verified
`far_subm_ax_si` fix from the same investigation was kept. Next session:
start from this exact writeup (probes `q_byrefforstepm1.bas`/
`q_byrefstepm1local.bas`, not saved as fixtures since unverified) and
either thread `local_init`'s base disp through to the FOR-header
recognizer, or find some other live anchor before re-implementing.

**Goal tightened mid-session to require a FULL wild-file closure, not just
advancing gaps** — pivoted away from the bmaster.exe/ifi.exe/zip.exe chain
(none looked close to fully closing) to hunt for smaller, more mechanical
fixes elsewhere in the tally:

- **ESC DA modrm=1E, the disp16 sibling of `icomp`** (2026-07-21):
  `mod=0,reg=3,rm=6` with `esc=DA` is a plain LONG (`&`) SCALAR variable
  (or pooled literal) compared against an FP-stack value (`IF X& > 5.5
  THEN`) — the disp16 counterpart of this SAME session's `icomp_si32`
  ([si], computed-index array form). New op `icomp32`, consumed
  identically to `icomp` but via `state.pool_lit32` instead of
  `state.pool_lit` for the pooled-literal fallback (mirroring `ifold32`'s
  existing long-pool-literal pattern). Fixture `t1_icomp32`, byte-exact
  both dialects — found and verified on the very first probe. Advances
  wild stat.exe (does NOT close it — see the dedicated ES/DS-segment-save
  writeup near the end of this section; the SAME shape blocks mdb.exe/
  mdb87.exe too, tallied there as "byte 8c").

- **Rank-4 static array accessed at a COMPUTED (variable) index, all four
  subscripts** (2026-07-21): pivoted away from bmaster.exe/ifi.exe/zip.exe
  (all stalled this round) to hfprop.exe's own long-open "displacement
  0x2b2 is neither scalar nor array element", per the `imul_m`/`icomp32`
  precedent that this error class is often a mechanical evidence-table
  gap, not fresh reverse-engineering. Confirmed: the far-IDX register
  machine's `imul_m`/`addsiax` chain (used for a computed multi-dim
  element's index arithmetic) only ever recognized TWO span cells
  (`jspan`@blk+0x0C for span1, `kspan`@blk+0x12 for span2) and one combine
  level (`jk`) — enough for rank ≤ 3, but a rank-4 array's 4th dimension
  needs a THIRD span cell (`lspan`@blk+0x18, i.e. span3) and a second
  combine level (`kl` = lspan+kspan, then `jkl` = kl+jspan, then finally
  `idx` = jkl+i). The existing `t1_dim4` fixture never exercised this at
  all — CONSTANT-index rank-4 access compiles through the movsi-disp16
  path (gap 15), a completely different mechanism from computed-index's
  shl-si/imul_m chain. Fixture `t1_dim4v` (`DIM Q(2,3,5,4)` with all four
  subscripts as variables), byte-exact both dialects — the FIRST fix this
  session verified on the first probe attempt. Only an OPTION-BASE-0
  (bare span multiply) 4th dimension is calibrated; a rank-4 array under
  OPTION BASE 1 would ALSO need `subax_m`'s lo-subtraction off-check
  extended to `blk+0x1A` (l - lo4) — unwitnessed, left fail-loud
  deliberately rather than guessed. Advances wild hfprop.exe (does NOT
  close it — next stop is a NEW, separately-documented "ax,bx combine
  with empty regs" gap, likely the SAME still-open 3-term mixed
  short-circuit/combinator control-flow puzzle grdscn.exe already
  surfaced and left unresolved earlier in the campaign — read that
  writeup before re-investigating). sabpcv3.exe's OWN "displacement ..."
  hit is a DIFFERENT root cause (a `movm_imm` target inside the ordinary
  scalar band failing to resolve, right after a `RANDOMIZE`/`TIMER`
  materialized-boolean sequence) — smells like a genuine DGROUP layout
  solving bug for this file specifically, not a decoder-vocabulary gap;
  untouched, needs its own `layout.py`-focused session.

- **LOCAL FOR-NEXT with literal `STEP -1`, plus bare LOCAL DECR** (2026-07-21):
  pivoted to horses.exe's "unhandled byte ff", following the same
  "sibling of an existing op" playbook. `dec_bp` (`FF 4E d8` = `DEC word
  [bp+d8]`) is the LOCAL-frame mirror of `dec_m`, gated exactly like
  `inc_bp` — consumed silently only inside a matching open FOR (patches
  the already-emitted `ir.For`'s step to `Lit(-1)`, mirroring `dec_m`'s
  own patch-up); fixture `t1_localforstepm1`, byte-exact both dialects.
  Advancing past that surfaced `subm_ax_bp` (`29 46 d8` = `SUB word
  [bp+d8], AX`), the subtraction sibling of the already-calibrated
  `addm_ax_bp` (bare LOCAL DECR, `X% = X% - 1`, outside any FOR) —
  fixture `t1_localsub1`, byte-exact both dialects. **Neither fix closes
  horses.exe**: it advances to a THIRD occurrence of the raw `DEC
  [bp+0x2E]` byte pattern, but this time genuinely OUTSIDE any open FOR
  (confirmed via trace: `CMP AX,[BP+46]` as a materialized-boolean VALUE
  comparison, then an IF/ELSE-shaped branch where the ELSE arm is the
  bare `DEC`) — i.e. dec_bp's fail-loud "outside a FOR" gate is legitimately
  hit by a REAL, un-witnessed shape, not a bug in the gate. A dedicated
  probe reproducing the EXACT same-looking source (`IF cond THEN X%=5
  ELSE X%=X%-1`, both TB 1.0 and 1.1) compiled to `subm_ax_bp` instead of
  a raw `dec_bp` in every attempt — so whatever specific difference
  triggers horses.exe's raw-DEC encoding for a NON-FOR decrement is still
  unidentified (possibly: statement position, a GOTO-based flow instead
  of block-IF, or some other structural cue) — needs more probe variants
  before extending `dec_bp`'s outside-FOR case; do not guess it in per
  the calibration rule.

### Gap: segment-register juggling around a far array access (stat.exe/mdb.exe/mdb87.exe), INVESTIGATED, NOT LANDED (2026-07-21)

Shared root cause behind stat.exe's "byte 8c" (surfaced by this session's
`icomp32` fix) and mdb.exe/mdb87.exe's OWN independent "byte 8c" hits
(same message, confirmed via trace to be the identical mechanism, not a
coincidence). The immediate byte is `8C 06 <disp16>` = `MOV [disp16], ES`
— the STORE-direction sibling of the already-calibrated `moves_m` (`8E 06
<disp16>` = `MOV ES,[disp16]`, LOAD direction). Byte-traced context in
mdb.exe: a bounds-checked/computed STRING array element access
(`shlsi;shlsi;moves_m <block>` — ES now holds that array's segment) is
IMMEDIATELY followed by this store (stash ES into a scratch cell, disp
`0x62` in every witnessed case), then — one instruction added and tested
in isolation, reverted after each step since none of it is oracle-verified —
`8E 1E <disp16>` = `MOV DS,[disp16]` (reloading the SAME scratch cell, but
into DS, not ES), then a THIRD unidentified `unhandled byte 8b` immediately
after that. Confirmed via `state.pend_es`/`state.r_arrs` reading that
`moves_m`'s existing gate (`op[2] not in state.r_arrs: raise`) is scoped to
runtime arrays specifically — this shape's context (bounds-checked/computed
STATIC string array in stat.exe) doesn't obviously fit that gate as-is, so
even the FIRST new op (`movm_es`) would need its own semantics, not just a
copy of `moves_m`'s.

**Working theory, unconfirmed**: DS gets temporarily repointed to the SAME
segment ES just held (a static or bounds-checked array's own segment) so
that a SECOND array can be addressed via ES SIMULTANEOUSLY, letting the
compiler reuse the ordinary near (DS-implied) op set for one array and the
far (ES:) op set for the other in the same copy/compare/swap sequence —
i.e. likely a two-array element operation (copy, compare, or swap) where at
least one of the two arrays is NOT a plain runtime-DIM'd array (ruling out
`moves_m`'s current `r_arrs` gate as sufficient).

**Ruled out this session** (all compiled clean, oracle-verified, zero `8C 06`
occurrences in the resulting EXE): plain `SWAP` of two computed STRING array
elements (both int- and single-typed loop variable index); `MID$` statement
on a computed STRING array element; copying an element between two DIFFERENT
runtime-DIM'd (`DIM ...(N%)`) arrays, both integer; copying between two
DIFFERENT runtime-DIM'd DOUBLE arrays under Bounds checking; passing a
Bounds-checked computed DOUBLE array element by reference to a SUB (this
one DID hit a DIFFERENT gap, `far_fold64_si`, so Bounds-checked far DOUBLE
by-ref args are a separate, also-open gap, not this one).

**Do not add `movm_es`/a DS-reload op speculatively** — three sessions'
worth of the calibration rule violations in one place is exactly the
"guessing" the rule forbids; a real fixture reproducing the exact `8C 06;
[something]; 8E 1E; [byte 8b]` chain is needed before writing any of this
in for real. Next steps: try a computed STRING array element used in an
IF-compound (not SWAP) with a DIFFERENT static/bounds-checked STRING array
on the other side; try FIELD/RANDOM-file record buffers (a `FIELD`-defined
buffer segment might need exactly this kind of juggling); or bisect
stat.exe's own source-adjacent statements directly if a source listing for
this specific shareware title is ever found.

### Gap: resume.exe's CGA-blitter helper family (CLOSED) + a new sub-VAR_BASE FP64 scalar (OPEN)

resume.exe's `unhandled byte c4`/`byte b4` sequence turned out to be gap
19's already-recognized-but-only-partially-fingerprinted opaque-helper
family (see `_OPAQUE_HELPER_BODY`/`_OPAQUE_HELPER_BODY_2`'s existing
docstring — a real framed far procedure the compiler links in, source
semantics deliberately not inferred, "coverage-only recovery"): the file
places SEVEN of these back-to-back, each skipped by its own `JMP`, almost
certainly one per video-mode/pixel-depth combination for a single
graphics primitive (all share the exact `push bp; mov bp,sp; push ds;
push es; ...; pop es; pop ds; pop bp; int3; retf` framing and the CGA
horizontal-retrace-wait idiom). Extracted each exact byte sequence via
the existing `_try_inline_rescue` machinery (byte-for-byte, not
approximate) and registered all six new ones (`_OPAQUE_HELPER_BODY_3`
through `_8`) alongside the two already known. Verified via the full
existing test suite (zero regressions) — no NEW fixture needed, same as
how the original two bodies are treated (their own source trigger isn't
inferred either).

Past all seven helpers, resume.exe hit a chain of SIX more gaps, each
found and fixed in turn (see the dedicated commit for the full writeup
of each) — all verified against the real wild file's exact byte trace
plus the full test suite/wild-scan regression check after every step:

1. **`fp64_bridge`**: the `displacement 0x52 ...` gap turned out to be a
   transient sub-`VAR_BASE` scratch cell, NOT a real scalar — an
   `fstp64`/`fcomp64` "promote once, compare many times" idiom
   (`IF N%=1 THEN...ELSEIF N%=2 THEN...` promotes the by-ref INT param to
   DOUBLE once and rereads the cache for each comparison), the exact same
   "stage, then reread" shape as the existing `fistp[0x2C]` IDX% bridge,
   just at a variable position. Confirmed via direct trace (repeated
   `fcomp64` reads of the identical disp) — NOT a `layout.py` scalar-band
   floor issue at all, so the earlier session's specific concern about
   `movm_imm`'s VAR_BASE-gate precedent not applying doesn't matter; this
   needed a wholly different (correct) mechanism.
2. **FP-typed LOCAL variables in SUB bodies**: the SAME gap ziptest.exe
   hit and left unresolved earlier this campaign. `fld_bp`/`fstp_bp`/
   `fold_bp`/`fold_n_bp`/`fcomp_bp` had NO case for `state.proc_frame`,
   silently no-oping. Implemented for SINGLE precision (spans two LOCAL
   words, renaming the first's phantom int name to `!` and dropping the
   second). Fixture `t1_localsingle`, byte-exact both dialects. (DOUBLE
   LOCALs, spanning four words, remain unimplemented — unwitnessed so
   far.)
3. **`arg_push_arr` as a shlsi-chain terminal**: a computed array
   element's address pushed as a by-ref CALL arg — the computed-index
   sibling of core.py's existing constant-index (movsi-disp16) handling.
4. **Deferred forwarded-arg type resolution**: a CALL to a SUB defined
   LATER in the file, forwarding an enclosing SUB's own by-ref param,
   needs the callee's param list to type the arg — unknown yet for a
   forward reference. Stages a second `("fwdpending", ...)` placeholder,
   resolved by the same post-pass that fixes up forward CallStmt names.
5. **`cmpax_bp`'s AND-chain shuffle**: the ax↔bx no-op round trip that
   preserves a running AND-accumulator across a compare (already handled
   for `cmpax_m`), extended to `cmpax_bp`.
6. **`subax_m`'s general fallback**: previously ONLY handled far-IDX
   array lo-subscript normalization, raising for anything else. Added
   the same pool-literal/scalar fallback `addax_m` already has, for a
   plain `<expr> - <mem>` fold (mem on the RIGHT, since SUB isn't
   commutative).
7. **`negax` spliced out of an element-access terminal lookahead**:
   negates whatever's already staged in ax (unrelated to the array
   element itself, e.g. `ARRAY(i) + (-2)`) before the real terminal
   combines it — not part of the element-access protocol.

None of gaps 1, 3–7 have a dedicated oracle-verified fixture (probes
built for several didn't reproduce the exact optimization trigger) —
verified instead via direct trace against the real wild file plus the
full regression suite, the same standard the existing `movm_imm`
VAR_BASE-gate-deferral fix (`b20bdc6`) already established as acceptable
for logic fixes that reuse already-verified resolution paths.

**resume.exe is STILL not fully closed.** The next (and, as far as this
session traced, LAST) blocker: `LOCAL zero-fill outside a fresh SUB
body`. Root cause fully diagnosed: this file has a **DEF FN that ALSO
declares LOCAL variables** — a combination with no existing support at
all (`local_init`'s handler hard-requires `state.proc_frame`, which only
`proc_enter`/SUB bodies ever set; DEF FN's own `state.fn_frame` has no
"locals" concept whatsoever). Compounding this, the auto-fn_frame-
creation that would normally open `fn_frame` for an unframed DEF FN body
NEVER fires for this specific DEF FN, because it's gated on `addr <
state.main_start`, and `state.main_start` is `None` for this whole file:
the ONE-TIME check that sets it (`state.k == 0 and kind == "jmp"`)
requires the file's very FIRST op to be literally a `jmp`, but this
file's first op is a `trap_hook` stamp (confirmed via direct trace: `ops[0]
== ('trap_hook',)`, `ops[1] == ('strfn', 'COMMAND$')` — no leading skip-jmp
at all in this file's compiled layout). Implementing this needs BOTH:
(a) a narrow, low-risk trigger — auto-create `fn_frame` (or a
fn_frame-scoped "locals" dict) directly from `local_init` itself when hit
with no open `proc_frame`/`fn_frame`, rather than depending on
`main_start` at all (safe: this path currently ALWAYS raises, so no
currently-passing file's behavior can regress); AND (b) properly
separating DEF FN "locals" from DEF FN "params" in `fp_bp`'s handler and
`fn_ret`'s closing logic — `fn_ret` currently computes `nparams =
max_off // 4` from the single highest bp-offset EVER touched, assuming
EVERY touched offset is a positional parameter; LOCAL variables would
need to be excluded from that count and instead emitted via their own
`ir.Local(...)`, mirroring `proc_ret`'s existing SUB-side treatment. This
is a real, if bounded, new subsystem.

**Attempted and REVERTED this session** (the risk assessment above turned
out to be justified): implemented (a) and part of (b) -- `local_init`
auto-creating `fn_frame` retroactively when hit with no open frame at
all, and `fp_bp`'s handler (fld_bp/fstp_bp/fold_bp/fold_n_bp/fcomp_bp)
checking `fn_frame["locals"]` before falling back to the positional-param
assumption, reusing the SAME `_single_local` SINGLE-precision logic the
`t1_localsingle` fix (above) already established for the SUB case. This
correctly created the frame and registered the one declared LOCAL (disp
6) -- but immediately surfaced a SECOND, unrelated failure: `movax_bp 2`
(a PLAIN integer LOCAL read, a DIFFERENT op from fld_bp) tried to resolve
bp+2 as a LOCAL and failed, because bp+2 is NOT a user LOCAL in a DEF FN
at all -- it's the SAME fixed "string result descriptor pointer" cell
`mov_bp_imm`'s own docstring already documents (a single-line STRING FN
zeroes only bp+2; a multi-line/numeric FN zeroes bp+0 AND bp+2). This
means `movax_bp` reading bp+2 inside an open `fn_frame` needs its OWN
DEF-FN-specific interpretation (distinct from a LOCAL read), and there is
no way to know in advance how MANY of the other bp-relative handlers
(`movsi_bp`, `movm_ax_bp`, `cmp_bpi8`, `inc_bp`, `dec_bp`, ...) have the
SAME kind of collision between "DEF FN's own reserved cells" and "a
LOCAL variable that happens to reuse a low bp offset" without checking
each one individually against real evidence. Given the project's own
calibration rule (fail-loud over guessing) and that getting this WRONG
would mean a BYTE-EXACT decompiler silently mis-rendering DEF FN bodies
containing LOCAL rather than failing loudly, the partial implementation
was reverted (`git checkout --` back to the previous commit) rather than
left half-correct.

**DEF FN + LOCAL: CLOSED (2026-07-21, later session)**, following exactly
the plan above (oracle probes first, `state.fn_frame` grep first). Four
probes (`probe_a`/`c`/`d`, promoted as `t1_fnlocal`/`t1_fnlocalint`, plus
a since-abandoned zero-param `probe_b` -- see below) pinned the real
shape:

- The auto-fn_frame-open trigger was gated on `addr < state.main_start`,
  but `main_start` is ONLY ever set from a single leading skip-jmp over
  the WHOLE def region (or a chain continuing it, `addr ==
  state.main_start`). resume.exe's own DEF FN is reached via a
  PER-DEFINITION trailing skip-jmp right after the PRECEDING SUB's own
  `proc_ret` (mod `trap_hook` stamps) -- `state.k == 0` is never a `jmp`
  in this file at all (its first op is a `trap_hook` stamp), so
  `main_start` stayed `None` forever and the DEF FN was silently never
  opened. Generalized: a `jmp` immediately following (mod `trap_hook`)
  either nothing (start of file) or a `proc_ret`/`fn_ret` ALSO
  sets/extends `main_start`, regardless of `state.k` position.
- `local_init`'s zero-fill and `loc_local` were hard-gated to
  `state.proc_frame`; both now also accept an open `state.fn_frame`
  (new `"locals"` key, populated identically to a SUB's).
- The bp+2 collision that sank the earlier attempt was a symptom of a
  BIGGER gap: `loc_local`'s int-register-path handlers (`movax_bp`,
  `imul_bp`, `movm_ax_bp`, `fild_bp`, ...) had ZERO fn_frame-param
  awareness at all -- every previously-working DEF FN fixture happened
  to touch its params exclusively through the FP path (`fld_bp`/
  `fold_bp`, handled by `fp_bp`), so the int path was simply never
  exercised for a DEF FN before. `loc_local` now falls back to treating
  an unrecognized bp-off as an integer-typed param when inside an open
  `fn_frame` (mirroring `fp_bp`'s existing float-typed-param handling),
  tracking it in a NEW `fn_frame["int_offs"]` set.
- The param list itself can't be derived from `max_off // 4` once
  integer params exist: an all-FP or all-string param list packs 4
  bytes/param (P04, P08, ...), but an all-integer one packs 2 (P04,
  P06, ...) -- NO fixed stride works for both. Replaced `max_off` with
  `fn_frame["param_offs"]`, a SET of every bp offset actually touched as
  a param; `fn_ret` now emits `sorted(param_offs)` directly as the
  param list (self-describing, no stride assumption).
- `loc_local`'s param fallback must return a name with the SAME suffix
  `fn_ret`'s own `params` tuple will use (`P04%` for int, not `P04`) --
  otherwise the declared param and its body references are two
  DIFFERENT strings and `rename.py` treats them as two different
  variables (caught by round-tripping a probe: the emitted body
  referenced a variable that was never declared).
- Caller-side: literal int args stage into `state.fn_args` via
  `mov_bp_imm` (nonzero immediate only -- a zero literal is
  byte-identical to the pre-existing "zero-init a staged string-arg
  descriptor pointer" glue and stays unsupported, unwitnessed, until a
  fixture disambiguates the two); COMPUTED int args stage the same way
  via `movm_ax_bp` when neither `proc_frame` nor `fn_frame` is open.
  The caller-side integer RESULT reload is `movax_bp 0` popping the
  `ir.FnCall` node straight off `state.stack` (the float path's
  `fld_bp` reload at the same spot is a true no-op, since the FPU
  already holds the value; the ax-register convention has no such
  free ride, so this one is NOT a no-op).
- Along the way, exposed and fixed a real, general (not DEF-FN-specific)
  bug: `state.sp_save_cell` (which `mov_mem_sp`/its paired
  `movm_imm <cell>,0` glue-match use to recognize semantic-free
  call-staging bookkeeping) was a single scalar with no save/restore. A
  call used as its OWN outer call's argument opens a NESTED
  `push_bp`/`mov_mem_sp`/.../`pop_bp` staging region, silently
  clobbering the outer call's cell number with no restore on return --
  corrupting the OUTER call's own `movm_imm`-glue match once control
  came back (`store to unknown system cell` at the outer's cell, only
  reachable once DEF FN calls could nest as arguments at all). Fixed
  with a `state.sp_save_stack`, pushed on `push_bp` and popped on
  `pop_bp`.
- `probe_b` (a ZERO-param integer FN) surfaced a separate, unrelated,
  NOT-yet-fixed emit0 gap: a zero-arg `ir.FnCall` always emits `NAME()`,
  but TB's own niladic-FN call syntax has no parens at all (`PRINT
  FNY%`, not `PRINT FNY%()`) -- the oracle rejected the round-trip with
  "Error 475: Parameter mismatch". Left unfixed (out of scope for the
  LOCAL work; no wild file hit it this session) -- probe_b itself was
  NOT promoted to the corpus.

All landed in `f199f1b`. Full byte-exact round trip (both dialects) for
`t1_fnlocal`/`t1_fnlocalint`; zero regressions (2378 passed, up from
2368, wild tally holds at 23/84 -- this closure alone didn't flip a
wild file to decode-ok, see the NEW gap immediately below it hit).

**resume.exe: STILL not fully closed -- a NEW, unrelated gap right past
DEF FN + LOCAL.** After the fix above, resume.exe's decode advances
completely through the DEF FN and a nested nested-call `far_call`
target that briefly regressed with `store to unknown system cell 0x66`
(a `movm_imm` call-arg-count-zero glue op whose paired `mov_mem_sp`
cell no longer matched once a call nested as its own outer call's
argument -- this WAS the `sp_save_cell` bug fixed above, and is fully
resolved: the scan now runs cleanly all the way to the end of the file,
`_finalize` completes). The scan itself is 100% clean; the ONLY
remaining blocker is `_resolve_calls` raising `KeyError: 86343` on an
unresolved forward `CallStmt` placeholder once every SUB/FN in the file
has been named and it tries to fill in the one remaining `("addr",
86343)` target.

**The `KeyError: 86343` mystery, UNSOLVED, extensively probed
(2026-07-21):** a `far_call` at file offset `0xB6CC` (46796) -- the
FIRST executable op after ALL of resume.exe's definitions, i.e. this
file's very first real statement, right before an `ON ERROR GOTO` --
targets file offset 86343. Verified byte-for-byte this is a genuine
`9A <off:u16> <seg:u16>` far-call encoding (`9a c7 b6 00 00`), and its
target math (`off=0xB6C7=46791` + `start=0x9A80=39552`, `start` being
this exact file's `find_prologue`-returned user-code base) is the
SAME, already-proven-correct formula every OTHER far_call in this file
uses successfully. So the target, 86343, is definitely, unambiguously
correct -- and it lands exactly on an ordinary `CLS` statement
(`INT EC` dispatch) in the middle of the program's main flow, with NO
`proc_enter` (in EITHER the fused `55 8B EC` or alternate `55 89 E5`
encoding -- checked the raw bytes directly) anywhere near it. Ruled out
by building throwaway oracle probes and comparing op shapes: plain
`ON ERROR GOTO` (no preceding far_call at all, target embedded directly
in the `on_error` op's own immediate operand), `GOSUB`/`ON...GOSUB`
(both compile to NEAR `call`/dedicated `on_gosub`, never `far_call`),
`RESUME <line>` (compiles to `resume_pre` + a plain `jmps`, no call at
all), and a plain no-param `CALL SUBNAME` where the callee's first
statement is also `CLS` (compiles completely normally, with a real
`proc_enter` immediately at the target -- ruling out "TB skips the
prologue for param-less SUBs"). None of these reproduce a `far_call`
landing on bare mid-flow statement code.

**Follow-up (same day, continued session): this is a FAMILY, not a
one-off, and there's a strong new structural clue.** A full survey of
every `far_call` in the file (144 total) turns up not one but FOURTEEN
calls, targeting SIX distinct addresses that never resolve to a named
proc: `86343`, `56020`, `56378`, `87474`, `87925`, and `55776` -- the
last one alone is the target of NINE separate calls, scattered from
file offset 50209 all the way to 84774. Every one of these callers
shares an identical shape: the
already-understood `andaxbx` materialized-AND-chain idiom (`movax
FFFF/jcc/incax/andaxbx/jcc/jmp <loop-top>`), i.e. structurally `IF
condA AND condB THEN CALL <mystery>` -- but reproducing that EXACT
statement shape (`IF...AND...THEN CALL SUBNAME`) via an oracle probe
still gets a completely normal `proc_enter`. Also tried and still
normal: `IF...AND...THEN GOSUB` and `SELECT CASE ... CALL` (menu-letter
dispatch is clearly what this file is doing, given its embedded UI
strings -- this is "Resume Shop", a menu-driven 1988 shareware
resume-builder, not related to the BASIC `RESUME` statement at all).

The new clue: at FOUR of these six distinct target addresses (56020,
55776, 87474, 87925 -- checked directly), the op stream shows a bare
`retf` (0xCB with no matching `5D` pop-bp, i.e. NOT the fused
`proc_ret` pattern) sitting in ORDINARY MAIN-CODE FLOW immediately
before the mystery target -- e.g. `far_call 43166 (a normal, already-
resolved proc) / retf / <mystery target begins>`. A bare `retf` with no
corresponding `proc_enter`-style frame anywhere upstream is otherwise
inexplicable main-code content (RETF pops a return address+segment off
the stack; if nothing pushed one, execution would jump to garbage) --
this is real evidence that these mystery regions are THEMSELVES
returning targets of some OTHER, so-far-unidentified calling mechanism,
laid out back-to-back with no distinguishing start marker of their own
(each one's only boundary evidence is "the previous one's retf just
happened"). This is consistent with a class of procedure the compiler
can frame WITHOUT the standard `push bp; mov bp,sp` prologue because it
touches no LOCAL/parameter (bp-relative) storage at all -- but why
`SUB...END SUB` bodies never get this treatment even when equally
frame-free (every reproduction attempt, param-less or not, keeps
getting a full `proc_enter`) is still the open question. **Whatever
source construct produces this remains unidentified.** Worth trying
next: `CALL ABSOLUTE` (unlikely -- pops a computed address off
`state.stack`, not an embedded immediate, so probably wouldn't scan as
`far_call` at all, but worth confirming with a real probe rather than
reasoning alone), `ON KEY/TIMER/COM/PEN/STRIG GOSUB` (event-trap
installation, unwitnessed all session -- see the separate "Gap INT-8c"
section below for a related, also-undiagnosed event-trap mystery this
might connect to), and tracing EACH of the other 10 mystery targets'
immediate predecessors the same way (only 4 of 5 distinct addresses
were checked) in case one has cleaner surrounding context than 55776's
(whose own backward trace, followed ~100 ops, is a long, undifferentiated
stretch of "print text at row N" calls with no proc_enter or other
landmark in reach -- tracing further back was not exhausted). A
`cfgview`/iced-x86 disassembly of the raw bytes around the call site and
target confirms the instruction decode (nothing hidden or misaligned,
manually re-verified byte-by-byte against the op stream) but adds no
semantic information beyond what the op-stream trace already showed.

**`$SEGMENT` is real, oracle-verified, and produces a matching FAILURE
MODE -- but is NOT resume.exe's mechanism (ruled out by direct check).**
Prompted by a user hint, tried the TB metacommand `$SEGMENT` directly:
it compiles cleanly (confirmed distinct output vs. a no-`$SEGMENT`
baseline) and, when placed between two `SUB` definitions, produces
EXACTLY resume.exe's failure shape: a `far_call` whose target
`_resolve_calls` can't find in `proc_names`, raising the same kind of
`KeyError`. Reverse-engineered via two probes (`probe_segmid.bas`,
`probe_seg2.bas`/`probe_seg3.bas`, not promoted to the corpus -- kept
in the session scratchpad): `$SEGMENT` emits a far JMP (`0xEA off:u16
seg:u16`) as a boundary marker, ALWAYS with `off=0` and a NON-ZERO
`seg` (3 for the first `$SEGMENT`, 4 for a second, ...) -- exactly the
"relocated code segments" case scan.py's OWN existing `jmpf` handling
already has a comment about (`# Segment-zero calls use the user-code
origin; relocated code segments use the preceding byte as their
logical origin`), but `far_call`'s handling right above it in the same
file NEVER reads the segment field at all, always computing `off +
start` regardless. Calls into a `$SEGMENT` region carry that SAME
non-zero `seg`, and their `off` resolves against a per-segment base
that is NOT `start` -- empirically, the address of a short skip-jmp
instruction that follows the EA marker after a zero-byte gap of
VARYING size (5 bytes in one probe, 10 in another, 0 for a
non-first/last segment in a third -- no clean formula pinned down yet;
might correlate with the segment's own body size, might be something
else). **Directly ruled out for resume.exe**: every one of its 14
mystery `far_call`s carries `seg=0` (checked all, not just the first),
and there is no non-zero-seg EA marker anywhere in its scanned op
stream (`state.ops` has exactly one `epilogue`, at true EOF, and zero
`jmpf`) -- resume.exe genuinely doesn't use `$SEGMENT`. A corpus-wide
scan for the `EA 00 00 <small nonzero> 00` signature (filtering out
huge/random `seg` values, almost certainly false-positive data bytes)
found exactly ONE candidate, `wild/hits/sabpcv3.exe` (`seg=6` at file
offset 41971) -- but that file currently fails EARLIER and separately
(`displacement 0xc16 is neither scalar nor array element`, an
unrelated layout gap), so implementing `$SEGMENT` support wouldn't
unlock it without also closing that gap first. Given the formula isn't
fully pinned (the gap-size inconsistency) and there's no fixture it
would actually close yet, this was NOT implemented -- documented here
so the reverse-engineering isn't lost. Next steps if picked up: probe
with 3+ `$SEGMENT`s and varying body sizes per segment to solve the
gap-size formula properly, then either fix sabpcv3.exe's earlier
layout gap first, or wait for a wild file where `$SEGMENT` is the
sole remaining blocker.

Previously, updated 2026-07-21 (earlier session): 23 of 84 wild EXEs decode-ok, up from 22.
`90250ca` closes tamstart.exe fully via three gaps found while chasing
the same generic "materialization template mismatch"/KeyError signature
across four files (tamstart/grdscn/kinder/process):
- Computed (variable) FOR init (`FOR I% = N% TO 23`, via `movm_ax`
  instead of `movm_imm`): the header recognizer required a `Lit` init,
  rejecting this outright though nothing downstream needed it to be
  one. Fixture `t1_forvarinit`.
- CALL to a SUB defined LATER in the file (address-ascending scan
  order): `proc_names` has no entry yet at that point (only populated
  once the callee's own `proc_ret` is processed). Staged as a pending
  placeholder, resolved once every SUB is decoded. Fixture `t1_fwdcall`.
  **This one regressed inv87.exe/invoice.exe on first landing** (a
  previously-full-decode-ok file broke with "jump target ... is not a
  statement start") because the resolver rebuilt every SubDef/IfBlock/
  SelectCase container unconditionally while walking for pending calls,
  changing `id()` even when nothing inside needed fixing --
  `_resolve_targets` keys `stmt_addr` off `id(stmt)` for body jump
  targets, so this silently orphaned targets inside untouched SUB
  bodies. Caught only by re-running the FULL WILD SCAN before declaring
  done, not by the corpus test suite (2318 tests, all green throughout
  -- neither new fixture happens to exercise a jump landing inside an
  unrelated body). Fixed by making the walk identity-preserving.
  **Lesson: after any fix touching statement-tree structure, re-scan
  the whole wild corpus, not just the new fixture and `pytest`.**
- A second relational term materializing directly into AX with no
  orax/jcc/jmp dispatch tail, combined via andaxbx/oraxbx as a plain
  assignable value (`V = (term1) AND (term2)`, never branched on) --
  generalizes an existing narrower branch for the same shape gated on
  short-circuit code flow specifically.

grdscn.exe/kinder.exe's OWN occurrences of "materialization template
mismatch" are a DIFFERENT root cause (grdscn.exe's is the previously-
documented 3-term short-circuit/combinator chain) and remain open.
process.exe advanced through the CallStmt/AND-value fixes into the
already-documented, extensively-investigated `di`-register memory-spill
gap ("Gap byte 89", below) -- do not re-open that investigation without
reading its existing notes first.

Also this round: `movm_imm`'s system-cell gate (`op[2] < VAR_BASE`)
deferred to the solved layout before raising -- VAR_BASE is only the
typical scalar floor, not a hard one; a program using fewer of the low
reserved cells can legitimately have real scalars below it (confirmed
by direct trace against wild tamstart.exe, not an oracle fixture --
no probe reproduced a sub-VAR_BASE scalar after trying varied
combinations). Advanced tamstart.exe further without alone closing it.

Previously, updated 2026-07-21 (earlier): 22 of 84 wild EXEs decode-ok, up
from 20. Two closures that round, together fully closing bill.exe and
color.exe (both previously stalled at 99%/93% through their files):
- `06a729a` literal `STEP -1` FOR-NEXT: TB special-cases both +1 and -1
  to a bare INC/DEC at the NEXT instead of the generic `addm_i8` path
  any other literal step uses. `dec_m`'s FOR-frame branch previously
  fail-loud raised on this, assuming it unwitnessed. Fixture
  `t1_forstepm1`, byte-exact both dialects.
- `06a729a` (same commit) the COLOR fg/bg + VIEW-border cell family
  (0x88/0x94/0xA0/0xAC/0xB8/0xC4) has a runtime-revision-skewed
  +2-shifted sibling (0x8A/0x96/0xA2/0xAE/0xBA/0xC6) in whichever
  compiler build produced bill.exe/color.exe -- resolves the
  `RR-SYSCELL-8A` candidate a prior session had opened but left
  unresolved. See `gap_reports/runtime-revision-assessments.json` for
  the full writeup.

Before that, two more gaps closed (both byte-exact both dialects), each
advancing a file further without yet finishing it:
- `bab24ce` bare `imul word [si]` (no ES prefix): the DS-relative sibling
  of the already-handled `far_imulax_si` (byref-param multiply), for a
  multiplicative fold of a computed static int-array element
  (`ARRAY1%(k) * ARRAY2%(i,j)`). Fixture `t1_imulsi`. Advanced grdscn.exe
  past its `unhandled byte f7` into a NEW, unrelated gap (see below).
- `b6c5ecc` computed (variable) `FOR...STEP` over a **LOCAL** variable:
  the bp-relative mirror of the already-working DGROUP case (`orax_self`
  sign test), using `movax_bp`/`movm_ax_bp`/`mov_bp_imm`/`cmp_bpi8`
  throughout. The header also reserves a `[limit-temp, step-temp]` word
  pair as the LAST two words of the LOCAL span (not v-relative like the
  literal-step case), and the step-temp is read again at NEXT so its
  removal from the LOCAL name table has to wait until the SUB body is
  fully decoded. Fixture `t1_localvarstep`. Does NOT close ziptest.exe
  (see the new FP-LOCAL gap below) despite matching its `TEST
  word[bp+d8],8000h` signature at the byte level -- ziptest.exe's actual
  loop variable turned out to be FP-typed, a different, bigger gap.

Two new gaps surfaced and were investigated but NOT closed this session
(see their own sections below for the full writeup): **FP-typed LOCAL
variables are unsupported in SUB bodies at all** (ziptest.exe), and
grdscn.exe's next blocker is a 3-term string-comparison chain mixing
short-circuit branching with a combinator fold, a new control-flow
template distinct from both `t1_and3` and `t1_mixedbool`.

Previously, updated 2026-07-20 (session, commits 4f29e9b..f2ae494): 20 of 84
wild EXEs decode OK, up from 16 at this session's start (ck, onelab87,
onelabel, mm, autonum, rev, startup, schart, r, book, inv87, invoice,
metric, strpfind, pz, rstprint, mymenu, be, invent, and one more --
re-run `scan_wild.py` for the exact current list, this session added
rstprint/mymenu/be/invent). Nine gaps closed this session, each verified
byte-exact both dialects via the oracle (see "Recently closed" for the
full list): the IDX% bridge's nop;nop fwait alias, computed
(variable) FOR-STEP, an INTO interposed in a shl-si element-address
chain, cmpax_m's pooled-literal left operand, a computed array
element's relational-value materialization, a mislabeled LOC(n) vector
(was "INP") plus its implicit fstp bridge, a bare file-channel
`PRINT #n,`, a leading zone-advance comma on a file-channel PRINT, RESUME
to the program's own first statement, and READ/INPUT into a computed
string-array element. `gap_reports/runtime-revision-assessments.json`
also got a pass: one stale "unresolved" entry corrected to "closed",
one new "closed" entry added for the nop-fwait fix, and one new
"unresolved" entry (`RR-DGROUP-BIGARR`) opened for a fresh finding (see
below). Every closure advanced files further into previously-unreachable
territory without fully finishing a NEW file every time, which is
expected once the easy/common gaps are gone and each file needs several
more fixes to reach the end. vhfprop.exe remains the only file blocked
purely by the line-table epic (see "vhfprop status" below, unchanged
this session).

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

### Gap: FP-typed LOCAL variables are unsupported in SUB bodies at all (ziptest.exe), INVESTIGATED, NOT LANDED (2026-07-21)

ziptest.exe fails with `unhandled byte f7 at 0xa5c6`, byte pattern `f7 46
0e 00 80` = `TEST word [bp+0Eh], 8000h`. At first glance this looks like
the LOCAL-frame analog of the already-supported DGROUP computed-STEP
integer FOR-NEXT's `orax_self` sign test (which this session DID add —
see `b6c5ecc` above) — same "sign-test on a variable step" shape. A
probe built to test that hypothesis (`q_localvarstep.bas`, an INTEGER
LOCAL var-step FOR) reproduced a *different* missing op entirely
(`unhandled op orax_self`, since integer LOCAL FORs go through AX/
`orax_self`, not a raw memory TEST) — that gap got fixed and promoted as
`t1_localvarstep`, but **it did not close ziptest.exe**: the wild file's
`scan_wild.py` re-run still fails at the exact same byte.

Building a second, more targeted probe (`q_localfpvarstep.bas`: `SUB
SUB1(N%): LOCAL I!, S!, ST!: ... FOR I! = 1 TO 10 STEP ST! ... NEXT I!`)
reproduced the exact byte pattern. Full op-stream trace (via
`decode0._scan`'s partial `ops` list, extracted from the exception
traceback since `--ops` fails wholesale on a scan-level gap):

```
fldz; fstp_bp 14              ; S! = 0
arg_ref 6; far_fild_si; fstp_bp 18   ; ST! = N% (byref, FILD-converted)
fild 294; fstp_bp 26          ; limit-temp = FLOAT(pooled 10)
fld_bp 18; fstp_bp 22         ; step-temp = ST! (copy)
fld1; fstp_bp 10              ; I! = 1.0 (init)
jmp test
BODY: fld_bp 10; fold_bp + 14; fstp_bp 14   ; S! = S! + I!
      fld_bp 22; fold_bp + 10; fstp_bp 10   ; I! = I! + step-temp
test: fwait
      TEST word [bp+18h], 8000h    <-- the missing op (step-temp's disp
                                        is 22 decimal = 0x16; +2 = 0x18,
                                        i.e. its HIGH WORD = IEEE sign bit)
      je +3; jmp NEG
      FLD [bp+1Ah] (limit-temp); FCOMP [bp+0Ah] (I!); fstsw; jae BODY
      jmp EXIT
NEG:  FLD [bp+1Ah]; FCOMP [bp+0Ah]; fstsw; jbe BODY
```

This is **structurally identical** to the already-working DGROUP FP
var-STEP FOR-NEXT (`lift.py`'s `_lift_next`/`_loose_for_header`, which
uses `testw`/`fld`/`fcomp`/`fstsw` — note this is a SEPARATE, older
template from the integer `orax_self` one; DGROUP already has both).
The fix for the scan+lift half is a small, direct mirror of work already
done twice this session:
- scan.py needs one new op, `TEST word [bp+disp8], imm16` (mirroring the
  existing DGROUP `testw` at scan.py:92) — call it `testw_bp`.
- `_loose_for_header`/`_lift_next` need to accept `testw_bp`/`fld_bp`/
  `fcomp_bp` as the bp-relative siblings of `testw`/`fld`/`fcomp`
  (`fcomp_bp` and `fld_bp` already exist and are used elsewhere; only
  `testw_bp` is new). `fstsw` takes no memory operand so needs no mirror.
- The increment-statement check in `_lift_next` currently reconstructs
  the loop var's name via `_slot(v)` (DGROUP `V####` scheme) — same
  V-vs-L naming-scheme problem this session's `_lift_var_step_next` fix
  already hit and solved by reading the name off the already-lifted
  `ir.For` statement instead of reconstructing it; the same fix applies
  here.

**What actually blocks this, and why it wasn't landed**: `fp_bp` in
`handlers/arith.py` (the handler for `fld_bp`/`fstp_bp`/`fold_bp`/
`fold_n_bp`/`fcomp_bp`) only implements two cases — `state.fn_frame is
not None` (a DEF FN body's params/result/folds) and an `else` branch
that's ONLY valid for FN-call argument staging in the main frame. There
is **no case at all for `state.proc_frame is not None`** (a LOCAL
variable inside a SUB) — hitting any of these ops with an open SUB frame
raises `unexpected {kind} in main body`. This matches `loc_local`'s own
docstring ("every slot in the zero-filled range is a 2-byte int for
now (no fixture has witnessed a mixed-type LOCAL declaration yet)") —
FP-typed LOCALs are a genuinely unimplemented feature, not just a
missing byte pattern. Closing ziptest.exe for real needs:
1. `loc_local`/the `local_init` name table to carry the right type
   suffix (`!`/`#`) instead of hardcoding `%`, presumably by inferring
   type from which op family (fld_bp vs the int ops) first touches each
   slot — no fixture has witnessed how TB actually distinguishes
   int/single/double LOCAL slot *sizes* in the zero-fill span itself
   (a SINGLE needs 4 bytes, a DOUBLE 8 — does `local_init`'s `cnt`
   still count in fixed 2-byte words with FP locals spanning multiple
   entries, per this trace's `fstp_bp 18` -> next real local at `26`,
   an 8-word gap for 2 FP locals? needs a dedicated fixture to pin).
2. A LOCAL-frame branch in `fp_bp` covering read/write/fold/compare,
   the SUB-body mirror of the `fn_frame` branch already there.
3. Then the FOR-header/NEXT mirror described above.

This is a full new subsystem (FP-typed LOCAL variable support), not a
quick patch — same category as the earlier-documented SUB-LOCAL
dynamically-sized array gap. Left undiagnosed further; the probes
(`q_localfpvarstep.bas`) are reproducible and byte-matching, so the next
session can pick this up directly without re-deriving the shape.

### Gap: grdscn.exe's 3-term mixed short-circuit/combinator string-compare chain, NEW (2026-07-21)

Surfaced by this session's `imul_si` fix (`bab24ce`), which advanced
grdscn.exe past its old blocker into new territory: `materialization
template mismatch at 0xa8f9` (raised by `lift.py`'s `_lift_while`, whose
template is `["movax","jcc","incax","orax","jcc","jmp"]` but the actual
op at that point continues with `movsi` instead of `orax`).

Op-stream trace (`tbx --ops`, addresses `0A8DC`-`0A91D`) shows THREE
string-compare terms (`strcmp`) chained together, but NOT via the
already-supported accumulator-fold shape (`t1_and3`'s same-combinator
chain, or `t1_mixedbool`'s combinator-switch-mid-chain, both closed
earlier this session/campaign): here each term materializes
**independently** (`movax 0xFFFF; jcc; incax; orax; jcc; jmp` — the
same 6-op shape `_lift_while` expects for a WHOLE compound, not a term),
and the jcc's TRUE branch jumps directly into the NEXT term's code
(control-flow short-circuit, no register accumulator) for the first two
terms; only the THIRD term's fold actually uses register combinators
(`movbxax`/`movrr:cx:bx`/`oraxbx`/`movrr:bx:cx`/`andaxbx`) to combine
the three terms' results together. This looks like it could be a
parenthesized/mixed-precedence expression (e.g. `A$="x" AND B$="y" OR
(C$="z" AND D$="w")`) or possibly a compiled `SELECT CASE` over string
equality — not yet disambiguated. This is a new, more complex
control-flow template than anything in `_lift_bool_tail`'s existing
family and needs its own dedicated investigation (probably a fresh
probe sweeping compound-string-IF shapes with explicit parens); not
attempted further this session given the scope. `state.exe`/
`state87.exe`'s own next blocker (the intra-inline-IF-body GOTO gap,
already documented above) remains separately unresolved too.

### THE LINE-TABLE EPIC (read this first)

Real wild programs have **multi-statement lines**, original line numbers
that are BYTE-SIGNIFICANT (error-trap line table present: ON ERROR/
RESUME/ERR), **codeless statements** (DATA, static-array DIM — REM and a
bare `::` are NOT codeless, confirmed NOT to produce a table entry), and
**numbered block-IF interior lines** jumped into from anywhere (gap 51
closed the single-level case; inv87's remaining stop needs the nested
case, still open).

#### CLOSED this session: DATA and static-DIM orphan recovery

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

#### vhfprop status: bare-DO un-synthesis CLOSED for unconditional loops; the WHILE/UNTIL case is a genuinely new, still-open puzzle

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

#### CLOSED: inv87.exe/invoice.exe's nested block-IF GOTO target

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

#### Reproducing the investigation

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

### Ongoing plan (priority order — pick up at the first incomplete step)

**Refreshed again 2026-07-20, end of the later session** (65 TB-but-fail /
20 decode-ok; the immediately-preceding version of this list was already
stale after that session's 9 closures). Cross-check
`gap_reports/runtime-revision-assessments.json` before investigating any
of these from scratch — several have an existing candidate/unresolved
writeup there with negative evidence already collected.

1. **vhfprop's tail-test DO...LOOP WHILE/UNTIL un-synthesis gap** (see
   "vhfprop status" above) — the ONLY file left blocked by the line-table
   epic; still open, unchanged.
2. **Intra-inline-IF-body GOTO targets (2 files: state.exe, state87.exe)**
   — a full spec for tackling this (confirmed via fresh `id()`-tracing in
   a 2026-07-22 follow-up session, plus the exact adjacent `_fold_if`/
   `_body_has_target` machinery and a phased investigation plan) is at
   `Part II` — start there. `secure.exe` also
   hits the same error message at a different target, not yet confirmed
   to be the same shape. `resume.exe` separately hits this SAME error
   message too (after this session's `far_call`/GOSUB fix advanced it),
   but at a target that traces to something ELSE entirely (compiler glue,
   not an intra-inline-body jump) — do not conflate the two, see the spec
   doc's "Explicitly out of scope" section.
   — CLOSED the mixed-AND/OR-combinator gap that used to sit here (commit
   4c0bde6, `t1_mixedbool`); both files now advance to a DIFFERENT, bigger
   gap still under the same "jump target ... is not a statement start"
   message. Traced (recursive search through IfInline/IfBlock bodies, not
   just top-level `state.stmts`) to: a giant `IfInline` (~40 statements,
   a flattened GOTO-based keyboard-input state machine -- no block
   IF/END IF in the source, just one unbroken chain of `IF cond THEN
   <lineY>` statements) whose body contains a `Goto`/`IfGoto` targeting
   ANOTHER statement inside that SAME body. `_resolve_targets`'s `index`
   (built in lift.py) only maps TOP-LEVEL `state.addrs` entries; nested
   body statements have no address entry at all unless the existing
   BodyLine mechanism (gap 51, built for block-IF interiors jumped into
   from OUTSIDE the block) applies -- but this is a jump WITHIN the same
   already-flattened inline body, a different case that mechanism
   doesn't cover. This is a real, substantial feature gap (making every
   nested body statement's address resolvable inside inline-IF bodies
   too, not just block-IF ones), comparable in scope to the byte-8b
   LOCAL-array gap below -- scope a fresh session around it rather than
   patching in a hurry. Next step: confirm the shape with a minimal
   oracle probe (several chained `IF...THEN <lineY>` statements with a
   later one jumping back into an earlier one's line, all inside what
   the source spells as ONE physical line via `:`) before touching
   `_resolve_targets`/`_fold_if`.
3. **`DGROUP layout not solvable` (4 files: menu, night, sprogh, swbb)** —
   see `RR-DGROUP-BIGARR` in the runtime-revision JSON for the full
   writeup: zero stamp candidates anywhere in any of the 4 files, and the
   descending-n walk never solves either; menu.exe's failing movsi disp
   (0x400) sits at the end of a long, cleanly 4-byte-spaced run (0x310..
   0x400, ~60 entries) suggesting a static string array too large (or a
   static-array COUNT too high, possibly past the stamp's `n<=31` cap) for
   the current record/stamp assumptions. NOT yet confirmed runtime-revision
   — could be a plain unimplemented shape. Next step: hand-derive `ds` for
   menu.exe (smallest of the four) via the brute-force ARR_BLOCK-scan
   technique from the original gap-16 investigation. mf.exe fails
   similarly but through the OTHER (runtime-grid-anchored) path with a
   distinct message — check separately, don't assume same cause.
4. **`byte 8b` / SUB-LOCAL dynamically-sized arrays (4 files: cleanup,
   crossref, filepatc, reformat)** — confirmed via oracle probe
   (`q_localarr.bas`) to be `LOCAL A()` + runtime `DIM A(n)` inside a SUB.
   The address-of-local primitive itself (`mov si,bp; add si,imm8; push
   ss; pop es`) is simple, but the follow-on element access resolves
   through the x87 ESC 0x34-0x3B range (already-handled FP ops, NOT new
   vectors — re-verify before assuming otherwise) and loads a SEGMENT out
   of the array's own descriptor, meaning these are genuinely
   HEAP-allocated at runtime (unlike every other runtime-DIM array so far,
   which lives in a fixed-size compile-time DGROUP block). This is a real
   new subsystem (heap alloc representation + element addressing through a
   runtime segment), not a small patch — scope a fresh session around it,
   starting with more oracle probes isolating what follows dim_begin for
   a plain integer/single LOCAL array before attempting any code.
5. **`INT EC sub 38` (4 files: catalog, football, refund, varamort)** —
   the runtime-array-block-reference family's 4th member (alongside
   dim_begin/dim_end/erase), block-only, no operand. Six candidate probes
   already ruled out (string/2-D ERASE, multi-array ERASE, SUB-local array
   ERASE, array-level SWAP, `SUB SUB1(B())` by-ref array param — TB
   rejects that syntax, REDIM — not a TB keyword). Untried: CLEAR
   variants, COMMON-shared dynamic array cleanup, ON-ERROR implicit
   ERASE, GET/PUT #n with an array-backed record buffer.
6. **`INT 8c` (4 files: baby, help, prtguide, readme)** — see
   `RR-INT-8C`; all TB 1.0, ON KEY(n) GOSUB is the only shared source
   feature, several trap-count/toggle hypotheses ruled out. Untried: a
   follow-on statement INSIDE the trap handler body.
7. **`INT EC sub ee` (3 files: cal, cal87, kinetics)** — see
   `RR-LINEINPUT`/HANDOFF's "EC sub EE remains unresolved" entry: a wide
   oracle probe matrix (PRINT/LPRINT/SHELL/RUN/CHAIN/NAME/OPEN/DATE$, plus
   the optional CHAIN/RUN forms) produced no `cd ec ee` at all — negative
   evidence only, no lead yet.
8. **`INT EC sub ac` (3 files: nvginst, pwinst, secure)** — see
   `RR-DISPATCH-HOLES`; untouched, no candidate hypothesis recorded yet.
9. **"displacement ... neither scalar nor array element" (2 files:
   hfprop, sabpcv3)** — mymenu.exe's own hit in this bucket closed this
   session (cmpax_m pooled-literal fix); the remaining 2 are untouched,
   likely still 2 distinct causes bucketed by error message shape (the
   gap-30/31 precedent) — triage each independently.
10. **The 2-tier and singles** — re-tally after each closure
    (`uv run python tbx/tools/scan_wild.py wild/hits`); for FP gaps check
    the `[si]` FP table for missing rows first. Byte 90 (see `RR-NOP-90`)
    and byte ea (see `RR-BYTE-EA`) are both fully CLOSED — don't reopen
    them if they resurface in a tally, they're a scanner-level decode now.

### Recently closed (this campaign, newest first)

- **Session summary, 8 more closures after the FOR-STEP/nop-fwait entry
  below** (2026-07-20, commits 8336d0f..f2ae494, wild 16->20 decode-ok):
  each is its own commit with the full byte-trace/probe writeup; this is
  just an index.
  - `8336d0f` INTO interposed in a computed-array-element shl-si chain
    (dialect-dependent position; fixture fov_t1_shlovf). Closed
    rstprint.exe fully.
  - `1f6c110` cmpax_m's pooled int-literal LEFT operand (`IF 180 =
    LEN(A$) THEN`), the same fallback imul_m already had (gap 43).
    Fixture t1_cmppool. Closed mymenu.exe fully.
  - `83c8f76` A computed array element's relational-value materialization
    (`B% = (A%(I%) = 5)`), hooked into the same pend_cmp/movax-0xFFFF
    path the scalar case already uses. Fixture t1_cmpsival. Advanced
    pfl.exe/number.exe (not fully closed).
  - `d8feff6` `_AXARG_SUBS[0x24]` was mislabeled "INP" -- it's actually
    LOC(n) (INP(n) always compiles inline, never reaches this vector);
    plus fstp's implicit ax->FP bridge for LOC(n)'s result. Fixture
    t1_loc2. Fixed a real crash (bare IndexError) in be.exe/styllist.exe.
  - `4cd81da` Bare file-channel `PRINT #n,` (blank-line flush with no
    staged items). Fixture t1_fprintblank. Closed be.exe fully.
  - `8ba4df1` Leading zone-advance comma on a file-channel PRINT (`PRINT
    #1, , A`), mirroring the existing console-PRINT auto-create. Fixture
    t1_fpcomma. Advanced styllist.exe.
  - `ae49657` RESUME to the program's own first statement: TB 1.0's
    E9-near jump canonicalization tags it "run" (same bytes as a bare
    RUN), colliding with resume_pre's tail check. Fixture t1_resumestart.
    Advanced styllist.exe (still open, a RESTORE line-item KeyError next).
  - `f2ae494` READ/INPUT into a computed STRING-array element: two gaps
    (data_read_str's _READDATA sentinel wasn't checked in the shlsi
    element-access handler's strassign branch; read_str never recognized
    an index computation starting instead of a plain scalar target).
    Fixtures t1_readsarr/t1_inpsarr. Closed invent.exe fully.
  - Still open, untouched further this session: styled.exe/styllist.exe's
    shared "87" (a RESTORE/DATA item-index KeyError -- traced to
    `item_to_stmt[87]` missing because a RESTORE target's raw item-index
    exceeds `len(items)`, root cause not yet found); pfl.exe's new
    "element access: unexpected op fistp"; number.exe's new "ax,bx
    combine with empty regs".
- **Computed (variable) `FOR...STEP`, and the IDX% bridge's nop;nop fwait
  alias** (2026-07-20, commit 4f29e9b): `FOR I% = a TO b STEP J%` can't
  pick ascending vs. descending continuation at compile time (J% isn't a
  literal), so the compiler copies the step expression into a temp cell at
  the header and emits BOTH `cmp;jcc` continuation blocks (ascending
  JLE/JBE, descending JGE, each either the direct short-jcc form or the
  indirect inverse-jcc-skip+jmp form already used by the literal-step
  case), selecting between them at runtime via `or ax,ax; jns` on the
  just-used step value (new `orax_self` op). The header fold pops the
  step-temp-copy and int-init statements into `ir.For` with a `Lit(0)`
  limit placeholder, patched in place once the dual branches are decoded
  (mirrors `addm_i8`'s existing step patch-up, just for the limit
  instead). Fixtures `t1_forvarstep`/`t1_forvarstep2` (+v10), byte-exact
  both dialects; `t1_forvarstep2` has a long body to force the indirect
  jcc form. Closed wild stat.exe's blocker; menu.exe also advanced past it
  (it separately needs a variable LIMIT too, not yet folded in — see
  `RR-DGROUP-BIGARR` below for what it hit next). Separately: electron.exe/
  rstprint.exe's `IDX% bridge mismatch` turned out to be a nop;nop pair
  standing in for `fwait` at the exact x87-sync point between
  `fistp[0x2C]` and `movaxmem[0x2C]` — a runtime-revision-skewed encoding
  (same category as the byte-90/far-JMP precedents; no oracle probe ever
  reproduces the raw NOP pair there). New `_sync_len` helper in
  `arith.py`'s `fp_math` accepts either 1 op (fwait) or 2 (nop;nop) at
  that position, in both the FP->int assign and element-subscript bridge
  shapes. See `gap_reports/runtime-revision-assessments.json`'s
  `RR-NOP-FWAIT` for the full writeup. Wild scan: still 16 decode-ok, 68
  fail (both fixes advance files deeper without finishing a new one).
- **Leading-semicolon `LINE INPUT;` / EC sub 64 flag C0** (2026-07-20):
  console LINE INPUT uses trailing flag `40` normally and `C0` when the source
  has the leading semicolon, exactly mirroring INPUT's keep-cursor-on-line bit.
  `LineInput` now retains that source-significant flag through render, rename,
  and C generation. Bare and prompted forms are covered together by
  `t1_linec0`/`v10_t1_linec0`; both are oracle byte-exact. `cal.exe` and
  `cal87.exe` advance from `LINE INPUT trailing byte c0` to the later shared
  `INT EC sub ee` gap.

- **EC sub EE remains unresolved after a bounded oracle matrix** (2026-07-20):
  the three wild hits (`cal.exe`, `cal87.exe`, `kinetics.exe`) remain fail-loud.
  The restored vendored oracle produced no `cd ec ee` for ordinary `PRINT`,
  `LPRINT`, `SHELL`, `RUN`, `CHAIN`, `NAME`, `OPEN`, or `DATE$` probes, nor
  for the accepted optional `CHAIN`/`RUN` forms. This is negative evidence,
  not a semantic identification; no scanner mapping was added.
- **Nested parenthesized logical short-circuit spills** (2026-07-20): an
  ungrouped outer AND whose left side is a parenthesized OR emits a direct JNZ
  plus far-jump gate, preserves the left logical value through BX/CX, and then
  combines the right materialized relation/value with `AND AX,BX`. The decoder
  now preserves both the short-circuit gate and the otherwise-reversed source
  operand order. Inline-body, direct-GOTO, two-group, and single-relation-right
  forms are covered by `t1_nestedbool`, `t1_nestedgoto`, and `t1_nestedone`,
  each byte-exact in 1.0 and 1.1. `hfprop.exe` advances to unknown displacement
  `0x2b2`; `styled.exe` advances to a later RESTORE/DATA target error. Other
  nested topologies from the probe matrix remain fail-loud rather than being
  generalized without fixtures.
- **Parenthesized logical-value direct JNZ inline `IF`** (2026-07-20): a fully
  parenthesized logical expression can finish with `OR/AND AX,BX` and feed JNZ
  directly, without the usual `OR AX,AX` or comparison materialization. When
  JNZ skips a following far jump and that jump lands on a scanned op boundary,
  the pair brackets an inline body. The decoder now retains the outer
  source-significant `Group` and opens the normal inline-IF frame instead of
  inventing `logical-expression = 0`. Fixtures `t1_boolflags` and
  `v10_t1_boolflags` verify byte-exact under both installed runtimes. The rule is
  deliberately boundary-gated: `styled.exe` and `hfprop.exe` contain deeper
  nested short-circuit spill topologies whose far targets are internal expression
  addresses, so they remain fail-loud pending their own oracle reproducer.
- **Stale string-comparison orientation before numeric `jcc 7f`**
  (2026-07-20): `photo.exe` and `styllist.exe` both materialize a compound
  string condition, then later evaluate `LEN(s$) > literal` through the signed
  `cmpax_bx` path. The earlier string fold left `pend_cmp_str=True`, causing the
  already-supported signed 7F row to be looked up in the unsigned string table.
  `cmpax_bx` now explicitly replaces the comparison orientation as well as the
  operands. Fixture `t1_cmpstale` reproduces the exact string-condition →
  concatenation → LEN comparison sequence; both dialects are oracle byte-exact.
  `photo.exe` advances to a later `movsi` continuation and `styllist.exe` to a
  later stack-fold error. Full suite: 2202 passed, 14 skipped.
- **Cursor-only/shape-only optional `LOCATE` legs** (2026-07-20): the compiler
  emits `INT D0` with AX for `LOCATE ,,cursor` even when no row/column `INT CF`
  precedes it, and similarly emits `INT CE` with BX/AX for
  `LOCATE ,,,start,stop`. The graphics handler now starts an `ir.Locate` from
  either independent leg as well as attaching them to an existing row/column
  leg. Two adjacent source statements (`LOCATE ,,1` then `LOCATE ,,,6,7`) are
  byte-identical to combined `LOCATE ,,1,6,7`, so the decoder intentionally
  canonicalizes that ambiguous sequence as one statement. Renderer and rename
  preserve leading omitted arguments; C emits cursor visibility without trying
  to move the terminal and treats scan-line shape as the existing no-op
  surrogate. Fixtures `t1_loccurs`/`v10_t1_loccurs` are oracle byte-exact.
  `pz.exe` now decodes fully (strict corpus 14→15); `styled.exe` advances to
  `jcc 75`, and `styllist.exe` to signed relational `IF jcc 7f`. Full suite:
  2198 passed, 14 skipped.
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

- **Numeric console INPUT into DOUBLE** (2026-07-20): `banker.exe`'s
  `INPUT` prologue carries the numeric type bit and its read terminal is
  `fstp64 [disp]`, not the previously supported `fstp [disp]` SINGLE form or
  the integer FISTP bridge. The continuation is the same one-target
  `_input_target` path, with no new IR shape. `t1_inpdbl` and
  `v10_t1_inpdbl` compile byte-exactly against the vendored 1.1/1.0 oracles;
  the wild file now advances to `stray USING emit`.

- **TAB/SPC inside PRINT USING** (2026-07-20): after the DOUBLE INPUT fix,
  `banker.exe` exposed `TAB/SPC` between two USING value emits. The oracle
  reproduces this with `PRINT USING "##"; A; TAB(5); B` and the matching
  `LPRINT` form in both dialects. The decoder now retains TAB/SPC as a Call
  expression in `PrintUsing.values`; the renderer preserves the semicolon
  spelling and the C backend emits the tab operation rather than formatting
  the column number as a USING value. `t1_usingtab`/`v10_t1_usingtab` are
  byte-exact fixtures. `banker.exe` advances to `unhandled op testw`.

- **Non-adjacent x87 FOR/NEXT sign test** (2026-07-20): after the USING-chain
  fix, `banker.exe` stopped at `testw [0x012A],8000h`. Its loop variable is at
  `0x0208`, with limit `0x012C` and step `0x0128`, so the existing `v-4/v-8`
  FOR-header assumption could not open the loop. The decoder now recognizes
  the complete two-path x87 test prefix, verifies that the three preceding
  assignments target those exact slots, and passes explicit `lim`/`stp`
  displacements to the existing NEXT lifter. This is deliberately narrower
  than accepting arbitrary `testw`. The real corpus hit decodes to 3029 IR
  statements; `tests/tbx/test_wild_batch3.py` keeps it as a regression witness.
  The fresh 84-file scan is 16 OK / 68 blocked, with no regressions; the next
  first blocker is the seven-file `unhandled byte ea` group.

- **Far `JMP` (`EA`) runtime-revision group** (2026-07-20): seven wild files
  stopped on the raw 16-bit `EA off:seg` transfer. The existing far-call
  convention establishes that segment-zero offsets rebase from the user-code
  start while relocated segments use the preceding-byte origin; applying that
  rule lands the non-zero targets on the corresponding wild code streams.
  Zero-offset transfers are the fixed cleanup/event handoff and terminate the
  scan like the existing `EC/E8` epilogue. The scanner now records non-zero
  transfers as `jmpf`, and conditional `JCC`/far-jump pairs use the five-byte
  skip length. The fresh scan removes `unhandled byte ea` from all seven files,
  with no regressions; each now exposes an independent later blocker. The
  oracle probe matrix for ERROR/RESUME, ON KEY, ON GOTO, nested IF, and GOTO
  did not emit `EA`, so this remains a wild runtime-revision closure rather than
  an oracle fixture.

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

### Reference: `$INLINE` / `SUB ... INLINE`, confirmed via the real handbook + oracle (2026-07-19)

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

### Gap byte 89 / the missing `di` spill register, DI LEVEL CLOSED; MEMORY-SPILL LEVEL OPEN (2026-07-19)

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

### Gap INT EC sub 4c (be.exe/pwinst.exe/strpfind.exe), UNDIAGNOSED (2026-07-19)

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

### Gap INT ce (billadd.exe/file.exe), UNDIAGNOSED (2026-07-19)

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

### Gap "unhandled materialized test" (metric.exe) — CLOSED (2026-07-19)

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

### Gap "codeless-statement entry but no DATA pool" (metric.exe), SOLVED (2026-07-19)

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

### CLOSED 2026-07-20 — missing runtime-revision three-argument INSTR (`INT ED sub 1e`)

`INT ED sub 1e` is the runtime entry for the three-argument form
`INSTR(start, haystack$, needle$)`. This is a missing Turbo Basic runtime
variant, not `CINT` and not a new IR intrinsic: the existing `ir.Call("INSTR",
args)` already supports both arities, the renderer preserves the argument list,
and the C backend already maps arity three to `tb_instr(start, haystack,
needle)`.

#### Byte-level calling convention

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

#### Negative evidence and evidence classification

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

#### Validation and unlock result

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

### CLOSED 2026-07-22 — integer runtime-array direct constant-subscript access

The promoted oracle probe `probe_metadynamic_num.exe` exposed a separate
runtime-array gap: integer arrays use runtime-slot type byte `0x00`, and a
constant element assignment emits `mov es,[0120]` followed by
`26 89 06 <disp16>` rather than the indexed `ES:[SI]` store family. The
matching read uses the existing ES-override FP path as `far_fild`. The scanner
now records the direct store, the lifter resolves its two-byte integer offset
through the active runtime-array record, and the layout anchor accepts integer
runtime slots. `Dim.dynamic` preserves the required `DIM DYNAMIC` spelling for
constant-bound runtime arrays without changing existing IR snapshots.

Fixture `t1_dynconstnum` is present in both dialect-independent corpus form and
ops/user-code snapshots. `verify_fixture t1_dynconstnum` is byte-exact; the
full suite passes at 2410 passed / 14 skipped; Ruff and `git diff --check` pass.
The fresh wild scan advanced the promoted probe and reports 24 decode OK / 67
blocked across 91 executables, with zero regressions.

### CLOSED 2026-07-22 — VARPTR$ pointer-string construction

The retained scalar and rank-1 array probes share the exact chain
`movsi; movdx; movesdx; mov [002e],imm16; mov [0032],ES; mov [0030],SI;
shortstr; movsi; strassign`. The decoder now recognizes that complete chain,
resolves either a scalar slot or a constant-bound rank-1 array element, and
emits `VARPTR$` as an IR call. Partial chains and unsupported array ranks
remain fail-loud.

Fixtures `t1_varptrs_scalar`, `t1_varptrs_arr`, `v10_varptrs_scalar`, and
`v10_varptrs_arr` all pass byte-exact oracle verification. The two retained
wild probes are now decode-OK; the next fresh wild tally should therefore be
26 decode OK / 67 blocked across 93 executables.

### CLOSED 2026-07-22 — reverse dynamic-array SWAP segment juggling

Oracle probes with two `$DYNAMIC` arrays reproduce the remaining reverse
segment topology: the first computed element loads ES and saves it with
`mov [0062],ES`; the second loads its own ES, restores the saved segment into
DS, and swaps the two element payloads through opposite segment overrides.
The decoder recognizes the complete reverse tail, including the two-word
STRING descriptor and the four-word DOUBLE payload, and consumes the explicit
`mov DS,DX` restoration only as part of that gated chain. Partial tails and
other element widths remain fail-loud.

Fixtures `t1_swap_dynstr`, `v10_swap_dynstr`, `t1_swap_dyndbl`, and
`v10_swap_dyndbl` pass byte-exact oracle verification. The runtime-slot layout
anchor also now admits the already-documented DOUBLE type byte `0x06` when
finding dynamic-array records. The wild scan remains 26 decode OK / 67 blocked;
`mdb.exe` and `mdb87.exe` advance from byte `8e` to a later `testw` gap, while
`stat.exe` advances to a subsequent runtime-layout gap.

### Gap 33 — INT EC sub 38 (catalog/football/refund/varamort), UNDIAGNOSED

Fresh handbook probes for `PALETTE USING P%(0)` (dynamic, static, and variable
index forms) all compiled but decoded to the distinct `INT EC sub 8a` gap. Per
the repository agent rule, their executables are retained as
`wild/hits/probe_paletteusing*.exe`; they are negative evidence against
PALETTE USING as the source of canonical `EC/38`. Explicit `LOCAL A$()` / `LOCAL
A%()` variants were also retained as `wild/hits/probe_localdecl*.exe`; both
fail earlier at byte `8b`, so they are separate Wave-2 evidence rather than
Gap 33 matches. The corpus is now 91 executables: 24 decode OK and 67
blocked.

`VARSEG` and `VARPTR` array-element probes decoded cleanly without `EC/38`.
The retained `VARPTR$` scalar and array probes now decode cleanly after the
separate intrinsic closure. The corpus is now 93 executables: 26 decode OK
and 67 blocked.

`$DYNAMIC` constant-bound DIM probes for string arrays decoded cleanly; the
numeric form originally failed at byte `26`. That witness is now decode-OK
after the integer runtime-array closure; it remains in `wild/hits/` as a
promoted probe and is covered by fixture `t1_dynconstnum`.

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

### Gap INT-8c — likely ON KEY GOSUB related, UNDIAGNOSED

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

### Gap byte ea (elec87/mcmurphy/mf/swbb), UNDIAGNOSED — ">64K" theory REFUTED

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

### Gap 19 — byte 06 (filepatc/morcalc/pw, all TB 1.0), UNDIAGNOSED

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

### The workflow (each gap, see gap 9–14 commits for examples)

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
