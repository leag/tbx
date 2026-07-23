# Remaining decoder gaps — execution plan

This is the resumable work plan for finishing the Turbo Basic decoder campaign.
It is deliberately separate from `HANDOFF.md`: the handoff preserves discoveries
and historical evidence; this file says what to do next, in what order, and how a
future session proves that it made progress.

## Project scope

The project target is **all Turbo Basic syntax**, across documented language
editions, compiler dialects, and compatible runtime revisions—not merely the
constructs currently listed in the Borland handbook. The handbook is a reference
and source of semantics, not a whitelist or completion boundary.

Track support in three dimensions: source syntax recognition, bytecode decoding,
and semantic/runtime fidelity. A construct may be source-known but bytecode-
unwitnessed, or bytecode-known but absent from the handbook; neither case is
silently discarded. Every new fixture and gap-ledger entry records its dialect,
edition/runtime tag, and evidence provenance.

## Live checkpoint

- Updated: 2026-07-20
- Branch: `claude/claude-md-docs-mr8ssz`
- Baseline commit: `25fbe9c` (`Decode INP intrinsic dispatcher`)
- Corpus: `wild/hits/` (84 Turbo Basic executables; gitignored, never commit)
- Baseline result: 14 decode OK, 70 fail at their first visible gap
- Current strict result: 16 decode OK, 68 blocked. Several blocked files have
  advanced through multiple signatures even though the strict count is flat.
- Current validation: 2233 passed, 14 skipped (2026-07-20); eight new 1.0/1.1
  oracle round trips are byte-exact for nested logical short-circuit forms and
  leading-semicolon `LINE INPUT;`.
- Immediate target: `unhandled INT 8c` (four files), continuing from Gap 33 in
  `HANDOFF.md`; the seven-file `byte ea` group is now advanced and documented
  as a runtime-revision closure.
- `INT ED sub 1e` is now identified as the missing three-argument
  `INSTR(start, haystack$, needle$)` runtime entry. Four independent wild
  programs establish the same AX-plus-two-string calling convention. The
  vendored compiler rejects all common three-argument source spellings, so this
  closure is classified as `runtime-revision`, not `oracle-verified`.

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

## Resume procedure

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

## Definition of a closed gap

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

## Standard gap workflow

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

## Work queue

Priority balances affected-file count, likelihood of oracle reproduction, risk,
and **unlock value**. Counts below are only the first-failure snapshot from
2026-07-19. When a fix advances a file, log both its old and new signature. Prefer
a lower-frequency gap when prior results show that it exposes shared downstream
work in several files. This blocker history is the campaign's unlock graph; do
not overwrite it with only the latest state.

### Wave 0 — restore the validation baseline

- [x] Regenerate `tests/fixtures/ir_snapshot.txt` and confirm the only addition is
  the already-committed `t1_getstr` section.
- [x] Rerun the full suite and establish the first tracked sanitized corpus report
  at `gap_reports/2026-07-19-baseline.json`.

### Wave 1 — bounded runtime dispatches

These have explicit opcode boundaries and are the best candidates for safe,
fixture-backed closures.

- [x] `INT ED sub 1e` — missing runtime-revision entry for
  `INSTR(start, haystack$, needle$)`. Four files (`be.exe`, `crossref.exe`,
  `hebrew.exe`, `invent.exe`) independently preserve the start position in AX,
  push haystack then needle, and consume the AX result. The adjacent `ED/1c`
  entry is the already-verified two-argument `INSTR`. See the full evidence and
  oracle limitation in `HANDOFF.md`.
- [ ] `INT EC sub 38` — 3 files. Re-open Gap 33 evidence in `HANDOFF.md`, build a
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

### Wave 2 — repeated instruction and x87 templates

- [ ] FP `dc/04` — 2 files; compare memory operand addressing with supported x87
  arithmetic forms and add a fixture for the exact data type.
- [ ] FP `da/1c` — 2 files; determine whether it is integer multiply/compare or a
  compiler spill form before generalizing ModR/M handling.
- [ ] byte `89` — 3 files; verify these are not another register-spill topology
  already partly covered by the DI work.
- [ ] byte `8c`, `8b`, `0b`, `1e`, `f7` — 2 files each. Cluster by the complete
  instruction and nearby ops rather than by first byte alone.
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

### Wave 3 — decoder state and structural recovery

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

### Wave 4 — ambiguous control/data and runtime-revision patterns

- [ ] byte `ea` — 6 files. Separate genuine far jumps from inline data records;
  require control-flow reachability evidence before accepting either shape.
- [ ] byte `90` — 6 files. Existing evidence suggests an unwitnessable runtime
  revision pattern; repeat only probes that add a genuinely new source topology.
- [ ] byte `06` — 3 files and raw `INT 8c` — 3 files. Continue from the extensive
  negative probes in `HANDOFF.md`; do not repeat the same ON KEY variants.

Wave 4 is intentionally last: permissive handling here could hide corrupt control
flow and produce plausible but wrong BASIC.

### Wave 5 — syntax inventory beyond the handbook

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

## Tooling work

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

## Validation commands

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

## Progress log

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
| 2026-07-22 | pending | Decode `IOCTL #n,s$` / `IOCTL$(n)` (`EC sub 50` / `EE sub 14`), a Wave-5 syntax-inventory gap found while chasing `EC sub ac` | 23 OK / 61 blocked; 0 regressions; touches no wild file | `EC sub ac` is confirmed NOT `IOCTL` despite the identical filenum+string calling convention — still unidentified, see `HANDOFF.md` |
| 2026-07-22 | pending | Decode `PUT$ #n,s$` (`EC sub ac`) — binary-mode string write, GetString's complement | 23 OK / 61 blocked; `nvginst`/`pwinst`/`secure` all advanced past this signature into 3 distinct new gaps, 0 regressions; `EC sub ac` signature removed | Triage the 3 newly exposed signatures (`byte f7`, `byte 36`, a jump-target error) |
| 2026-07-22 | pending | Decode `mov ss:[si],imm16` (byte `36`, new op `movm_imm_temp`) + fix a real pre-existing bug: `fn_args` had no nesting protection around a DEF FN call used as another call's own argument | 23 OK / 61 blocked; `hebrew`/`pwinst` advanced past this signature, 0 regressions; byte `36` signature removed | Triage `byte 2b` (hebrew) and `byte 26` (pwinst) separately |
| 2026-07-22 | pending | Decode `or ax,es:[si]` (new op `far_orax_si`), the OR sibling of the already-handled `far_andax_si` in the by-ref-int-param family | 23 OK / 61 blocked; `pwinst.exe` advanced past this signature, 0 regressions | `pwinst.exe`'s own `byte 26` occurrence is now closed; the SAME signature at `bmaster.exe`/`ifi.exe` is a DIFFERENT, harder shape (`26 ff 0c` = far DEC, needs `local_init` base-disp threading, see HANDOFF's "Investigated at length but NOT landed" writeup) — do not assume this closure fixes those two |
| 2026-07-22 | pending | SOLVE the multi-session `far_call(mid-flow)`/`KeyError: 86343` mystery: under active event trapping, `GOSUB` compiles to a far call/retf pair, not near — `_resolve_calls` now falls back to `ir.Gosub` when a far_call target isn't a known proc; also fixed an independent latent bug (`far_call` used the wrong statement address, silently corrupting `$EVENT ON/OFF` metadata recovery under trapping) | 23 OK / 61 blocked; `resume.exe` advances completely past this into a DIFFERENT jump-target-resolution error, 0 regressions | `resume.exe`'s new failure is NOT the same bug as state.exe/state87.exe's (corrected after further tracing — see `docs/intra-inline-if-goto-spec.md`'s "out of scope" section); it targets compiler glue and needs its own trace. Target `86343`'s own large-near-call-displacement mechanism is also untested separately |
| 2026-07-22 | pending | Write `docs/intra-inline-if-goto-spec.md`: a full investigation spec for the intra-inline-IF-body GOTO gap (state.exe/state87.exe), correcting an earlier same-day misdiagnosis ("SUB/DEF FN body" — state.exe has none) by cross-referencing an existing, more precise prior-session diagnosis and confirming it via fresh `id()`-tracing | No code change; 23 OK / 61 blocked unchanged | Follow the spec's phased plan (minimal probe first, trace `_fold_if`/`_body_has_target`, then fix) in a dedicated session |

## Completion checklist

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
- [ ] `HANDOFF.md` contains durable reverse-engineering findings; this plan records
  all work items complete and points to the final commits.
