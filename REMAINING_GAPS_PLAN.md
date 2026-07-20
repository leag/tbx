# Remaining decoder gaps — execution plan

This is the resumable work plan for finishing the wild-corpus decoder campaign.
It is deliberately separate from `HANDOFF.md`: the handoff preserves discoveries
and historical evidence; this file says what to do next, in what order, and how a
future session proves that it made progress.

## Live checkpoint

- Updated: 2026-07-19
- Branch: `claude/claude-md-docs-mr8ssz`
- Baseline commit: `25fbe9c` (`Decode INP intrinsic dispatcher`)
- Corpus: `wild/hits/` (84 Turbo Basic executables; gitignored, never commit)
- Baseline result: 14 decode OK, 70 fail at their first visible gap
- Current worktree at plan creation: scanner-report tooling plus this plan
- Baseline validation: 2168 passed, 14 skipped after repairing the missing
  four-statement `t1_getstr` IR snapshot section.
- Immediate target: identify `INT ED sub 1e` in `be.exe` and `budfin.exe`
- Important negative result: a minimal `CINT(1.7)` oracle probe compiles cleanly
  without producing this gap; do not label sub `1e` as `CINT` from intuition.

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

- The source construct is identified from compiler-oracle evidence or an equally
  strong byte-level proof. Similar-looking opcodes are not sufficient.
- A minimal fixture is added under `tests/fixtures/corpus/` when the oracle can
  reproduce the byte pattern, with matching ops/user-code snapshots.
- Decoder and IR/render/C changes preserve fail-loud behavior for shapes that are
  still unknown.
- Focused tests cover the new construct and any dialect or arity variation.
- `ruff`, `git diff --check`, focused tests, and the full test suite pass.
- A fresh wild report demonstrates the expected files advanced or completed and
  shows no reduction in the decode-OK count.
- The change is committed independently with the progress log updated.

If the installed compiler cannot reproduce a wild pattern, classify it as
`revision-skew` and retain fail-loud decoding. Such a classification needs the
probe matrix and byte context recorded in `HANDOFF.md`; it does not count as
84/84 completion unless project policy is explicitly changed.

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

- [ ] `INT ED sub 1e` — 2 files (`be.exe`, `budfin.exe`). Inspect argument/result
  convention first. `CINT` has already been ruled out by a minimal probe.
- [ ] `INT EC sub 38` — 3 files. Re-open Gap 33 evidence in `HANDOFF.md`, build a
  statement-family probe matrix, and test both dialects.
- [ ] `INT EC sub 42` — 2 files (`styled.exe`, `styllist.exe`). Their common
  provenance may make source-shape comparison especially useful.
- [ ] `INT EC sub ac` — 2 files.
- [ ] raw `INT af` — 2 files; determine whether it is a string/array runtime vector
  by tracking stack and descriptor setup.
- [ ] raw `INT c2` — 2 files.
- [ ] singleton dispatches: `INT d4`, `INT EC sub ee`.

### Wave 2 — repeated instruction and x87 templates

- [ ] FP `dc/04` — 2 files; compare memory operand addressing with supported x87
  arithmetic forms and add a fixture for the exact data type.
- [ ] FP `da/1c` — 2 files; determine whether it is integer multiply/compare or a
  compiler spill form before generalizing ModR/M handling.
- [ ] byte `89` — 3 files; verify these are not another register-spill topology
  already partly covered by the DI work.
- [ ] byte `8c`, `8b`, `0b`, `1e`, `f7` — 2 files each. Cluster by the complete
  instruction and nearby ops rather than by first byte alone.
- [ ] relational/materialization gaps: integer compound `jcc 7f` (2), singleton
  `jcc 75`, and materialization-template mismatch.
- [ ] singleton instruction bytes `ff`, `38`, `36`, `21`, `18`, `16`.

### Wave 3 — decoder state and structural recovery

- [ ] unknown system cell `0x8a` — 2 files; correlate reads/writes and runtime
  consumers before assigning semantics.
- [ ] unknown system cell `0x110` — 1 file.
- [ ] numeric `INPUT` read without `FSTP` — identify alternate target/store shape.
- [ ] `LINE INPUT` trailing byte `c0` and `LINE INPUT #` template mismatch.
- [ ] cursor call without open `LOCATE` — test optional-argument and statement
  coalescing assumptions.
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

## Tooling work

- [x] Add `scan_wild.py --report FILE`: JSON totals, per-file results, and stable
  address-normalized failure groups for cross-session comparison.
- [x] Commit-ready sanitized baseline under `gap_reports/`; `/tmp` is working storage,
  not a resumable checkpoint.
- [ ] Add `compare_gap_reports.py` before the next decoder closure. It must show
  files newly decoded, regressed, advanced to a different signature, unchanged,
  signatures removed, and newly exposed signatures. Its advanced-file output is
  the input to the unlock graph.
- [ ] Extend `batch_probe.py` with optional retained artifacts (`--keep DIR`) so a
  winning oracle executable can be inspected without recompiling. Ensure the
  output directory is outside the repository by default and never auto-commit it.
- [ ] Add a context dumper accepting `EXE OFFSET` that prints raw bytes, nearby
  scanned ops, dialect-canonical interrupt numbers, and decoder register/stack
  state where available. Reuse `insns.py`/`dump_ops.py` rather than duplicating
  disassembly logic.
- [x] Add report schema version, generator identity, and content-based corpus
  fingerprint so comparisons can reject incompatible formats or different corpora.
- [ ] Assign stable IDs such as `G-ED-1E` to active gaps and keep hypothesis,
  evidence, confidence, and disposition in a compact ledger. Error text remains
  a symptom and may change without creating a new logical gap.
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

## Completion checklist

- [ ] Wild corpus reaches 84/84 decode OK, or each exclusion is explicitly
  accepted in project policy with a byte-exact reason.
- [ ] No fixture, regression, lint, or formatting failures.
- [ ] Every new IR node and intrinsic has render, rename, and C behavior (or an
  explicit unsupported-C diagnostic) as applicable.
- [ ] The final JSON report is archived in a tracked, copyright-safe summary that
  contains paths/signatures only, never wild executable bytes.
- [ ] `HANDOFF.md` contains durable reverse-engineering findings; this plan records
  all work items complete and points to the final commits.
