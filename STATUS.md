# tbx — project status

**Parked 2026-07-29. Unattended.** Nothing in this file or in `PLAN.md` is a
commitment to future work. The tree is green and the decoder does what the
README says; the wild-corpus campaign is stopped mid-tail, deliberately, and
this page is the one read needed to pick it up or leave it alone.

Read this file first. `PLAN.md` is 9000 lines and is now an **evidence
archive**, not a work queue — go there for the reasoning behind a specific
finding, not to find out what to do next.

## Current mcmurphy investigation

The command-dispatch string guards now survive decoding when a near branch's
16-bit target names an operation in an earlier code window. `DecodeState.branch`
canonicalizes that target to the matching operation in the active window before
inline-IF frames close. The wild regression asserts all eleven previously
missing literals (`xmaid`, `xbutler`, `x#z`, `xK`, `xZ`, `x6160`, `re30>75`,
`x30>75`, `O`, `u>`, `u<`) remain in emitted source.

Measured with the oracle using dialect `1.1` and toggles `KBOS`, the mcmurphy
round trip improved from 127,313 to 129,697 bytes against a 129,710-byte
original. Layout array bases and the complete string-pool multiset now match;
the remaining 13-byte delta is a DATA/string-descriptor ordering issue, not a
missing guard. Use `python -m tbx.tools.roundtrip_report` to reproduce the
measurement.

The residual was narrowed from the original descriptor table without another
oracle compile: the descriptors classified as DATA are three non-contiguous
runs (indices `570`, `572`, and `583..589`), interleaved with code-referenced
strings. mcmurphy has no error-trap line table, so it carries no codeless DATA
statement lines or boundaries that the decoder can recover. Emitting those
runs as one top-level `DATA` statement is therefore the only evidence-backed
canonicalization currently available; synthesizing source placement from pool
order would be a guess and risks changing unrelated programs.

The boolean folding gap is now closed for a calibrated shape: when a compound
`IF` owns a `FOR/NEXT` body, `_fold_if` preserves the structured block instead
of rewriting it as a negated `OR` guard. The rewrite changed Turbo Basic's
short-circuit template (`AND`/`andaxbx` to `OR`), causing byte drift. The new
`probe_compound_loop_block` fixture round-trips byte-for-byte (34,832 bytes).
The mcmurphy measurement remains 129,697 versus 129,710 because its residual
13-byte difference is in the separate DATA descriptor ordering issue.

Artifact refresh (2026-08-01): `scan_wild --only mcmurphy.exe` reports one
Turbo Basic 1.1 hit with 3,092 statements and no decode failures. A follow-up
oracle report was attempted with an 800 MB virtual-memory cap; the vendored
Node/V8 process failed before compilation while reserving its CodeRange. This
is an infrastructure limit, not a decoder or source-compile result; the last
uncapped oracle measurement remains 129,697 rebuilt bytes versus 129,710.

## Verified state on the park date

Run on `release/0.1.0` at `b79a756`:

| Check | Command | Result |
|---|---|---|
| Test suite | `uv run pytest` | **2805 passed** |
| Lint | `uv run ruff check tbx tests` | **all checks passed** |
| Wild corpus | `uv run python tbx/tools/scan_wild.py wild/hits --report ...` | **33 of 86 decode-OK** |

Fixture corpus: 442 compiled `.bas` fixtures, 1034 op goldens, 1015 emitted-source
goldens. Authored probes: 28 under `wild/probes/`.

### Branch state — read this before trusting any local ref

**Local `main` and `origin/main` have diverged, and the local one is the real
work.** Local `main` is **73 commits ahead of `origin/main` and 1 behind.** The
one commit it lacks is `e56d981`, GitHub's own merge commit for PR #5; the same
content was merged locally as `2ff4189` instead, so the two histories describe
the same work through different merge commits and will not fast-forward onto each
other.

The practical consequence: **anyone cloning this repository from GitHub gets a
`main` that is 73 commits behind this working copy.** Measure against
`origin/main`, not `main`, when reasoning about what the world can see.

| Branch | vs local `main` | vs `origin/main` |
|---|---|---|
| `release/0.1.0` | ahead 20, behind 0 | ahead 93, behind 1 |
| `experimental/c0` (native C backend) | ahead 1, behind 83 | ahead 1, behind 11 |
| `experimental/deferred-fold` | ahead 0, behind 32 | **ahead 41**, behind 1 |
| `propagate_call_types` | ahead 0, behind 84 | ahead 0, behind 12 |
| `refactor-direct-bool-ir` | ahead 0, behind 83 | ahead 0, behind 11 |

So: `propagate_call_types` and `refactor-direct-bool-ir` are fully merged by both
measures and are safe to delete. `experimental/deferred-fold` is **not** — it is
merged into local `main` only, and carries 41 commits `origin/main` has never
seen. `experimental/c0` holds one unique commit and is the branch `CLAUDE.md`
designates for the native C backend; keep it.

PR [#6](https://github.com/leag/tbx/pull/6) is open for `release/0.1.0` → `main`
and carries the 93 commits above. Version stays `0.1.0`; **nothing was tagged or
released, and merging that PR would not be a release.**

## What "correct" means here, and where that runs out

The contract is byte-exactness: a recovery is correct only when recompiling the
emitted source with the original Borland toolchain reproduces the input EXE
byte-for-byte. That contract is fully enforced across the fixture corpus, which
is what the 2805 tests defend.

**It is not verifiable for most of `wild/hits`, and no amount of decoder work
changes that.** Those executables were built with runtime revisions the vendored
v86 oracle does not have, so a byte comparison against a re-compile measures
runtime skew as well as decoder error. `wild/hits/tbd73.exe` is the exception and
the reason it carried so much of the campaign: it is TBWINDOW 7.3 compiled from
`TBD73.BAS` + `TBW73.INC` **by our own oracle**, so its gaps were read off real
source instead of reverse-engineered, and a round trip on it means something.

The full census reached this conclusion independently — see `PLAN.md:1915`
("Census FINISHED, and the mismatch class is probably NOT a decoder defect") and
`PLAN.md:1859` for the localization that preceded it. Treat any plan to drive
`wild/hits` to 100% as unfounded until that census is revisited.

## Why this is parked rather than finished

`PLAN.md`'s own completion checklist (`PLAN.md:951`) and scope statement
(`PLAN.md:47`) are **superseded by this file.** They cannot be satisfied as
written:

- The checklist asks for "84/84 decode OK". The corpus is now 86 executables;
  the number was the corpus size on 2026-07-23. Every wild EXE added moves the
  finish line.
- The scope statement claims "all Turbo Basic syntax, across documented language
  editions, compiler dialects, and compatible runtime revisions — not merely the
  constructs currently listed in the handbook." There is no reachable state of
  the code that demonstrates coverage of syntax that has not been witnessed.
- The remaining tail has no leverage left: 53 blocked files across **38 distinct
  first-failure signatures**, 30 of them affecting exactly one file. The era
  where one closure advanced seven files is over — see the progress log
  (`PLAN.md:914`), whose every row generates the next row's blocker.
- Byte-exactness, the project's definition of correct, is unavailable for most of
  the tail (above).

The campaign was real and it worked: 14 decode-OK on 2026-07-19 to 33 on
2026-07-29. It is stopped because the goal was unbounded, not because it stalled.

## The remaining tail

Current first-failure signatures, from `gap_reports/2026-07-29-current.json`.
This is a **flat inventory, deliberately unprioritized** — ordering it would
imply a queue.

| Files | Signature | Executables |
|---|---|---|
| 4 | DGROUP layout not solvable from the calibrated rules | menu, night, sprogh, swbb |
| 4 | unhandled jcc 74 | file, grdscn, hebrew, pwinst |
| 4 | unhandled materialized test | cal, cal87, football, varamort |
| 3 | materialization template mismatch | kinder, kinetics, wb |
| 2 | `87` (DATA/code shared descriptor) | styled, styllist |
| 2 | LOCAL zero-fill outside a fresh SUB/DEF FN body | cleanup, reformat |
| 2 | ax,bx combine with empty regs | hfprop, number |
| 2 | jump target `0x1991f` is not a statement start | mdb, mdb87 |
| 1 each | NEXT template mismatch · SCREEN bad tag · SELECT CASE string arm: unexpected jcc 76 · `[bp+6]` outside the open LOCAL frame · bad string descriptor at `[0x05a0]` · displacement `0x1054` neither scalar nor array element · displacement `0x76` likewise · element access: unexpected op movrr · empty di spill · forwarded arg to unknown callee params · string BP push outside DEF FN · numeric INPUT read without FSTP · runtime blocks not `0x36`-contiguous after statics · unhandled INT 8c · unhandled INT EC sub a6 · unhandled bytes 18, 21, 33, 38, 51, ad, c4 | mcmurphy, refund, nvginst, CVT2TB, mf, filepatc, billadd, pfl, process, bmaster, crossref, rs, stat, ifi, catalog, bm1_dsk2, pcdcfile, phone, lmaster, sabpcv3, nvg, pw |
| 1 each | jump target not a statement start (6 distinct addresses) | prtguide, help, resume, rsltest, photo, elec87/electron, morcalc |

## Diagnosed but not landed

These are the threads with real diagnosis behind them. Each is a genuine
stopping point, not an unexplored gap — read the cited entry before touching the
code, because several were **tried and reverted** and the entry says why.

- **`mcmurphy.exe` round-trip — unmatched `EXIT LOOP` (diagnosed 2026-08-01).**
  The emitted source contains `EXIT LOOP` at BASIC line `7920` before the next
  lexical `DO` (line `8010`), with the same shape recurring at `8300`, `10390`,
  and `11130`. Turbo Basic consequently reports `Error 435: DO loop expected`
  later, at physical include line 1840 (`18370 AI = 0`); that reported line is
  only where the parser notices the earlier damage. The decoder-side cause is
  `_apply_exit_folds()` in `tbx/decode0/lift.py`: it rewrites every GOTO whose
  target equals an exit address when it cannot locate the enclosing loop
  (`for_start is None`), because `in_for` deliberately falls back to `True`.
  In this large state-machine shape, a following loop begins at the same
  address as the preceding loop's exit; the backward edge into that following
  loop is therefore mistaken for the preceding loop's exit and becomes
  `ExitLoop` outside any `Do`. The existing guard comment documents the failure
  for `cal.exe`; `mcmurphy.exe` is a second witness of the same ungated fallback.
  The decoder fix now constrains the rewrite to a positively identified
  enclosing `Do`; ambiguous targets remain `GOTO`s, and the emitter guard still
  rejects any invalid `ExitLoop` that slips through. Both witnesses should be
  recompiled through the oracle before this fix is treated as byte-exact.

- **`mcmurphy.exe` round-trip — stack-test helper bytes (narrowed 2026-08-01).**
  Calibrated `S` and `KBOS` probes show that a normal INT 8A payload is a
  signed start-relative GOSUB target; the scanner now restores those as `call`
  and keeps only out-of-image payloads as source-less `stack_call_runtime`.
  This improves mcmurphy's rebuilt size from 123,920 to 127,313 bytes. The
  remaining first structural divergence is operation 1384: the original has
  an out-of-image INT 8A helper immediately before a valid checked GOSUB, while
  the rebuilt image has only the GOSUB. That helper is not a source-level
  target: its payload decodes to `0xe989b00`, and interpreting the words as a
  far pointer lands at `0xe980`, whose bytes begin `INT 87`/runtime dispatch,
  not a BASIC statement. It must not be guessed as a GOSUB. Establish whether
  it is a compiler/runtime revision artifact or a reproducible KBOS helper
  shape before adding preservation logic.

  A tested follow-up hypothesis treated 220 relative-looking targets landing on
  another `CD 8A` as helper chaining. The oracle rejects that change: split
  source recompiles at 125,309 bytes versus 127,313 bytes with those targets
  retained. The filter was reverted; those targets are not proven helpers.

- **`mcmurphy.exe` 48-byte static-band shift — `$SEGMENT` hypothesis ruled out
  (2026-08-01).** Removing the recovered `$SEGMENT` directive does not produce
  the original allocation; Turbo Basic rejects the resulting source with
  `Error 408: Segment exceeds 64k` at line 28220. The directive is required to
  compile this large program, so it cannot be the missing 48-byte reservation.
  With the oracle harness's Compile-to navigation fixed, the current split
  source recompiles to 127,313 bytes. The first scanned-op mismatch is already
  the first array access (`FILD 0x1378` in the original versus `0x134c` in the
  rebuild); every scalar and pool slot remains aligned. Two oracle probes show
  that adding twelve scalar slots shifts the array band by exactly 48 bytes,
  but also shifts the pool, so that is not evidence for inserting twelve
  speculative variables. The remaining cause is an untracked compiler-generated
  pool/code-layout contribution and needs a source witness before changing
  layout recovery.

- **`tbd73.exe` round-trip** (`PLAN.md:2000`, round 47). Decodes end to end —
  906 lines, exit 0 — but does not recompile. Four defects were fixed; the
  recompile now stops at `Error 475: Parameter mismatch` with two diagnosed open
  causes: a lost trailing STRING parameter (`TBW73.INC:427`), and a by-ref
  argument with no other use spelled `%`. The second needs layout to distinguish
  "typed by evidence" from "defaulted" — **not** another caller-side special
  case. This is the highest-value single thread in the repo, because it is the
  one wild file where a round trip is meaningful.
- **`resume.exe` — 98.59%, was 80.14%** (2026-07-31). Both halves of the
  forwarded-parameter typing are in: a helper callee takes the caller's type
  (`_type_helper_forwards`), and an ORDINARY callee with an untyped parameter
  is retyped at BOTH ends -- argument, header and body together
  (`_type_untyped_callee_params`), which is what avoids the `Error 475` a
  one-ended retype gives. What remains is 1365 unreproduced bytes and delta
  +32, at 98.82% after the numeric SELECT CASE entry learned to skip an
  event-trap poll stamp (ledger `RR-BYREF-INT-FP-COMPARE`, closed). What is
  left is scattered rather than structural -- the op-kind diff no longer has a
  dominant signal.
- **`cal.exe`/`cal87.exe` — a loop closed too early** (2026-07-30). Two upstream
  defects were found and fixed (commit `c2994a3`): a fold region started one
  statement early when a codeless `DO` was spliced below its recorded boundary,
  and the inline guard now skips those address-less headers. cal's decode now
  matches its byte order — INPUT before the test, `IF BD >= 1 AND BD <= 80 THEN
  <exit>`. It still does not compile. The remaining defect is precise: **two
  `EXIT LOOP` statements stand outside any `DO...LOOP`** (bundle lines 20405 and
  20435, immediately after the `LOOP` at 20345), which is what TB reports as
  `Error 435: DO loop expected`. They belong to a loop the decoder closes too
  early, so look for the missing enclosing `DO...LOOP` rather than at the EXITs
  themselves. Ruled out along the way, in
  `gap_reports/ruled-out-hypotheses.json`: `$INCLUDE` block spanning
  (`RO-INCLUDE-BLOCK-SPAN`), jumping into a DO body (`RO-GOTO-INTO-DO`), and
  six candidate source spellings (`RO-CAL-SOURCE-SHAPES`). A block-nesting
  sweep will call this file clean — it cannot see an EXIT outside its block.
- **`state.exe`/`state87.exe` — one loop/FOR crossing left** (2026-07-30). Three
  of four were closed by teaching `_loop_back_in_scope` that a back-edge may not
  span a `NEXT` whose FOR opened above it. The fourth survives because the
  compound tail-test path bypasses that guard when `empty_body` is true
  (`lift.py`, `_lift_bool_do_tail`). Still COMPILE-FAIL.
- **Per-procedure TYPE resolution pre-pass** (`PLAN.md:60`, live checkpoint).
  Rounds 18 and 19 were single-pass state-ordering bugs — the decoder infers
  whole-procedure facts destructively *while* lifting, so results depend on which
  op it saw first. Round 22 converted one such case to evidence-based layering;
  the general fix was scoped and **deliberately deferred**, as it needs its own
  plan plus an oracle re-verification sweep across every op golden. Do not
  mistake round 22 for the whole idea.
- **Intra-inline-IF-body GOTO targets** (`PLAN.md:968`, Part II). A full
  investigation spec exists for `state.exe`/`state87.exe`, including confirmed
  facts, the machinery that should already handle it, a phased plan, and an
  explicit out-of-scope section. It was never executed. Note the spec corrects an
  earlier same-day misdiagnosis; trust the spec, not the older entries.
- **DATA pointer table locator** (`PLAN.md:1494`). The authoritative table was
  found and the crash is now a proper `ValueError` instead of a bare `KeyError`;
  the locator is still open. Reproduced in seven lines at
  `wild/probes/probe_datadup.bas`. Note commit `b79a756` narrowed the claim: the
  table is confirmed on probes, **not** on the wild files.
- **SUB-epilogue `EXIT SUB`** (`PLAN.md:1202`). Cause found and a fix written,
  blocked on the line-width gate. Under event trapping the epilogue is fronted by
  a run of CC hooks and the compiler jumps to the run, not to `proc_ret`, so
  `core.py`'s existing `EXIT SUB` recognition misses. Affects `help`, `resume`,
  `rsltest`.
- **OR-flavored value-folded groups** (`PLAN.md:1775`). `(A AND B) OR (C OR D)`.
  **Tried and reverted** this campaign, no fixture landed, tree confirmed clean.
  An oracle probe reproducing the shape is described in that same entry, but it
  was never committed to `wild/probes/`, so it must be re-authored from the
  description before the evidence can be re-run. Affects `grdscn`,
  `kinder`, `kinetics`, `wb`.
- **LOCAL slot reuse across FOR scratch temps** (`PLAN.md:1817`). Traced
  precisely with instrumented `core.py` (reverted, not committed): the
  variable-limit-FOR branch reserves a step/limit word pair that collides with a
  declared LOCAL. Affects `bmaster`, `ifi`.

## Where the evidence lives

- `docs/decoder-architecture.md` — the pipeline map. Start here for the code, per
  `CLAUDE.md`.
- `PLAN.md` Part III — chronological reverse-engineering log, newest first. The
  durable findings and the dead ends, including which hypotheses were ruled out.
- `PLAN.md` Part II — the one deep-dive spec that was written but not executed.
- `gap_reports/*.json` — dated sanitized scans with schema version, generator
  identity and corpus fingerprint, so two reports can be compared or rejected as
  incomparable. Paths and diagnostics only, never executable bytes.
- `gap_reports/runtime-revision-assessments.json` — `RR-*` ledger with
  hypothesis, evidence class, confidence and disposition per assessment.
- `gap_reports/ruled-out-hypotheses.json` — `RO-*` ledger, the sibling for
  decoder-side dead ends: a cause that was not the cause, or a fix written and
  reverted. Read it before re-deriving a diagnosis; several entries exist
  precisely because the obvious approach was tried and failed.
- `wild/probes/` — authored probes that compiled, with `.bas` source and a
  recorded first failure.
- `docs/release-checklist.md` — what a release would have required. Unused; no
  release was cut.

The Turbo Basic Owner's Handbook was removed from `docs/` on the park date: it is
a third-party 1987 Borland manual and was not ours to redistribute. Prose
citations of it remain throughout (for example
`tests/tbx/test_emitted_source_width.py:3` on the editor's line limits), which is
citation, not redistribution. It is still present in git history at `378bb4f`.

## If you are resuming this

1. Read this file, then `docs/decoder-architecture.md`, then only the `PLAN.md`
   entries cited above. Do not read `PLAN.md` front to back.
2. Confirm the tree still behaves as recorded: `uv run pytest`,
   `uv run ruff check tbx tests`, and a fresh scan compared against
   `gap_reports/2026-07-29-current.json` via `tbx/tools/compare_gap_reports.py`.
3. Decide the scope question before writing code. If the goal is again "all of
   `wild/hits`", re-read the census verdict above first — most of that corpus
   cannot be byte-verified with the vendored oracle, and a coverage target
   phrased in decode-OK count will not tell you whether the decoder is right.
   The honest unit of progress is a construct closed with oracle evidence, per
   `CLAUDE.md`'s calibration rule, which still holds.
4. `tbd73.exe`'s round trip (`PLAN.md:2000`) is the one thread where success is
   unambiguous. If you want a single objective, use that one.

The calibration rule is not suspended by this park: unknown byte patterns must
still raise `ValueError`, and a new mapping still requires a compiled fixture and
byte-exact oracle verification. Parked does not mean relaxed.
