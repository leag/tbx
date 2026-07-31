# tbx — project status

**Parked 2026-07-29. Unattended.** Nothing in this file or in `PLAN.md` is a
commitment to future work. The tree is green and the decoder does what the
README says; the wild-corpus campaign is stopped mid-tail, deliberately, and
this page is the one read needed to pick it up or leave it alone.

Read this file first. `PLAN.md` is 9000 lines and is now an **evidence
archive**, not a work queue — go there for the reasoning behind a specific
finding, not to find out what to do next.

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

- **`tbd73.exe` round-trip** (`PLAN.md:2000`, round 47). Decodes end to end —
  906 lines, exit 0 — but does not recompile. Four defects were fixed; the
  recompile now stops at `Error 475: Parameter mismatch` with two diagnosed open
  causes: a lost trailing STRING parameter (`TBW73.INC:427`), and a by-ref
  argument with no other use spelled `%`. The second needs layout to distinguish
  "typed by evidence" from "defaulted" — **not** another caller-side special
  case. This is the highest-value single thread in the repo, because it is the
  one wild file where a round trip is meaningful.
- **`banker.exe`/`number.exe` — one PRINT statement, two `USING` clauses**
  (2026-07-30). banker recompiles 155 bytes off in 94 KB but 16 bytes too long,
  and every one of those bytes is a per-statement commit marker (`CD 87`,
  raw `CD 81` in TB 1.0) that the original does not have. Turbo Basic accepts
  a SECOND `USING` inside one print statement:
  `LPRINT TAB(5); "n "; TAB(25); USING f1$; A#; TAB(37); USING f2$; B$`
  compiles to one statement with two `rt CA` USING-begins
  (`wild/probes/probe_using_twice_one_stmt.bas`, byte-shape identical to
  banker's). The decoder flushes unconditionally at `rt CA`
  (`handlers/control.py`, "USING begin") and again where a plain item follows a
  USING emit, so one source statement becomes four. 13 extra markers in banker,
  15 sites across banker and number.
  The evidence for the real boundary is already collected and unused:
  `out.commits` holds every commit-marker address, so "is there a marker between
  this chain's start and here" answers it exactly. What blocks the fix is
  representation, not detection — the IR has `Lprint(items)` and
  `PrintUsing(fmt, values)` as separate statements with no mixed form. The
  cheapest shape is to let a `PrintUsing` sit inside a print item list and
  render it as `USING fmt; v1; v2`, which needs no new node but does need the
  `pend_print`/`pend_using` chain pair to nest.
  **Deliberately not landed**: both affected programs carry IDE toggle `K`, so
  neither can ever be byte-exact, and no comparable program has the shape. This
  is a fidelity gap worth closing when a comparable witness appears, not before.
  `probe_commit_per_statement.bas` pins the thing that makes the diagnosis
  readable: markers are per STATEMENT, not per line — a colon-joined
  `PRINT 1: PRINT 2` emits two.
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
