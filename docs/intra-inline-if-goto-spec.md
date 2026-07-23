# Spec: intra-inline-IF-body GOTO targets

Status: 2026-07-22, investigation-only — no code changes yet. This
supersedes the "SUB/DEF FN body" framing in `HANDOFF.md`'s `6f1a9fb`
diagnosis commit, which was **factually wrong about the mechanism**
(corrected in `HANDOFF.md` alongside this spec — see "Correction" below).

## Problem statement

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

## Confirmed facts (traced this session, `state.exe`)

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
   `HANDOFF.md`** from an earlier session (search for "Intra-inline-IF-body
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

## The machinery that *should* already handle this, and doesn't (yet)

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

## Recommended investigation plan

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
   project's own established lesson (HANDOFF.md, the `796c9c0`-era
   "re-run the FULL WILD SCAN before declaring done" note) applies
   directly here.
5. Once `state.exe`/`state87.exe` close, re-check `secure.exe`'s own
   occurrence of the same error message — confirm (don't assume) it's
   actually the same shape before declaring it closed too.

## Explicitly out of scope for this spec

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

## Why this matters / acceptance criteria

- `state.exe`/`state87.exe` (and possibly `secure.exe`) decode completely.
- No regression anywhere in the existing 2407-test suite or the 84-file
  wild scan.
- The fix is provably narrow: it should be possible to point at the exact
  condition in `_body_has_target`/`_fold_if` that was wrong, with a
  before/after trace on the new minimal probe, not just "the crash went
  away."
- `HANDOFF.md` gets a real, dated closure writeup (matching this
  project's own convention) once landed, including which of the three
  candidate causes above (or a fourth, if the trace finds something
  different) was the actual one.
