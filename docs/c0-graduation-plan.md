# Plan: taking the c0 recompiler out of the experimental phase

Status snapshot (2026-07-14): all 564 corpus programs transpile and the
runtime has library and SDL2 build modes, but c0's correctness evidence is
~25 hand-pinned stdout expectations, several constructs still raise for
lack of a semantic witness, and a few semantics silently diverge from real
Turbo Basic. "Experimental" comes off when the evidence standard matches
the decompiler's.

## The enabler: an automated Turbo Basic oracle

A private sister project provides a **headless, automated original-
toolchain oracle**: given a `.BAS`, it compiles it with the real Turbo
Basic 1.1 (or 1.0) under an emulator with no display or manual steps, and
it can run a compiled DOS EXE, script its keyboard input, capture the text
screen, and retrieve files the program wrote. tbx locates it via the
`TBX_ORACLE` environment variable; it is a triage/authoring tool, never
part of the decompile pipeline, and the repo works fully without it.

**Verified**: a corpus fixture's `.bas` compiled through the oracle is
byte-identical to the committed corpus EXE. That closes the loop CLAUDE.md
declares out of scope ("verifying new fixtures requires the original DOS
toolchain, which this repo does not include or automate") — it is now
scriptable.

Design constraints: sources must be CRLF; guest filenames are 8.3; the
compiler caps sources around 64 KB (irrelevant for fixtures); each
emulator boot cycle costs tens of seconds, so oracle runs are for fixture
authoring and one-time golden capture, not per-PR CI.

## Phase 0 — bridge the oracle into tbx

1. `tbx/tools/oracle.py`: thin wrapper over the `TBX_ORACLE` scripts
   exposing `compile_bas(path, dialect="1.1") -> bytes` and
   `run_exe(path, keys=..., timeout=...) -> CapturedOutput`. Fail with a
   clear message when the oracle is absent.
2. Generic run harness on the oracle side: boot, launch the EXE, feed a
   scripted key sequence, snapshot the text screen on exit (with scroll
   handling), and retrieve any files the program created.
3. Byte-exact round-trip automation: `tbx/tools/verify_fixture.py STEM` =
   decompile corpus EXE → emit .BAS → oracle-compile → `cmp` with the
   original. Run it over the existing corpus once as a self-audit; wire it
   into the documented fixture-addition workflow in CLAUDE.md.

Acceptance: `verify_fixture.py t1_print` (and a dozen more, both dialects)
reports byte-identical with no manual emulator steps.

## Phase 1 — differential behavior goldens (the evidence standard)

The c0 analog of the byte-exact rule: **a construct's runtime behavior is
trusted only when the recompiled native output has been compared against
the original EXE running on the real (emulated) machine.**

1. `tbx/tools/dump_dos_output.py`: for each corpus EXE, run it through the
   oracle harness (with a per-stem stdin/keys table for INPUT fixtures —
   `t1_tab` gets "3", etc.) and write `tests/fixtures/dosout/<stem>.txt`
   plus any produced files' bytes. Capture once, commit — like the ops and
   usercode goldens, these encode past verifications.
2. New test layer in `test_c0.py`: for every stem with a dosout golden,
   build the recompiled native binary and compare its output after
   normalization (CRLF; 80-column screen wrap; the documented surrogates —
   e.g. PEEK-of-BIOS reads 0 — get per-stem waivers with a comment naming
   the surrogate).
3. Triage every divergence: either a c0 bug (fix it) or a new documented
   surrogate (waiver). Expect the PRINT layout, rounding, and INPUT echo
   details to produce real findings.

Acceptance: ≥90% of the corpus carries a dosout golden and passes; every
waiver names its surrogate; the ~25 hand-pinned expectations become
derived from (or checked against) captured goldens.

## Phase 2 — close the vocabulary holes with witnesses

Author probe .BAS programs, oracle-compile them (TB 1.1 + TB 1.0 for the
`v10_` pair), oracle-run them to pin semantics, then add them as corpus
fixtures (scan/IR/usercode goldens via the normal regeneration flow) and
implement the c0 lowering:

1. **SUB body variables** — the known blocker (`c0.py`: "no corpus witness
   pins TB's local/shared default"). Probes: assign in main, read in SUB;
   assign in SUB, read in main; STATIC/SHARED declarations; arrays in SUBs
   (SHARED and not). Then delete the `non-parameter variable in SUB` and
   `array access inside SUB` raises.
2. **String DEF FN** (single-line and multi-line, string params).
3. **DIM rank > 2** (rank 3 probe; verify the slot-record layout too).
4. **GOTO/GOSUB/ON ERROR inside procedures** if TB accepts them (probe;
   if the compiler rejects them, document that the raise is unreachable).
5. Sweep the remaining `_Unsupported` sites (`grep "raise _Unsupported"
   tbx/c0.py`) — each either gains a witnessed implementation or a comment
   naming the probe that proved it impossible/illegal in TB.

Acceptance: `test_transpile_coverage_floor` stays 100% over the *grown*
corpus; no `_Unsupported` message is reachable from a program real TB
accepts, or it's documented why.

## Phase 3 — fix the silent divergences

Ordered by user-visible impact:

1. **RND/RANDOMIZE**: capture TB's actual sequence via oracle probes
   (`RANDOMIZE n : PRINT RND; RND; RND` for several seeds), implement the
   exact generator in `terminal.c`, golden-test the sequence. Kills the
   biggest reproducibility divergence (games, procedural graphics).
2. **Binary-safe strings**: migrate the runtime string representation from
   NUL-terminated `char *` to a length-carrying descriptor. This fixes a
   whole class, not one bug: `MKI$(256)` (embedded NUL) stored in a
   variable, FIELD buffers with binary records, `CHR$(0)`, and INKEY$
   extended keys (`CHR$(0)+scan`, today swallowed). Largest single c0
   refactor — touches `tb_runtime.h`, every string helper, and codegen's
   `char *` assumptions; do it behind the Phase 1 goldens so regressions
   surface immediately.
3. **String memory**: with descriptors in hand, add statement-scoped arena
   allocation for temporaries + owned heap copies on variable store,
   replacing "never freed". Removes the short-lived-programs-only caveat.
4. **Bounds/overflow as compiled**: honor `Program.toggles` — the decoder
   already recovers the IDE's Bounds/Overflow flags, so `emit_c` can emit
   `-DTB_BOUNDS`-gated subscript checks (TB error 9) and overflow checks
   (error 6) exactly when the original EXE had them. Matches TB's own
   default-off behavior while eliminating UB divergence for flagged
   programs; the `f*_` corpus fixtures become runnable witnesses.
5. **x87 extended precision**: document as a known divergence (evaluation
   in C double vs TB's 80-bit stack); optionally offer `long double`
   arithmetic on x86 builds if Phase 1 goldens show visible drift.

## Phase 4 — platform CI and the release gate

1. CI matrix for c0: Linux gcc + clang with SDL2 installed (the SDL
   headless test currently always skips in CI), macOS clang, Windows
   MSYS2/MinGW running `test_c0.py` natively; optionally a Wine job using
   an llvm-mingw cross build.
2. Oracle jobs stay out of per-PR CI (minutes per fixture): a documented
   release checklist step re-verifies a sample of dosout goldens and the
   byte-exact round trip.
3. Freeze the runtime interface: `TB_RT_VERSION` in `tb_runtime.h`, a
   `c0_runtime/README.md` spelling out the surrogate contract (emulated
   machine, file devices, event no-ops, SDL behavior) so changing a
   surrogate is a reviewable event like golden regeneration.
4. Drop "experimental" from README/CLI help when: Phase 1 goldens ≥90%
   and green, Phase 2 raises all witnessed-or-documented, Phase 3 items
   1–4 landed, CI matrix green.

## Sequencing and effort

Phase 0 unblocks everything and is mostly adapting working code (~days).
Phase 1 is the core investment: harness generalization plus one long
capture sweep, then triage. Phase 2 rides on Phase 0's authoring loop
(each probe ~minutes of oracle time). Phase 3 items 1 and 4 are small and
independent; items 2–3 are the big refactor and should land mid-plan,
after goldens exist to catch regressions. Phase 4 is configuration work.

Biggest risks: screen-capture fidelity for console output (mitigate by
preferring file-writing probes and keeping per-stem key scripts simple)
and the string-descriptor refactor's blast radius (mitigate: land after
Phase 1, behind the full golden suite).
