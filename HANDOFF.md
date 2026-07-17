# Wild-corpus gap campaign — handoff

Status as of 2026-07-17, branch `claude/claude-md-docs-mr8ssz`.
Standing instruction: close the most common decoder gap first, in frequency
order, over the 84 wild PC-SIG Turbo Basic EXEs in `wild/hits/` (untracked,
gitignored, copyrighted shareware — **never commit them**).

## Where things stand

`python -m tbx.tools.scan_wild wild/hits` — 84 EXEs: 2 decode OK, 82 fail.
Current tally (post gap 15):

| count | error | status |
|---|---|---|
| 15 | INT cd | unwitnessable runtime-revision artifact — not actionable (see `scan_wild.py` docstring) |
| 5 | DGROUP layout not solvable | **gap 16, needs fresh diagnosis — see below** (gap 15's shape closed, but none of the 5 wild files actually had it) |
| 4 | byte 90 | set aside: unwitnessable FWAIT-revision skew (3 probe variants all compile INT 3Dh) |
| 3 each | INT EC sub c4, byte ea, ce, 83, 81, 26 | next tier, undiagnosed |
| 2 each | EC sub 66, INT 8c, FP dc/04, byte ff, 8c, 3b, 29, 03, 01 | then singles |

## Recently closed (this campaign, newest first)

- **Gap 15, static string array at constant index** (this session): static
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

## Gap 16 — schart/hfprop/vhfprop/inv87/invoice, UNDIAGNOSED

The 5 wild "DGROUP layout not solvable" files did NOT advance after gap
15's fix landed. Traced schart.exe in detail (instrumented `layout._layout`
with temporary debug prints, since removed): the "no runtime arrays"
walk-based solver (`_layout`'s `for n in range(31, -1, -1)` loop) never
finds a consistent `(ds, n, statics)` triple for ANY `n` from 0 to 31 —
`find_statics` returns `None` for most `n`, and the handful of `n` where it
does return statics (9, 7, 6, 4, 3, 2, 1, 0) all produce bogus/spurious
array records (huge implausible bases like `0xc8a0`-`0xc960`, none of them
`str`-typed) that don't include a string array whose span covers the
movsi disp `0x600` referenced in the ops. That disp is never explained as
either a scalar, a pool descriptor, or (in any candidate reached) a string
array element.

This means schart.exe's real DGROUP shape doesn't fit the existing
walk-anchored solve strategy at all — likely something structurally
different (not just "add one more exemption"), e.g.: array element storage
interleaved with or ahead of the scalar walk in a way the `dc`-driven
`pool_base` formula doesn't model, a second/nested array region, or this
file actually needs the `rt_blocks` (runtime-DIM) anchor path but isn't
tripping it. Needs fresh evidence-set analysis (`tbx FILE --ops`,
`cfgview`, hexdump around disp 0x600 and its file offset) before attempting
another fix — do not assume it's a small tweak.

hfprop/vhfprop/inv87/invoice are untested against this specific finding;
they may or may not share schart's exact shape.

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
