# Wild-corpus gap campaign — handoff

Status as of 2026-07-16, branch `claude/claude-md-docs-mr8ssz` (clean, pushed).
Standing instruction: close the most common decoder gap first, in frequency
order, over the 84 wild PC-SIG Turbo Basic EXEs in `wild/hits/` (untracked,
gitignored, copyrighted shareware — **never commit them**).

## Where things stand

`python -m tbx.tools.scan_wild wild/hits` — 84 EXEs: 2 decode OK, 82 fail.
Current tally (post gap 14):

| count | error | status |
|---|---|---|
| 15 | INT cd | unwitnessable runtime-revision artifact — not actionable (see `scan_wild.py` docstring) |
| 5 | DGROUP layout not solvable | **gap 15, diagnosed — see below** |
| 4 | byte 90 | set aside: unwitnessable FWAIT-revision skew (3 probe variants all compile INT 3Dh) |
| 3 each | INT EC sub c4, byte ea, ce, 83, 81, 26 | next tier, undiagnosed |
| 2 each | EC sub 66, INT 8c, FP dc/04, byte ff, 8c, 3b, 29, 03, 01 | then singles |

## Recently closed (this campaign, newest first)

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

## Gap 15 — diagnosed, NOT yet implemented

**Shape**: static string array accessed at a constant index. Reproducer
(oracle-compiled it fails with "DGROUP layout not solvable"):

```basic
10 DIM A$(5)
20 A$(2) = "HI"
30 B$ = A$(2)
40 PRINT B$
50 END
```

**Cause**: the element access compiles `movsi <array_base + 4*index>`; that
disp is neither a scalar slot nor a pool descriptor, and `layout.py`'s
`finish` descriptor check exempts static-array spans only for fp/int
evidence, never movsi.

**Fix plan**:
1. In `finish`, exempt movsi disps landing inside a **string** static
   array's span (`rec["str"]`, type byte 0x0A in
   `datapool._parse_static_slot`).
2. In `core.py`'s movsi handler (~line 1836) route span-hitting disps
   through `state.loc(d)` — `loc` already returns `ArrayRef` for span
   disps — on both the read (`rt 0x9C` push) and write (`strassign`) legs;
   also the `state.loc(d) if d in strs else _pool_str(d)` dispatch nearby.
3. Oracle byte-exact verify the probe, promote as `t1_sstat`, regenerate
   goldens (diffs must be additive-only), capture dosout, pin test, full
   suite + ruff + ty, commit, re-scan.

Wild schart.exe (movsi 0x600 inside a string static's span) should advance;
hfprop/vhfprop/inv87/invoice likely share the shape.

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
