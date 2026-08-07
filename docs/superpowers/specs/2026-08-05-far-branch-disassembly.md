# Disassembly: follow far jmp/call targets

Status: proposed
Date: 2026-08-05

## Purpose

`tbx.tools.insns.decode_flow` (the control-flow-directed x86 decoder behind
the web UI's disassembly panels) only follows *near* branch/call targets.
On a program compiled under `$SEGMENT` -- code split across more than one
64KB segment, reached via far jumps/calls -- the trace stops dead at the
segment boundary, and everything past it never appears. `tbd73.exe` is the
witness: its `IF`-block preamble ends in `jmp 001Eh:0`, a far jump into a
later segment holding the bulk of the program's real logic (up to file
offset `0x12f5d`; the near-branch-only trace never gets past `0x97b4`).

This spec covers teaching `decode_flow` to follow far jumps and far calls
the same way it already follows near ones, so segment-crossing programs
disassemble as completely as single-segment ones do today.

## Background: the address math already exists and is already tested

This is not new territory for the project. `decode0.scan` resolves the
exact same far branches for its own purposes, and the formulas are proven
against the corpus (including `tbd73.exe` by name):

```python
# tbx/decode0/scan.py, far call (opcode 0x9A)
off, seg = struct.unpack_from("<HH", exe, p + 1)
target = off + seg * 16 + start   # start = file offset of the code prologue

# tbx/decode0/scan.py, far jmp (opcode 0xEA), _scan_far_jump
off, seg = struct.unpack_from("<HH", exe, p + 1)
if off == 0 and seg == 0:
    ...                            # "epilogue": program end, not a real target
elif off == 0:
    target = start + seg * 16      # "segjmp" -- tbd73.exe's exact case
else:
    target = start + seg * 16 + off  # "jmpf"
```

`start` is the same file offset `decode0.find_prologue` returns and
`decode_flow` already takes as a parameter. The segment word is always
relative to that prologue, not the file's absolute segment 0 -- decode0's
comment on the far-call case is explicit that folding in `seg * 16` is a
no-op for every single-segment corpus program and only matters "under
`$SEGMENT` ... its offset restarts, so it is the only way to reach the
right byte (probe t1_segment; wild tbd73.exe)". That's the exact situation
here.

**Reuse this arithmetic directly rather than re-deriving it.** It's already
validated against the fixture corpus and named wild files; independently
re-deriving DOS segment/relocation math in `insns.py` would risk getting a
subtly different (and unvalidated) answer to a problem decode0 has already
solved.

## Scope

In scope:
- `iced_x86` far branch operand kinds for `jmp`, `jcc` (conditional far
  branches don't exist in practice, included for completeness of the
  operand-kind check), and `call` -- `OpKind.FAR_BRANCH16` -- resolved via
  the formulas above and added to `decode_flow`'s worklist the same way a
  near target is.
- The `off == 0 and seg == 0` "epilogue" case: not a real target: treat
  like `decode_insns`/`decode0` do, i.e. don't add it to the worklist
  (it marks program end, not a jump).
- Extending the `[start, end)` range `decode_flow` is bounded to, since a
  far target routinely lands *past* `end` as currently computed (`end =
  max(op[0] for op in ops)` from a single-entry `decode0._scan`, which may
  not itself have walked into the later segment). See "Range" below.

Out of scope:
- Indirect far calls/jumps (`call far [bx]` etc.) -- like near indirect
  branches today, these can't be resolved statically and stay unreached,
  same documented limitation.
- Following into a genuinely different *program* (overlays loaded from a
  separate file) -- out of this program's own EXE bytes entirely. Nothing
  in the corpus does this and it's not implied by anything found so far.
- Changing `decode0` itself. This is purely an `insns.py`/`app.py` change;
  decode0's own far-branch handling is untouched and out of scope.

## Design

### `decode_flow` changes

Add a second branch-kind check alongside the existing near-branch one:

```python
_FAR_BRANCH_KINDS = {FlowControl.UNCONDITIONAL_BRANCH, FlowControl.CALL}
# (no CONDITIONAL_BRANCH: x86 has no far conditional jump)

if fc in _FAR_BRANCH_KINDS and insn.op0_kind == OpKind.FAR_BRANCH16:
    off = insn.far_branch16
    seg = insn.far_branch_selector
    if not (off == 0 and seg == 0):  # not the epilogue marker
        far_target = start + seg * 16 + off
        if start <= far_target < end:
            target = far_target
            worklist.append(far_target)
```

placed as a parallel branch to the existing `NEAR_BRANCH16` check (both
can't be true for the same instruction, so this is an `elif` in practice).
`target` feeds the same label-building (`sub_`/`loc_` in
`Disassembly.tsx`) and jump-to-label UI already built for near targets --
no frontend change needed, a far call/jump gets a label exactly like a
near one once its target resolves.

### Range

Today, `_disassemble_exe` computes `end = max(op[0] for op in ops)` from
one `decode0._scan` pass starting at the single entry point, then passes
`[start, end)` to `decode_flow` as the bound both for "in range" checks and
for how far into the file `Decoder` is allowed to read. A far target can
legitimately land beyond that `end` (that's the whole point -- it's a
later segment `_scan`'s single entry-point walk may not have reached
either, for the same reason `decode_flow` doesn't today).

Two options, in order of preference:

1. **Widen `end` to the far EXE's actual code-region extent** (e.g. up to
   end-of-file, or up to the start of a recognizable DATA pool if
   `decode0.layout` exposes that boundary). Simplest and most robust: lets
   `decode_flow`'s own traversal (which only decodes bytes it actually
   reaches) do the filtering, rather than trying to precompute a tighter
   bound. Risk: if the file has trailing DATA after the last reachable
   code, decode_flow won't walk into it anyway (nothing points at it), so
   over-widening `end` is low-risk by construction.
2. **Re-run `decode0._scan` seeded at each newly-discovered far target**
   and union the resulting `end`s. More precise, more complex, and
   duplicates work `decode_flow`'s own traversal already does at the
   instruction level -- prefer (1) unless it proves to leave real gaps.

Start with (1).

### What "in range" means for a far target

`start <= far_target < end` reuses the widened `end` above. A far target
outside even that widened range (e.g. genuinely into a different overlay
file, or a bogus/corrupted far pointer) resolves to `target = None` --
same fallback as an out-of-range near target today, rendered as a plain
address with no label, not a crash.

## Testing plan

Unit tests in `tests/tbx/test_insns.py`, mirroring the existing near-branch
tests:
- A synthetic far jmp (`0xEA`) to a resolvable in-range target is followed
  and produces a `loc_`/`sub_`-labelable entry.
- The `off == 0, seg == 0` epilogue encoding is *not* treated as a target.
- A far call (`0x9A`) both enters its target *and* falls through to the
  return address (mirrors the existing near-call fallthrough test).
- A far target that resolves outside `[start, end)` yields `target = None`
  rather than raising or silently including an out-of-file address.

Integration: re-run the `tbd73.exe` probe from this session --
`/api/disassembly` on it should now decode instructions past `0x97b4`,
and `decode0`'s own statement addresses (already available via
`/api/decompile`'s `addresses`/`line_starts`) should show substantially
more of the 52 addressed statements landing on an exact decoded
instruction start than today's baseline (1 of 52, recorded in this
session). Record the before/after counts in the PR description rather
than asserting an exact number in a test -- the exact count is incidental
to the fix, not something to pin as a regression guard.

## Open questions

- Does any corpus/wild program have a far branch whose segment word is
  *not* prologue-relative (e.g. an absolute segment fixed up by the DOS
  relocation table, rather than one of decode0's own `$SEGMENT`-relative
  values)? decode0's own handling assumes prologue-relative uniformly and
  that assumption is proven against the corpus, so this is believed
  answered already -- called out here so it isn't silently re-assumed
  without checking if a new far-branch shape shows up during
  implementation.
- Whether to surface, in the UI, that a given label was reached via a far
  branch (crossing a segment) versus a near one -- e.g. `far_sub_` instead
  of `sub_`. Not required for correctness; a cheap, separate follow-up if
  it turns out to help reading the output.
