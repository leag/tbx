# Far jmp/call following in decode_flow: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** `docs/superpowers/specs/2026-08-05-far-branch-disassembly.md`

**Goal:** `tbx.tools.insns.decode_flow` follows far `jmp`/`call` targets the
same way it already follows near ones, so a `$SEGMENT` program's
disassembly (web UI's "Original disassembly" / "Recompiled disassembly" /
"Disassembly diff" panels) doesn't stop dead at the first segment
boundary. Witnessed gap: `tbd73.exe` decodes only 1 of its 52 addressed
statements to an exact instruction start today, because its `IF`-block
preamble ends in a far `jmp 001Eh:0` into a later segment holding the rest
of the program.

**Architecture:** Pure addition to `tbx/tools/insns.py` (`decode_flow`) and
`tbx/web/app.py` (`_disassemble_exe`'s range computation). No change to
`tbx.decode0`, `tbx.emit0`, or the frontend — far targets flow through the
same `target: int | None` field the UI already renders labels and
jump-to-label links from.

## Global Constraints

- Reuse decode0's own far-branch address math (`start + seg * 16 + off`
  for a far jmp/call; `off == 0, seg == 0` is the "epilogue", not a
  target) rather than re-deriving DOS segment/relocation math — that
  arithmetic is already proven against the fixture corpus and named wild
  files in `tbx/decode0/scan.py`.
- `decode_flow`'s existing behavior for near branches, indirect branches,
  and out-of-range targets must not change. All existing tests in
  `tests/tbx/test_insns.py` and `tests/tbx/test_web_api.py` stay green
  throughout.
- No new dependency, no new API field. `target` was already `int | None`;
  a far target populates the same field a near one does.

---

## File Structure

```
tbx/tools/insns.py     # decode_flow: add far-branch resolution
tbx/web/app.py          # _disassemble_exe: widen the disassembly range
tests/tbx/test_insns.py # new far-branch unit tests
tests/tbx/test_web_api.py  # widened-range regression test
```

---

### Task 1: Resolve far jmp/call targets in `decode_flow`

**Files:**
- Modify: `tbx/tools/insns.py`
- Test: `tests/tbx/test_insns.py`

**Interfaces:**
- Consumes: `insn.op0_kind == OpKind.FAR_BRANCH16`, `insn.far_branch16`
  (offset), `insn.far_branch_selector` (segment) — both already confirmed
  present on `iced_x86`'s decoded `Instruction`.
- Produces: the existing `decode_flow` return shape, unchanged
  (`list[tuple[int, str, str, int | None]]`) — far targets populate the
  same `target` slot a near target does, and get added to the internal
  traversal worklist the same way.

This task lands the pure address-resolution logic against a byte range
`decode_flow` is already given wide enough to include the far target — the
worklist/traversal mechanics don't change at all here. Task 2 handles the
`_disassemble_exe` caller actually widening that range for real files;
here, tests pass `end` generously by hand.

- [ ] **Step 1: Write the failing tests**

```python
# tests/tbx/test_insns.py -- add alongside the existing decode_flow tests

def test_decode_flow_follows_a_far_jump():
    # jmp far 0000h:0008h (opcode EA, off=8, seg=0); start=0 so the
    # resolved target is 0 + 0*16 + 8 = 8. nop at offset 8 confirms it
    # was actually reached, not just resolved.
    code = bytes([0xEA, 0x08, 0x00, 0x00, 0x00]) + bytes(3) + bytes([0x90])
    lines = insns.decode_flow(code, 0, len(code))

    by_addr = {addr: (text, target) for addr, _kind, text, target in lines}
    assert by_addr[0][1] == 8
    assert 8 in by_addr


def test_decode_flow_far_jump_zero_zero_is_not_a_target():
    # jmp far 0000h:0000h -- decode0's "epilogue" sentinel, not a real
    # target. Must not be added to the worklist (would just re-decode the
    # jmp itself, or -- since start=0 -- appear to "target itself").
    code = bytes([0xEA, 0x00, 0x00, 0x00, 0x00])
    lines = insns.decode_flow(code, 0, len(code))

    by_addr = {addr: (text, target) for addr, _kind, text, target in lines}
    assert by_addr[0][1] is None


def test_decode_flow_far_call_enters_target_and_falls_through():
    # call far 0000h:0008h (opcode 9A); nop at the return address (5, the
    # call's own length); nop at the far target (8).
    code = bytes([0x9A, 0x08, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x90])
    lines = insns.decode_flow(code, 0, len(code))

    addresses = {addr for addr, _kind, _text, _target in lines}
    assert 5 in addresses  # fallthrough (return address)
    assert 8 in addresses  # far call target


def test_decode_flow_far_target_outside_range_resolves_to_none():
    # jmp far 0100h:0000h -- off=0, seg=0x100 -> target = 0x100*16 = 4096,
    # well outside a 16-byte range. Must not raise, and must not be
    # treated as a resolvable target.
    code = bytes([0xEA, 0x00, 0x00, 0x00, 0x01]) + bytes(11)
    lines = insns.decode_flow(code, 0, len(code))

    by_addr = {addr: (text, target) for addr, _kind, text, target in lines}
    assert by_addr[0][1] is None
```

Run them; confirm all four fail (far branches currently produce
`target=None` unconditionally and never get added to the worklist).

- [ ] **Step 2: Implement**

In `tbx/tools/insns.py`, alongside the existing `_BRANCH_KINDS` /
near-branch resolution block in `decode_flow`:

```python
# Far jmp/call: x86 has no far conditional jump, so CONDITIONAL_BRANCH is
# deliberately not in this set (unlike _BRANCH_KINDS for near branches).
_FAR_BRANCH_KINDS = {FlowControl.UNCONDITIONAL_BRANCH, FlowControl.CALL}
```

and inside the main loop, as an `elif` alongside the existing
`if fc in _BRANCH_KINDS and insn.op0_kind == OpKind.NEAR_BRANCH16:` block:

```python
elif fc in _FAR_BRANCH_KINDS and insn.op0_kind == OpKind.FAR_BRANCH16:
    off, seg = insn.far_branch16, insn.far_branch_selector
    if not (off == 0 and seg == 0):  # decode0's "epilogue" sentinel
        far_target = start + seg * 16 + off
        if start <= far_target < end:
            target = far_target
            worklist.append(far_target)
```

Update the `decode_flow` docstring to mention far-branch support (the
spec's "Background" section has the wording to draw from).

- [ ] **Step 3: Run and confirm green**

```sh
uv run pytest tests/tbx/test_insns.py -q
```

All tests pass, including the four new ones and every pre-existing one
(no near-branch/indirect/out-of-range behavior changed).

---

### Task 2: Widen the disassembly range so real far targets aren't dropped

**Files:**
- Modify: `tbx/web/app.py` (`_disassemble_exe`)
- Test: `tests/tbx/test_web_api.py`

**Interfaces:**
- Consumes: nothing new — same `exe_bytes` `_disassemble_exe` already has.
- Produces: same `/api/disassembly` response shape.

Per the spec's "Range" section, take option 1: widen `end` rather than
re-running `decode0._scan` per discovered far target. `decode_flow` only
ever decodes bytes it actually reaches via a real control-flow edge, so a
generous `end` costs nothing — nothing points into stray trailing data,
it just never gets visited.

- [ ] **Step 1: Write the failing test**

```python
# tests/tbx/test_web_api.py

@pytest.mark.skipif(not _iced_x86_available(), reason="iced-x86 debug extra not installed")
def test_disassembly_reaches_code_past_a_far_jump_on_tbd73():
    wild_path = Path(__file__).parent.parent.parent / "wild" / "hits" / "tbd73.exe"
    if not wild_path.exists():
        pytest.skip("wild/hits/tbd73.exe not present locally")

    decompile_response = client.post(
        "/api/decompile", files={"exe": ("tbd73.exe", wild_path.read_bytes())}
    )
    session_id = decompile_response.json()["session_id"]

    response = client.post("/api/disassembly", json={"session_id": session_id})

    instructions = response.json()["instructions"]
    addresses = {i["address"] for i in instructions}
    # 0x97b4 is the far jmp itself (today's last reached instruction);
    # real code beyond the segment boundary it jumps into starts well
    # past it once far jumps are followed. Exact address chosen from this
    # session's probe of the file, not a magic number invented for the
    # test.
    assert max(addresses) > 0x97B4
```

Run it; confirm it fails against today's code (`max(addresses)` tops out
at `0x97b4`, the far jmp instruction itself).

- [ ] **Step 2: Implement**

In `_disassemble_exe`, widen `end` before calling `decode_flow`:

```python
# A far jmp/call can legitimately target code past this single-entry
# scan's own reach (that's the point of following it) -- widen the bound
# decode_flow is allowed to decode into. decode_flow only ever decodes
# bytes an actual control-flow edge leads to, so a generous bound costs
# nothing: nothing points into real trailing data, so it's never visited.
end = len(exe_bytes)
```

replacing the current `end = max(op[0] for op in ops) if ops else start`
line -- keep computing `ops`/`op_starts` exactly as today (still needed
for the inline-argument-byte fix), just stop using `ops` to bound `end`.

- [ ] **Step 3: Run and confirm green**

```sh
uv run pytest tests/tbx/test_web_api.py -q
```

All tests pass, including the new one. Also re-run the full
`test_insns.py` + `test_web_api.py` + `test_emit_line_starts.py` set to
confirm nothing regressed:

```sh
uv run pytest tests/tbx/test_insns.py tests/tbx/test_web_api.py tests/tbx/test_emit_line_starts.py -q
```

---

### Task 3: Verify against tbd73.exe and record the before/after

**Files:** none (verification only, no code change)

Per the spec's testing plan, this is a probe against the actual wild file,
not a pinned regression assertion (the exact instruction/coverage count is
incidental to the fix). Steps:

- [ ] **Step 1: Re-run the exact probe from the 2026-08-05 session**

```sh
.venv/bin/python -c "
from fastapi.testclient import TestClient
from tbx.web.app import app
client = TestClient(app)
data = open('wild/hits/tbd73.exe', 'rb').read()
r = client.post('/api/decompile', files={'exe': ('tbd73.exe', data)})
body = r.json()
sid = body['session_id']
addrs = [a for a in body['addresses'] if a is not None]
d = client.post('/api/disassembly', json={'session_id': sid})
instr = d.json()['instructions']
iaddrs = set(i['address'] for i in instr)
covered = sum(1 for a in addrs if a in iaddrs)
print('decoded instructions:', len(instr))
print('statements with address:', len(addrs), 'exact match:', covered)
"
```

Record the new counts (baseline before this plan: 143 decoded
instructions, 1 of 52 addressed statements landing on an exact decoded
instruction start). Expect both numbers to increase substantially now
that the later segment is reachable.

- [ ] **Step 2: Verify live in the browser**

Upload `wild/hits/tbd73.exe`, recompile, and check the "Original
disassembly" / "Disassembly diff" panels show code past `0x97b4` with
correctly-labeled far jump/call targets (`loc_`/`sub_` prefix, clickable
jump-to icon) — no frontend change is expected to be needed, since far
targets flow through the same `target` field near ones already do.

- [ ] **Step 3: Full test suite**

```sh
uv run pytest -q
```

Confirm the only failures are the pre-existing, unrelated
`test_wild_subset.py` / `test_emitted_source_width.py` baseline failures
already tracked from before this work (not anything newly broken by it).

---

## Explicitly Deferred (per spec's "Out of scope")

- Indirect far calls/jumps (`call far [bx]` etc.) — stay unreached, same
  as near indirect branches today.
- Cross-file overlays — out of scope, nothing in the corpus implies it.
- Surfacing "reached via a far branch" distinctly in the UI (e.g.
  `far_sub_` vs `sub_` labels) — a cheap, separate follow-up if it turns
  out to help reading the output; not required for correctness.
