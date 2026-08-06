import pytest

try:
    from tbx.tools import insns

    _INSNS_AVAILABLE = True
except ImportError:
    _INSNS_AVAILABLE = False

pytestmark = pytest.mark.skipif(not _INSNS_AVAILABLE, reason="iced-x86 debug extra not installed")


def test_decode_flow_straight_line():
    code = bytes([0x90, 0xB0, 0x01, 0xC3])  # nop; mov al,1; ret
    lines = insns.decode_flow(code, 0, len(code))

    assert [addr for addr, _kind, _text, _target in lines] == [0, 1, 3]


def test_decode_flow_records_branch_target():
    # nop; mov al,1; jmp short -3 (back to nop)
    code = bytes([0x90, 0xB0, 0x01, 0xEB, 0xFB])
    lines = insns.decode_flow(code, 0, len(code))

    by_addr = {addr: (text, target) for addr, _kind, text, target in lines}
    assert by_addr[3][1] == 0


def test_decode_flow_reaches_target_a_linear_sweep_would_skip():
    # nop; mov al,90h (2 bytes: B0 90 -- its 2nd byte, 0x90, is itself a
    # valid one-byte NOP); jmp short 0002h (targets that same byte,
    # decoded on its own as the instruction starting there).
    #
    # A byte-by-byte sweep from 0 never visits address 2 at all: it falls
    # through 0 -> 1, decodes the 2-byte `mov al,90h` there, and continues
    # at 3 -- consuming the very byte the jump targets as someone else's
    # operand. Flow-directed decode reaches address 2 directly because the
    # jump names it explicitly, regardless of what the fallthrough chain
    # decoded first.
    code = bytes([0x90, 0xB0, 0x90, 0xEB, 0xFD])
    lines = insns.decode_flow(code, 0, len(code))

    addresses = {addr for addr, _kind, _text, _target in lines}
    assert 2 in addresses

    by_addr = {addr: (text, target) for addr, _kind, text, target in lines}
    assert by_addr[3][1] == 2


def test_decode_flow_stops_at_unconditional_branch():
    # jmp short 0003h skips clean over the byte at address 2 (0xFF, which
    # would otherwise decode as the start of some multi-byte instruction
    # if fallthrough from the jump were wrongly followed too).
    code = bytes([0xEB, 0x01, 0xFF, 0x90])
    lines = insns.decode_flow(code, 0, len(code))

    addresses = {addr for addr, _kind, _text, _target in lines}
    assert 2 not in addresses
    assert 3 in addresses


def test_decode_flow_ignores_out_of_range_target():
    # jmp short well past the end of the given range -- should not be
    # treated as a resolvable target, and should not raise.
    code = bytes([0xEB, 0x7F])
    lines = insns.decode_flow(code, 0, len(code))

    by_addr = {addr: (text, target) for addr, _kind, text, target in lines}
    assert by_addr[0][1] is None


def test_decode_flow_uses_op_starts_to_skip_inline_argument_bytes():
    # int 0ECh (2 bytes); 1 inline argument byte the interrupt handler
    # consumes at runtime (0xAA, chosen so it'd decode as a bogus `stosb`
    # if iced were left to decode it as an instruction); mov al,1 -- the
    # real next instruction, at offset 3.
    #
    # Without op_starts, iced's naive int-fallthrough (offset 2) decodes
    # the argument byte as its own (bogus) instruction and never reaches
    # offset 3 as a distinct entry with the right text. With op_starts
    # saying this whole op runs 0..3, decode_flow should skip straight to
    # the real next instruction.
    code = bytes([0xCD, 0xEC, 0xAA, 0xB0, 0x01])  # int 0ECh; AA; mov al,1
    lines = insns.decode_flow(code, 0, len(code), op_starts=[0, 3])

    by_addr = {addr: text for addr, _kind, text, _target in lines}
    assert 2 not in by_addr
    assert by_addr[3] == "mov al,1"


def test_decode_flow_op_starts_does_not_shrink_a_shorter_real_op():
    # int 0ECh with NO inline argument this time (op_starts says the op is
    # exactly the 2-byte int) -- op_starts must never make decode_flow skip
    # past real code that's already there.
    code = bytes([0xCD, 0xEC, 0xB0, 0x01])  # int 0ECh; mov al,1
    lines = insns.decode_flow(code, 0, len(code), op_starts=[0, 2])

    by_addr = {addr: text for addr, _kind, text, _target in lines}
    assert by_addr[2] == "mov al,1"


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
