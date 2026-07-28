from tbx.decode0.matchers import match_delay
from tbx.decode0.cursor import OpCursor


def test_match_delay_returns_consumption_and_hook_facts():
    ops = [
        (0x10, "delay_init"),
        (0x11, "trap_hook", 100),
        (0x12, "delay_poll"),
        (0x13, "jcc", 0x75, 0x11),
        (0x14, "end"),
    ]

    match = match_delay(ops, 0)

    assert match is not None
    assert match.hooks == (ops[1],)
    assert match.loop_back == 0x11
    assert match.stop == 4
    assert match_delay(OpCursor(ops)) == match


def test_match_delay_rejects_near_misses_without_mutation():
    ops = [(0x10, "delay_init"), (0x11, "delay_poll"), (0x12, "jmp", 0x99)]
    before = list(ops)

    assert match_delay(ops, 0) is None
    assert ops == before
    assert match_delay(ops, 1) is None
