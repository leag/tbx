"""Exclusion decides whether a mismatch is a failure, not whether to look.

Two emitter bugs -- a dropped `PRINT ,,` and an `EOF(n)` truth test spelled as
a comparison -- lived in wild pz.exe for as long as the corpus has had it, and
the harness never saw them: `verify` returned `skip:` before compiling, because
pz carries an IDE toggle -- and a runtime revision this oracle does not have,
which is the part that really does put byte-exactness out of reach. Its USER
code is still ours, and compiling it is what found both.

So the reasons now annotate the result instead of replacing it, and only a
program that COULD have been exact counts against the tally.
"""

from tbx.tools import verify_wild


class _Prog(list):
    toggles = ""


def _prog(toggles=""):
    p = _Prog()
    p.toggles = toggles
    return p


def test_a_clean_program_has_no_reason():
    data = (verify_wild._ROOT / "tests/fixtures/corpus/t1_ifgoto.exe").read_bytes()
    assert verify_wild.unreachable_reason(data, _prog(), "1.1") is None


def test_a_code_bearing_toggle_is_a_reason_but_not_a_skip():
    data = (verify_wild._ROOT / "tests/fixtures/corpus/t1_ifgoto.exe").read_bytes()
    reason = verify_wild.unreachable_reason(data, _prog("B"), "1.1")
    assert reason and "Bounds" in reason


def test_keyboard_break_alone_is_not_a_reason():
    # K leaves ONLY the flags mask -- one byte, no inserted code -- so the
    # program is judged with that byte normalized rather than excused.
    data = (verify_wild._ROOT / "tests/fixtures/corpus/t1_ifgoto.exe").read_bytes()
    assert verify_wild.unreachable_reason(data, _prog("K"), "1.1") is None
    assert verify_wild.unreachable_reason(data, _prog("KB"), "1.1") is not None


def test_a_wrong_build_is_a_reason():
    # A 1.0 program judged against 1.1 is the shape that used to hide 16
    # programs; here it is forced, to pin that the reason is still produced.
    data = (verify_wild._ROOT / "tests/fixtures/corpus/v10_t1_ifgoto.exe").read_bytes()
    reason = verify_wild.unreachable_reason(data, _prog(), "1.1")
    assert reason and "different Turbo Basic build" in reason
    # ...and against its own dialect there is no reason at all.
    assert verify_wild.unreachable_reason(data, _prog(), "1.0") is None


def test_an_expected_mismatch_does_not_count_against_the_tally():
    marked = "1096 bytes off (96.85% identical), delta +0  [expected: Options toggles K]"
    plain = "1096 bytes off (96.85% identical), delta +0"
    def counts(r):
        return not r.startswith(("exact", "skip:")) and "[expected:" not in r

    assert not counts(marked)
    assert counts(plain)
    assert not counts("exact")
