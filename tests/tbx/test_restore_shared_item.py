"""A DATA item that reuses a code literal's text is dropped from the pool.

`data_items` recovers DATA by EXCLUSION: pool descriptors that no code site
references. The compiler emits ONE descriptor per distinct piece of text, so a
DATA item whose text is identical to a string literal used in code shares that
descriptor, counts as code-referenced, and never reaches the item list. Every
later item index shifts down, and a `RESTORE <line>` naming one of the highest
ones has nowhere to land.

Seven lines reproduce it (`probe_datadup`): `DATA ONE` / `DATA TWO` /
`PRINT "ONE"` / `RESTORE 20`. 'ONE' is shared with the PRINT, one item is
recovered instead of two, and `RESTORE 20`'s target -- item index 1, the
calibrated encoding being imm/2 over source item order, as `t1_restoreline`
pins -- is past the end.

**Why this is a guard and not yet a mapping.** Exclusion is the wrong mechanism
outright, and `probe_datamid` shows why: with `DATA AAA` / `PRINT "MIDDLE"` /
`DATA BBB`, the code-only literal 'MIDDLE' lands at descriptor index 1, BETWEEN
'AAA' (2) and 'BBB' (0). The pool is in source first-appearance order and
interleaves DATA items with code literals, so DATA descriptors are not
contiguous and `RESTORE` cannot be indexing the pool at all.

The runtime carries an explicit DATA pointer table instead -- a word per DATA
item, in source order, holding its descriptor disp, skipping code-only literals
and including shared ones. It has been located in all three witnesses (94
entries for wild styled.exe against the 86 recovered by exclusion, 8 of them
shared; its four RESTORE splits resolve to 'ACCORDINGLY', 'UNLESS', 'AM',
'ING', matching the four word categories that program prints headers for).
Reading it is the real fix; what is missing is only a principled way to FIND
it, since its DGROUP disp is neither fixed nor at a constant offset from
`pool_base`. The search that located it -- longest run of valid descriptor disps
-- is a heuristic a coincidental run could win, so it is not landed.

So the decoder refuses. What this test fixes is that it refuses *loudly*: the
failure used to be a bare `KeyError`, which is not a `ValueError` and so
escaped `decode_user_code`'s wrapper without collecting any phase context --
leaving the wild scan to report the raw index as the program's entire failure
signature (styled.exe and styllist.exe both grouped under `87`).
"""

from pathlib import Path

import pytest

from tbx import decode0

_ROOT = Path(__file__).resolve().parents[2]


def test_the_calibrated_encoding_still_resolves():
    """`t1_restoreline` is what pins imm/2 as a source item index.

    `DATA 7` / `DATA 8,9` / `RESTORE 20` -> target item 1, which opens the
    second DATA statement. Nothing here may disturb that.
    """
    exe = (_ROOT / "tests" / "fixtures" / "corpus" / "t1_restoreline.exe").read_bytes()

    source = "\n".join(str(s) for s in decode0.decode_user_code(exe))

    assert "Restore" in source


def test_a_shared_data_item_is_refused_rather_than_dropped_silently():
    """The probe: one shared item, so target 1 is past the end."""
    exe = (_ROOT / "wild" / "probes" / "probe_datadup.exe").read_bytes()

    with pytest.raises(ValueError, match=r"RESTORE item index 1 is past the 1 "):
        decode0.decode_user_code(exe)


def test_the_refusal_is_a_valueerror_carrying_phase_context():
    """A KeyError here would bypass the fail-loud contract entirely.

    `decode_user_code` annotates `ValueError` only, so the crash this replaces
    reached the CLI with no phase, offset or op trail at all.
    """
    exe = (_ROOT / "wild" / "probes" / "probe_datadup.exe").read_bytes()

    with pytest.raises(ValueError) as caught:
        decode0.decode_user_code(exe)

    message = str(caught.value)
    assert "[phase=finalize" in message
    # Names the mechanism, so the report points at the pool recovery rather
    # than at whatever statement happened to be in flight.
    assert "sharing a descriptor with a code string literal" in message


@pytest.mark.parametrize("name", ("styled.exe", "styllist.exe"))
def test_the_wild_witnesses_report_the_cause_not_a_bare_index(name):
    """Both used to surface as the signature `87` and nothing else."""
    hits = _ROOT / "wild" / "hits" / name
    if not hits.is_file():  # wild/hits is gitignored
        pytest.skip(f"{name} not present")

    with pytest.raises(ValueError) as caught:
        decode0.decode_user_code(hits.read_bytes())

    message = str(caught.value)
    assert "RESTORE item index 87 is past the 86 recovered DATA items" in message


def test_the_two_witnesses_share_one_triage_signature():
    """Both must group together in the scan tally, which keys on the message.

    `failure_signature` collapses a message from ` at 0x...` to the end, so a
    message without that marker keeps its whole `[phase=...]` trailer in the
    key and each witness reads as its own singleton -- which would mis-rank the
    family against every other open gap. Asserted through the real normalizer
    rather than by trimming the string here.
    """
    from tbx.tools.scan_wild import failure_signature

    names = ("styled.exe", "styllist.exe")
    paths = [_ROOT / "wild" / "hits" / n for n in names]
    if not all(p.is_file() for p in paths):  # wild/hits is gitignored
        pytest.skip("wild witnesses not present")

    signatures = set()
    for p in paths:
        with pytest.raises(ValueError) as caught:
            decode0.decode_user_code(p.read_bytes())
        signatures.add(failure_signature(str(caught.value)))

    assert len(signatures) == 1, signatures
    assert "0x" not in signatures.pop()


def test_a_code_only_literal_sits_between_two_data_items():
    """The structural fact that rules out every pool-order index rule.

    `probe_datamid` is `DATA AAA` / `PRINT "MIDDLE"` / `DATA BBB`. 'MIDDLE' is
    never a DATA item, yet its descriptor lands between the two that are -- so
    the pool is in source first-appearance order and DATA is not a contiguous
    run in it. Pinned because re-deriving it costs an oracle compile, and
    because any future "the DATA items are the span from X to Y" idea has to
    fail this test first.

    Exclusion still gets the ITEMS right here (nothing is shared), which is why
    this probe decodes: the bug needs a shared descriptor, not merely an
    interleaved one.
    """
    exe = (_ROOT / "wild" / "probes" / "probe_datamid.exe").read_bytes()

    source = "\n".join(str(s) for s in decode0.decode_user_code(exe))

    assert "'AAA'" in source and "'BBB'" in source, source
    # MIDDLE is a PRINT operand, never a DataItem.
    assert "DataItem(text='MIDDLE'" not in source, source


def test_two_data_statements_without_a_restore_collapse_into_one():
    """A separate, still-open gap, recorded here because the probe shows it.

    Statement boundaries come only from RESTORE targets or from
    `data_orphan_lines`. With a READ present and no `RESTORE <line>` there is
    neither, so `splits` collapses to {0} and both source DATA statements merge
    into one. The DATA statement count and each one's line ARE byte-significant
    (probes q_lt3/q_lt4), so this probe recompiles 14 bytes different and is
    therefore NOT promoted to the corpus. The pointer table above would not fix
    it either -- that recovers items, not boundaries.
    """
    exe = (_ROOT / "wild" / "probes" / "probe_datamid.exe").read_bytes()

    datas = [s for s in decode0.decode_user_code(exe) if type(s).__name__ == "Data"]

    assert len(datas) == 1, datas  # source had two, at lines 10 and 30
    assert len(datas[0].items) == 2, datas
