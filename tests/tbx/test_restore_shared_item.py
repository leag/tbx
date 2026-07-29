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

**Why this is a guard and not a mapping.** Which index space WOULD place those
targets is not determined. Two rules were tested against wild styled.exe (221
pool descriptors, 135 code-referenced, 86 recovered as DATA, targets
{0, 48, 61, 87}) and both were eliminated:

- *The unreferenced descriptors span one contiguous run, shared items
  included.* Arithmetically it fits -- the span is exactly 100 descriptors with
  14 shared ones inside it, and all four targets land in range -- but the
  target at item 61 then resolves to `'     1st/last before/after pn    '`, a
  PRINT-layout string, and a DATA statement is implausible as the thing that
  opens with it. It also fails outright on the probe, whose only shared item
  sits at the TOP of the run and so outside the unref span entirely.
- *The index counts every pool descriptor down from the highest disp.* This
  works on the probe and agrees with `t1_restoreline`, but on styled.exe it
  puts item 0 inside the trailing 97-descriptor run of code-only literals.

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
