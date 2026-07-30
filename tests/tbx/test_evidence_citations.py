"""The evidence a docstring cites still exists.

The decoder is calibrated, not inferred, and the citations are how that shows:
a handler says which compiled fixture witnesses its shape and which wild EXE
first needed it. Those names are the only route from a rule back to the bytes
that justify it, and the whole method rests on being able to walk it.

Nothing checks a name, so nothing stops one from rotting. Three had:
`t1_byrefonlyarg` for `t1_argrefonly` (a transposition), `t1_tron_troff` for a
fixture that never existed, and `t1_nestif` for a path no fixture reaches at
all -- the last being a calibration gap the citation was quietly hiding.

This is `test_architecture_doc.py`'s rule applied to the citations instead of
the map: the parts that are facts about the repository are checked against the
repository. Whether a fixture really witnesses what it is cited for is not
checkable here and stays a matter of review.
"""

import glob
import os
import re

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CORPUS = os.path.join(_ROOT, "fixtures", "corpus")
_SOURCE = sorted(
    glob.glob(os.path.join(_ROOT, os.pardir, "tbx", "**", "*.py"), recursive=True)
)

#: Fixture stems as they are written in prose. The corpus spells a dialect with
#: a `v10_` prefix and an IDE-toggle build with `f<letters>_`, and both appear
#: in citations, so the pattern has to admit them to see the whole population.
_FIXTURE = re.compile(r"\b((?:v10_)?(?:f[a-z]+_)?(?:v10_)?t1_[a-z0-9_]+)\b")

#: `wild <stem>.exe` -- the form the docstrings use when naming a wild program.
_WILD = re.compile(r"\bwild ([a-z0-9_]+\.exe)\b", re.I)


def _corpus_stems():
    return {
        os.path.splitext(os.path.basename(p))[0]
        for p in glob.glob(os.path.join(_CORPUS, "*.exe"))
    }


def _cited(pattern):
    """{name: [files citing it]} across the decoder source."""
    found = {}
    for path in _SOURCE:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        for match in pattern.finditer(text):
            rel = os.path.relpath(path, os.path.join(_ROOT, os.pardir))
            found.setdefault(match.group(1), set()).add(rel)
    return found


def test_every_cited_fixture_is_in_the_corpus():
    """A fixture name in a docstring resolves to a compiled EXE.

    The failure to catch is a citation that looks authoritative and leads
    nowhere -- the reader cannot tell a renamed fixture from a deleted one, or
    from a claim that was never true.
    """
    stems = _corpus_stems()
    stale = {
        name: sorted(where)
        for name, where in _cited(_FIXTURE).items()
        if name not in stems
    }

    assert not stale, "cited fixtures missing from tests/fixtures/corpus: " + "; ".join(
        f"{name} (cited in {', '.join(where)})" for name, where in sorted(stale.items())
    )


def test_every_cited_wild_program_is_in_the_corpus():
    """A `wild foo.exe` citation names a program that is actually there.

    Checked against the `wild/hits` DIRECTORY, not against
    `wild_roundtrip.json`: the manifest records only the programs that decode,
    while citations name failing ones just as often -- a gap is written up
    against the program that exposed it, which by definition did not decode at
    the time. Using the manifest here would demand an ever-growing list of
    allowed exceptions, which is the kind of bookkeeping that rots.

    The directory is gitignored (copyrighted shareware), so this skips where it
    is absent, the same bargain `conftest.wild_hits_bytes` makes.
    """
    import pytest

    hits = os.path.join(_ROOT, os.pardir, "wild", "hits")
    if not os.path.isdir(hits):
        pytest.skip("wild/hits not present (gitignored, local-only corpus)")
    present = {name.lower() for name in os.listdir(hits)}

    unknown = {
        name: sorted(where)
        for name, where in _cited(_WILD).items()
        if name.lower() not in present
    }

    assert not unknown, "wild programs cited but not in wild/hits: " + "; ".join(
        f"{name} (cited in {', '.join(where)})" for name, where in sorted(unknown.items())
    )


#: `q_foo.bas` / `probe_foo.bas` -- authored probes, which `CLAUDE.md` requires
#: to live in `wild/probes/` with their source.
_PROBE = re.compile(r"\b((?:q|probe)_[a-z0-9_]+\.bas)\b")

#: Documents a probe citation is enforced in. `PLAN.md` is deliberately absent:
#: it is an evidence ARCHIVE of a parked campaign whose scratch probes were
#: never committed (23 of them), and enforcing that retroactively would only
#: invite an allowlist. What matters is that the LIVE documents -- the ones a
#: session is told to read -- do not offer evidence that cannot be re-run.
_LIVE_DOCS = ["STATUS.md", "CLAUDE.md"]


def test_every_probe_cited_by_a_live_document_is_committed():
    """A probe offered as current evidence can actually be re-run.

    `CLAUDE.md` already requires authored probes to be kept in `wild/probes/`
    with their `.bas` source; this is what makes that rule bite. STATUS.md
    cited `q_orofors3.bas` as reproducing an open gap while the file had never
    been committed, so the one thing that would let the next session pick the
    thread up did not exist.
    """
    root = os.path.join(_ROOT, os.pardir)
    present = {
        os.path.basename(p)
        for p in glob.glob(os.path.join(root, "wild", "probes", "*"))
        + glob.glob(os.path.join(root, "wild", "probes_gap16", "*"))
    }

    missing = {}
    for name in _LIVE_DOCS + _SOURCE:
        path = name if os.path.isabs(name) else os.path.join(root, name)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8", errors="ignore") as handle:
            text = handle.read()
        for match in _PROBE.finditer(text):
            if match.group(1) not in present:
                missing.setdefault(match.group(1), set()).add(
                    os.path.relpath(path, root)
                )

    assert not missing, "probes cited as evidence but absent from wild/probes: " + (
        "; ".join(
            f"{name} (cited in {', '.join(sorted(where))})"
            for name, where in sorted(missing.items())
        )
    )
