"""The evidence ledgers stay well-formed and their citations resolve.

Two JSON ledgers under `gap_reports/` record findings that outlive a session:
`runtime-revision-assessments.json` for questions whose answer is a property of
the compiler, and `ruled-out-hypotheses.json` for decoder-side hypotheses that
were tried and rejected. Both exist because a rejected hypothesis is expensive
evidence -- somebody spent a session earning it -- and is otherwise lost.

A ledger nobody validates decays into prose. These checks keep the shape
uniform and, more importantly, keep the pointers honest: an entry that cites a
wild program, a `PLAN.md` line or a fixture is only worth reading if you can
follow it. The prose is not checked and cannot be.
"""

import json
import os

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REPO = os.path.join(_ROOT, os.pardir)
_REPORTS = os.path.join(_REPO, "gap_reports")

_LEDGERS = {
    "runtime-revision-assessments.json": (
        "tbx.runtime_revision_assessments",
        "assessments",
        {"id", "title", "disposition", "confidence", "assessment"},
    ),
    "ruled-out-hypotheses.json": (
        "tbx.ruled_out_hypotheses",
        "hypotheses",
        {"id", "title", "disposition", "confidence", "hypothesis",
         "negative_evidence", "instead"},
    ),
}


def _load(name):
    with open(os.path.join(_REPORTS, name), encoding="utf-8") as handle:
        return json.load(handle)


@pytest.mark.parametrize("name", sorted(_LEDGERS))
def test_a_ledger_declares_itself(name):
    document_type, _, _ = _LEDGERS[name]
    doc = _load(name)

    assert doc["document_type"] == document_type
    assert doc["schema_version"] == 1
    assert doc["updated"]


@pytest.mark.parametrize("name", sorted(_LEDGERS))
def test_every_entry_has_the_fields_its_ledger_promises(name):
    _, key, required = _LEDGERS[name]
    entries = _load(name)[key]

    assert entries, f"{name} has no entries"
    ids = [e["id"] for e in entries]
    assert len(ids) == len(set(ids)), f"duplicate ids in {name}: {ids}"
    for entry in entries:
        missing = required - set(entry)
        assert not missing, f"{name} {entry.get('id')} missing {sorted(missing)}"


def test_a_rejected_hypothesis_says_what_to_do_instead():
    """The field that makes the register worth keeping.

    Recording that something failed only saves the next session time if it also
    says where to look next; without it the entry reads as discouragement
    rather than evidence.
    """
    for entry in _load("ruled-out-hypotheses.json")["hypotheses"]:
        assert entry["negative_evidence"], f"{entry['id']} rejects nothing"
        assert len(entry["instead"]) > 30, f"{entry['id']} has no usable redirect"


@pytest.mark.parametrize("name", sorted(_LEDGERS))
def test_every_wild_program_a_ledger_cites_exists(name):
    """Ledger `files` entries are repo-relative paths into the wild corpus."""
    _, key, _ = _LEDGERS[name]
    hits = os.path.join(_REPO, "wild", "hits")
    if not os.path.isdir(hits):
        pytest.skip("wild/hits not present (gitignored, local-only corpus)")
    present = {n.lower() for n in os.listdir(hits)}

    missing = [
        path
        for entry in _load(name)[key]
        for path in entry.get("files", ())
        if path.startswith("wild/hits/")
        and os.path.basename(path).lower() not in present
    ]

    assert not missing, f"{name} cites absent wild programs: {sorted(set(missing))}"


def test_every_plan_anchor_in_the_ledgers_and_status_resolves():
    """`PLAN.md:NNNN` citations still land on a heading.

    PLAN.md is 9000 lines and is cited by line number from STATUS.md and from
    the ledgers -- the only way anyone finds a specific finding in it. An
    inserted paragraph silently slides every anchor below it, and the citation
    then points at the middle of an unrelated entry, which is worse than a
    broken link because it still reads as an answer.
    """
    import re

    with open(os.path.join(_REPO, "PLAN.md"), encoding="utf-8") as handle:
        plan = handle.read().splitlines()

    sources = {"STATUS.md": open(os.path.join(_REPO, "STATUS.md"), encoding="utf-8").read()}
    for name in _LEDGERS:
        sources[name] = open(os.path.join(_REPORTS, name), encoding="utf-8").read()

    bad = []
    for where, text in sources.items():
        for match in re.finditer(r"PLAN\.md:(\d+)", text):
            n = int(match.group(1))
            if not 0 < n <= len(plan):
                bad.append(f"{where} -> PLAN.md:{n} (out of range)")
            elif not plan[n - 1].startswith("#"):
                bad.append(f"{where} -> PLAN.md:{n} ({plan[n - 1][:48]!r} is not a heading)")

    assert not bad, "stale PLAN.md anchors: " + "; ".join(bad)
