"""DATA items that reuse code literals need the compiler's pointer table.

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

Exclusion is the wrong mechanism outright, and `probe_datamid` shows why: with
`DATA AAA` / `PRINT "MIDDLE"` /
`DATA BBB`, the code-only literal 'MIDDLE' lands at descriptor index 1, BETWEEN
'AAA' (2) and 'BBB' (0). The pool is in source first-appearance order and
interleaves DATA items with code literals, so DATA descriptors are not
contiguous and `RESTORE` cannot be indexing the pool at all.

What `RESTORE` indexes instead is an explicit DATA pointer table -- a word per
DATA item, in source order, holding its descriptor disp, skipping code-only
literals and including shared ones. Both authored probes carry one at DGROUP
disp 0x100, below `var_base` where nothing else is allocated: `probe_datamid`'s
skips the PRINT-only literal, `probe_datadup`'s includes the shared item.

The location is calibrated by `t1_datasharedlit` and wild zip.exe as well as
the two probes, which all sit at 0x100/0x110 below a 0x120 `var_base`, and by
wild styled.exe/styllist.exe, whose 94-entry tables sit at 0x180/0x140 --
PAST `var_base`. The bound that holds for all five is the string pool: the
table is a paragraph-aligned run of descriptor displacements below `ss_base`,
ending at the first word that is not one. Requiring it to contain every
exclusion-derived item in order leaves exactly one candidate in each.
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


def test_a_shared_data_item_is_recovered_from_the_pointer_table():
    exe = (_ROOT / "wild" / "probes" / "probe_datadup.exe").read_bytes()

    data = [stmt for stmt in decode0.decode_user_code(exe) if type(stmt).__name__ == "Data"]

    assert [item.text for stmt in data for item in stmt.items] == ["ONE", "TWO"]


@pytest.mark.parametrize("name", ("styled.exe", "styllist.exe"))
def test_the_wild_witnesses_recover_their_table_past_var_base(name):
    """Both used to surface as the signature `87` and nothing else.

    Their 94-entry tables sit at DGROUP 0x180 and 0x140, past a 0x120
    `var_base` -- the reason a search bounded by `var_base` (which every small
    witness happens to satisfy) could not find them. `RESTORE`'s item 87 is
    real DATA in both, so the recovered table has to be at least that long.
    """
    hits = _ROOT / "wild" / "hits" / name
    if not hits.is_file():  # wild/hits is gitignored
        pytest.skip(f"{name} not present")

    program = decode0.decode_user_code(hits.read_bytes())

    items = [item for stmt in program if type(stmt).__name__ == "Data"
             for item in stmt.items]
    assert len(items) >= 88, len(items)
    # Exclusion alone recovered 86: the shared descriptors are back.
    assert sum(1 for i in items if i.text == "xxx") > 1, items[:5]


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
