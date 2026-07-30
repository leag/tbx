"""`docs/decoder-architecture.md` still describes this decoder.

A map is worth having only while it is right, and an architecture document is
the easiest thing in a repository to leave behind. The parts of it that are
facts about the code -- the ownership views and their sizes, the modules in the
pipeline, the tools it points at, the diagnostic fields it tells you to read --
are checked here against the code itself.

The prose is not checked, and cannot be. What this stops is the specific way
such a document goes wrong: a view renamed, a field count moved, a tool that no
longer exists, quietly diverging until nobody trusts any of it.
"""

import importlib
import re
from pathlib import Path

import pytest

from tbx.decode0.cursor import DecodeDiagnostics
from tbx.decode0.state_parts import STATE_VIEWS

DOC = Path(__file__).resolve().parents[2] / "docs" / "decoder-architecture.md"
TEXT = DOC.read_text()


def test_every_ownership_view_is_described_with_its_real_size():
    for attr, cls in STATE_VIEWS.items():
        heading = f"**`state.{attr}`** ({cls.__name__}, {len(cls.fields)} fields)"
        assert heading in TEXT, f"missing or stale: {heading}"


def test_every_owned_field_is_listed_under_its_owner():
    for attr, cls in STATE_VIEWS.items():
        section = TEXT.split(f"**`state.{attr}`**", 1)[1].split("**`state.", 1)[0]
        for name in cls.fields:
            assert f"`{name}`" in section, f"{name} missing from state.{attr}"


def test_the_total_field_count_is_current():
    total = sum(len(cls.fields) for cls in STATE_VIEWS.values())

    assert f"holds {total} persistent" in TEXT


@pytest.mark.parametrize(
    "module",
    [
        "tbx.decode0.scan",
        "tbx.decode0.layout",
        "tbx.decode0.core",
        "tbx.decode0.lift",
        "tbx.decode0.select_case",
        "tbx.decode0.rename",
        "tbx.decode0.events",
        "tbx.decode0.statement_log",
        "tbx.decode0.control_graph",
        "tbx.decode0.fold_pass",
        "tbx.decode0.cursor",
        "tbx.emit0",
    ],
)
def test_a_module_the_map_names_still_exists(module):
    importlib.import_module(module)
    assert Path(module.replace(".", "/") + ".py").name.replace(".py", "") in TEXT


@pytest.mark.parametrize(
    "tool",
    ["dump_ops", "dump_events", "scan_wild", "verify_fixture", "verify_wild"],
)
def test_a_tool_the_map_points_at_is_runnable(tool):
    importlib.import_module(f"tbx.tools.{tool}")
    assert f"tbx.tools.{tool}" in TEXT


def test_the_diagnostic_fields_it_tells_you_to_read_are_the_real_ones():
    """The failure-reading table is the reason the document exists.

    Checked against what `report()` actually prints, not against the
    dataclass's own attribute names -- the report renames several on the way
    out (`file_offset` prints as `offset`), and what a reader sees in a
    traceback is the only spelling that helps them.
    """
    report = DecodeDiagnostics(
        phase="lift",
        file_offset=0x1234,
        op_index=7,
        statement_address=0x1200,
        component="control",
        expected=["x"],
        rejected=["y"],
        history=[(1, "movax", 2)],
    ).report()
    emitted = set(re.findall(r"(\w+)=", report))
    # Scoped to the failure-reading section: other tables in the document use
    # the same row shape, and a frame named `start` is not a diagnostic field.
    table = TEXT.split("## Reading a failure", 1)[1].split("\n## ", 1)[0]
    documented = {
        a
        for pair in re.findall(r"^\| `(\w+)`(?: / `(\w+)`)? \|", table, re.M)
        for a in pair
        if a
    }

    assert documented == emitted, (
        "the failure-reading table and the report have diverged; "
        f"report prints {sorted(emitted)}, doc lists {sorted(documented)}"
    )
