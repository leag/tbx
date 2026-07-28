"""Migration boundary guard for the decoder-state ownership refactor.

A module listed here reaches decode state only through its ownership view.
That is what makes a handler's read/write set readable at its top: the alias
line names every component the handler may touch.

Adding a module to ``MIGRATED`` is the last step of migrating it; the test
then keeps a new ``state.<field>`` access from slipping back in. Modules that
are not listed are legacy and unconstrained.
"""

import ast
from pathlib import Path

import pytest

from tbx.decode0.state_parts import STATE_VIEWS

ROOT = Path(__file__).resolve().parents[2]

MIGRATED = [
    "tbx/decode0/handlers/arith.py",
    "tbx/decode0/handlers/control.py",
    "tbx/decode0/handlers/dos_io.py",
    "tbx/decode0/handlers/fileio.py",
    "tbx/decode0/handlers/graphics.py",
    "tbx/decode0/select_case.py",
]

OWNED = frozenset().union(*(view.fields for view in STATE_VIEWS.values()))


def _direct_accesses(path: Path) -> list[str]:
    tree = ast.parse(path.read_text())
    return sorted(
        f"{path.name}:{node.lineno}: state.{node.attr}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "state"
        and node.attr in OWNED
    )


@pytest.mark.parametrize("relpath", MIGRATED)
def test_migrated_module_uses_ownership_views(relpath):
    direct = _direct_accesses(ROOT / relpath)
    assert not direct, (
        f"{relpath} is listed as migrated but bypasses its ownership views:\n"
        + "\n".join(direct)
    )


@pytest.mark.parametrize("relpath", MIGRATED)
def test_migrated_module_does_not_mutate_the_operation_index(relpath):
    """Consumption is committed through ``state.advance`` and the cursor."""
    tree = ast.parse((ROOT / relpath).read_text())
    writes = [
        f"{Path(relpath).name}:{node.lineno}"
        for node in ast.walk(tree)
        if isinstance(node, (ast.Assign, ast.AugAssign))
        for target in (
            node.targets if isinstance(node, ast.Assign) else [node.target]
        )
        if isinstance(target, ast.Attribute) and target.attr == "k"
    ]
    assert not writes, f"{relpath} writes the operation index directly: {writes}"
