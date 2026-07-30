"""Every owned decode-state field is live: the audit Chapter 7 asks for.

`test_state_parts.py` proves the partition is total and disjoint -- that no
field has two owners or none. That says nothing about whether a field is still
*used*. A decoder field that is written and never read is the worst kind of
state to carry: it reads as meaningful, so anyone reasoning about the dispatch
loop has to account for it, and nothing fails when it stops mattering.

So this is the other half. It walks the source for attribute access and checks
that each owned field is read somewhere. At the time of writing all 96 are, and
the least-used are down at one read -- which is the point: they can be found
and judged, rather than suspected.

The walk sees attribute syntax only. A field reached through `getattr(state,
name)` would look unread, and the right response to a failure here is to check
that first rather than delete a field the audit cannot see.
"""

import ast
import collections
from pathlib import Path

from tbx.decode0.state_parts import INFRASTRUCTURE_FIELDS, STATE_VIEWS

_ROOT = Path(__file__).resolve().parents[2]


def _access_counts():
    """Reads and writes of every owned field name, across the package."""
    owned = {f for cls in STATE_VIEWS.values() for f in cls.fields}
    reads: collections.Counter = collections.Counter()
    writes: collections.Counter = collections.Counter()
    for path in sorted((_ROOT / "tbx").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Attribute) and node.attr in owned:
                bucket = writes if isinstance(node.ctx, ast.Store) else reads
                bucket[node.attr] += 1
    return owned, reads, writes


def test_no_owned_field_is_written_and_never_read():
    owned, reads, _ = _access_counts()

    unread = sorted(f for f in owned if not reads[f])

    assert not unread, (
        f"{len(unread)} owned fields are never read: {unread}. "
        "Either they are dead and should go, or they are reached through "
        "getattr and this audit cannot see them."
    )


def test_the_state_surface_is_the_size_it_says_it_is():
    """A number worth having to change on purpose.

    The whole reason for the ownership partition is that a hundred fields
    reachable from one object is more than a person can hold. Growing that is
    a decision, not a side effect.
    """
    owned, _, _ = _access_counts()

    assert len(owned) == 99
    assert not owned & INFRASTRUCTURE_FIELDS, (
        "migration scaffolding must not be claimed as decode state"
    )
