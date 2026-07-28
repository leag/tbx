"""Ownership-partition guards for the decoder-state migration.

The views are only useful if every persistent decode-loop field has exactly
one owner. These tests fail when a field is added to ``DecodeState`` without
an ownership claim, or when two views claim the same field.
"""

import dataclasses

import pytest

from tbx.decode0.core import DecodeState
from tbx.decode0.state_parts import INFRASTRUCTURE_FIELDS, STATE_VIEWS


def _decode_fields() -> set[str]:
    return {f.name for f in dataclasses.fields(DecodeState)} - INFRASTRUCTURE_FIELDS


def test_every_decode_field_has_exactly_one_owner():
    claims: dict[str, list[str]] = {}
    for name, view in STATE_VIEWS.items():
        for field in view.fields:
            claims.setdefault(field, []).append(name)

    unowned = sorted(_decode_fields() - set(claims))
    assert not unowned, f"decode state fields without an owner: {unowned}"

    shared = sorted(f for f, owners in claims.items() if len(owners) > 1)
    assert not shared, f"decode state fields claimed by several views: {shared}"


def test_no_view_claims_a_field_that_does_not_exist():
    claimed = set().union(*(view.fields for view in STATE_VIEWS.values()))
    stale = sorted(claimed - _decode_fields())
    assert not stale, f"views claim fields absent from DecodeState: {stale}"


def test_views_alias_live_state_rather_than_copying_it():
    state = DecodeState()
    state.validate_ownership()

    state.machine.ax = "from-view"
    assert state.ax == "from-view"
    state.cur = 0x1234
    assert state.control.cur == 0x1234


def test_a_view_rejects_a_field_it_does_not_own():
    state = DecodeState()

    with pytest.raises(AttributeError, match="OutputState does not own 'ax'"):
        state.output.ax  # ax belongs to MachineState

    # A write must not be absorbed as a view-local attribute either: that
    # would leave the shared state stale with no error at the write site.
    with pytest.raises(AttributeError, match="OutputState does not own 'ax'"):
        state.output.ax = "stray"
    assert state.ax is None


def test_detached_views_are_reported():
    state = DecodeState()
    state.expr = None

    with pytest.raises(ValueError, match="view 'expr' is detached"):
        state.validate_ownership()
