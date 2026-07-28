"""Address-bearing events produced after operation lifting.

The event stream is intentionally immutable and statement-oriented in its
first migration stage. It preserves the final structured IR together with the
physical statement address, allowing later control-flow and rendering passes
to replay from a stable boundary without reading decoder registers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class DecodedEvent:
    """One decoded, address-bearing statement event."""

    kind: str
    address: int | None
    payload: Any


def statement_events(
    statements: Iterable[Any], addresses: Iterable[int | None]
) -> tuple[DecodedEvent, ...]:
    """Build the immutable statement event stream for a finished lift."""

    return tuple(
        DecodedEvent("statement", address, statement)
        for statement, address in zip(statements, addresses, strict=True)
    )


def replay_events(events: Iterable[DecodedEvent]) -> tuple[Any, ...]:
    """Replay committed statement events into the next pipeline pass.

    The first event schema has one lossless kind. Rejecting unknown kinds here
    is deliberate: adding a new event must update the replay contract instead
    of silently dropping it.
    """

    statements = []
    for event in events:
        if event.kind != "statement":
            raise ValueError(f"unknown decoded event kind: {event.kind!r}")
        statements.append(event.payload)
    return tuple(statements)
