"""Recognition of calibrated opaque machine-code helper spans.

These helpers are not Turbo Basic source constructs.  Their full bodies are
fingerprinted elsewhere because their calling convention is known but their
source semantics are not.  Classification is deliberately a byte-only pass:
it may recognize an exact body bracketed by the compiler's declaration-skip
JMP, but it never turns an unfamiliar framed routine into an opaque helper.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable

from tbx.decode0.opaque_helpers import OpaqueHelperSpec


def find_opaque_helpers(
    exe: bytes, start: int, helpers: Iterable[OpaqueHelperSpec]
) -> dict[int, tuple[int, bytes, tuple[int, ...]]]:
    """Return exact helper spans keyed by their body address."""
    known = {helper.body: helper for helper in helpers}
    found: dict[int, tuple[int, bytes, tuple[int, ...]]] = {}
    for jump in range(start + 3, len(exe) - 2):
        if exe[jump] != 0xE9:
            continue
        target = start + ((jump + 3 + struct.unpack_from("<h", exe, jump + 1)[0] - start) % 0x10000)
        body_start = jump + 3
        if not body_start < target <= len(exe):
            continue
        body = exe[body_start:target]
        if spec := known.get(body):
            found[body_start] = (target, body, spec.param_offsets)
    return found
