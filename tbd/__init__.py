"""Public API for the compact best-effort Turbo Basic decoder."""

from tbd.core import decode
from tbd.ir import (
    BasicBlock,
    CrossReference,
    Diagnostic,
    Operation,
    PassReport,
    Program,
    Slot,
)

decode_user_code = decode

__all__ = [
    "BasicBlock",
    "CrossReference",
    "Diagnostic",
    "Operation",
    "PassReport",
    "Program",
    "Slot",
    "decode",
    "decode_user_code",
]
