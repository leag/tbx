"""Public API for the compact best-effort Turbo Basic decoder."""

from tbd.core import decode
from tbd.ir import (
    BasicBlock,
    CrossReference,
    Diagnostic,
    Fact,
    FactReport,
    Operation,
    PassReport,
    Program,
    Slot,
    Statement,
)

decode_user_code = decode

__all__ = [
    "BasicBlock",
    "CrossReference",
    "Diagnostic",
    "Fact",
    "FactReport",
    "Operation",
    "PassReport",
    "Program",
    "Slot",
    "Statement",
    "decode",
    "decode_user_code",
]
