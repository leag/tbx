"""Public API for the compact best-effort Turbo Basic decoder."""

from tbd.core import decode
from tbd.ir import (
    BasicBlock,
    CrossReference,
    Diagnostic,
    Operation,
    PassReport,
    Program,
)

decode_user_code = decode

__all__ = [
    "BasicBlock",
    "CrossReference",
    "Diagnostic",
    "Operation",
    "PassReport",
    "Program",
    "decode",
    "decode_user_code",
]
