"""Public API for decoding Turbo Basic executables."""

from tbd.basic import BasicTranslationError, emit_basic, to_basic
from tbd.core import decode
from tbd.ir import (
    BasicBlock,
    CrossReference,
    Diagnostic,
    Fact,
    FactReport,
    Operation,
    Program,
    Slot,
    Statement,
)

decode_user_code = decode

__all__ = [
    "BasicBlock",
    "BasicTranslationError",
    "CrossReference",
    "Diagnostic",
    "Fact",
    "FactReport",
    "Operation",
    "Program",
    "Slot",
    "Statement",
    "decode",
    "decode_user_code",
    "emit_basic",
    "to_basic",
]
