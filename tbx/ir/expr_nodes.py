"""Expression, condition and CASE-guard IR nodes, plus shared constants.

Pure data (frozen dataclasses) with no rendering logic -- `unparse`/`parse_expr`
live in the sibling `unparse`/`parse` modules. See the package docstring in
`ir/__init__.py` for the IR's fidelity gate.
"""

from __future__ import annotations
from dataclasses import dataclass

# TB intrinsic functions: NAME(args) is a Call iff NAME is here, else an array reference.
# Includes the decoder's pseudo-names for x87 FP constants (LOG2/LOG10 from FLDL2T etc.).
INTRINSICS = {
    "SQR",
    "ABS",
    "SIN",
    "COS",
    "TAN",
    "ATN",
    "EXP",
    "LOG",
    "INT",
    "FIX",
    "SGN",
    "LOG2",
    "LOG10",
}

_SUFFIX_TY = {"%": "INT", "!": "SGL", "#": "DBL", "$": "STR"}

# The IR is duck-typed -- analyses pattern-match on node classes rather than a closed
# union -- so Expr/Stmt are documentation aliases for "any node", used to annotate the
# `tuple[Expr, ...]` / `tuple[Stmt, ...]` child collections below.
Expr = object
Stmt = object


@dataclass(frozen=True)
class Lit:
    value: int | float  # usually a non-negative int; pooled FP singles arrive as float


@dataclass(frozen=True)
class Unknown:
    """The decoder's '?' sentinel: a value it does not model (e.g. INPUT-sourced)."""


@dataclass(frozen=True)
class Var:
    name: str

    @property
    def ty(self) -> str:
        return _SUFFIX_TY.get(self.name[-1], "NUM")


@dataclass(frozen=True)
class ArrayRef:
    name: str
    indices: tuple[Expr, ...]


@dataclass(frozen=True)
class Call:
    name: str
    args: tuple[Expr, ...]


@dataclass(frozen=True)
class BinOp:
    op: str  # "+" | "-" | "*" | "/"
    lhs: object  # Expr
    rhs: object  # Expr


@dataclass(frozen=True)
class StrLit:
    """String literal (pooled as a 4-byte descriptor into the string space)."""

    value: str


@dataclass(frozen=True)
class Neg:
    """Unary FP negation (x87 FCHS)."""

    operand: object  # Expr


@dataclass(frozen=True)
class DblLit:
    """Pooled IEEE-754 double literal, rendered with a '#' BASIC suffix."""

    value: float


@dataclass(frozen=True)
class SingleLit:
    """An implicit-single literal: an unsuffixed source literal (e.g. `S! = 1.5`)
    that TB pools as f64 (so it loads via fld64/DblLit) but stores to a width-4
    single slot -- rendered as a plain decimal with NO precision suffix."""

    value: float


@dataclass(frozen=True)
class HexLit:
    """Integer literal canonically rendered as &H hex (e.g. the LINE style word --
    a bit pattern; the hex token compiles to the same imm16, gate-proven)."""

    value: int  # unsigned 16-bit


@dataclass(frozen=True)
class Not:
    """Bitwise/logical NOT (F7 D0 on the int accumulator)."""

    operand: object  # Expr


@dataclass(frozen=True)
class Group:
    """An explicitly parenthesized subexpression. Parens are BYTE-SIGNIFICANT:
    a parenthesized operand compiles as a pushed group (combined with a
    DE-class pop op), while an unparenthesized chain folds its trailing leaves
    -- so parens live in the IR and unparse never invents them. Decode mints
    Group exactly where TB's codegen requires the parens to reproduce the
    bytes."""

    inner: object  # Expr (always compound)


# The standard TB operator hierarchy.
_PREC = {
    "^": 9,
    "*": 8,
    "/": 8,
    "\\": 7,
    "MOD": 6,
    "+": 5,
    "-": 5,
    "=": 4,
    "<>": 4,
    "<": 4,
    "<=": 4,
    ">": 4,
    ">=": 4,
    "AND": 3,
    "OR": 2,
    "XOR": 1,
}


@dataclass(frozen=True)
class RelOp:
    """Comparison condition (IF / loop guards): lhs op rhs, op in = <> < <= > >=."""

    op: str
    lhs: object
    rhs: object


@dataclass(frozen=True)
class LogOp:
    """Compound condition: lhs AND/OR rhs (compiled as short-circuit materialization)."""

    op: str  # "AND" | "OR"
    lhs: object  # RelOp | LogOp
    rhs: object


@dataclass(frozen=True)
class CaseValue:
    """A `CASE <value>` guard term (also each item of a `CASE 1, 3, 5` list)."""

    value: object  # Expr


@dataclass(frozen=True)
class CaseRange:
    """A `CASE <lo> TO <hi>` guard term."""

    lo: object  # Expr
    hi: object  # Expr


@dataclass(frozen=True)
class CaseIs:
    """A `CASE IS <op> <value>` guard term (op is a RelOp symbol: '<','>','=',...)."""

    op: str
    value: object  # Expr


@dataclass(frozen=True)
class FnCall:
    """User DEF FN invocation `FNx(args)` -- value-returning call expr (Expr, not Stmt).
    Distinct from `Call` (built-in intrinsics); the `FN` prefix is part of the name."""

    name: str
    args: tuple[Expr, ...]


@dataclass(frozen=True)
class VarSeg:
    """VARSEG(v) of a DGROUP variable: compiles to a bare `mov ax,ds`, so WHICH
    variable was named is not recoverable -- any DGROUP var round-trips. Rendered
    against the assignment target (always a DGROUP var) in unparse_stmt."""


@dataclass(frozen=True)
class Nullary:
    """A bare zero-argument intrinsic rendered without parens (CSRLIN, INSTAT,
    TIMER, MTIMER-as-function; POS is Call("POS", (0,)) -- dummy arg required)."""

    name: str


@dataclass(frozen=True)
class Err:
    """ERR -- last error code: plain word read of DGROUP cell [0074]."""


@dataclass(frozen=True)
class Erl:
    """ERL -- last error line: plain word read of DGROUP cell [0072]."""
