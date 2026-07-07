"""Expression parsing: `tokenize` / `parse_expr`, and the `lift_assign` adapter.

`parse_expr` is the inverse of `unparse` (see the sibling `unparse` module):
`unparse(parse_expr(s)) == s` for every expression the decoder produces.
"""

from __future__ import annotations
import re

from tbx.ir.expr_nodes import (
    INTRINSICS,
    ArrayRef,
    BinOp,
    Call,
    Lit,
    Neg,
    Unknown,
    Var,
    _PREC,
)
from tbx.ir.stmt_nodes import Assign

# V_#### form first (so it isn't split), then general identifiers, integers, single-char punct.
_TOKEN = re.compile(r"V_[0-9A-Fa-f]{4}|[A-Za-z][A-Za-z0-9_]*[%!#$]?|\d+|[()+\-*/,?]")
_OPS = {"+", "-", "*", "/"}


def tokenize(s: str) -> list[str]:
    """Split an expression string into tokens. Whitespace is insignificant (it only ever
    surrounds binary operators in the decoder's output)."""
    toks = _TOKEN.findall(s)
    # Round-trip safety: the concatenation of tokens must equal the input minus whitespace.
    if "".join(toks) != s.replace(" ", ""):
        raise ValueError(f"untokenizable expression: {s!r}")
    return toks


def parse_expr(s: str):
    """Parse one expression string into a typed IR node. Raises ValueError on malformed
    input or trailing tokens. Precedence-climbing over flat chains; every
    parenthesized subexpression mints a Group node (parens are
    byte-significant), so unparse(parse_expr(s)) reproduces s's paren
    structure."""
    toks = tokenize(s)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos
        t = toks[pos]
        pos += 1
        return t

    def expect(t):
        got = take()
        if got != t:
            raise ValueError(f"expected {t!r}, got {got!r} in {s!r}")

    def expr(minp=1):
        lhs = parse()
        while (t := peek()) in _OPS and _PREC[t] >= minp:
            take()
            lhs = BinOp(t, lhs, expr(_PREC[t] + 1))
        return lhs

    def parse():
        nonlocal pos
        t = peek()
        if t is None:
            raise ValueError(f"unexpected end of expression in {s!r}")
        if t == "(":  # strip parse-time parens; decoder mints Group
            expect("(")
            node = expr()
            expect(")")
            return node
        if t == "-":  # unary negation (FCHS)
            take()
            return Neg(parse())
        if t == "?":
            take()
            return Unknown()
        if t.isdigit():
            return Lit(int(take()))
        if re.fullmatch(r"V_[0-9A-Fa-f]{4}|[A-Za-z][A-Za-z0-9_]*[%!#$]?", t):
            name = take()
            if peek() == "(":  # NAME "(" args ")"
                expect("(")
                args = [expr()]
                while peek() == ",":
                    take()
                    args.append(expr())
                expect(")")
                if name in INTRINSICS:
                    return Call(name, tuple(args))
                return ArrayRef(name, tuple(args))
            return Var(name)
        raise ValueError(f"unexpected token {t!r} in {s!r}")

    node = expr()
    if pos != len(toks):
        raise ValueError(f"trailing tokens after expression in {s!r}: {toks[pos:]}")
    return node


def lift_assign(text: str):
    """Adapter: lift a decoder `BAS` line "target = rhs" into a typed Assign. Returns None for
    lines that are not assignments (the only statement form this slice models). The target is
    parsed with the same grammar (it is a Var or an ArrayRef)."""
    if " = " not in text:
        return None
    lhs, rhs = text.split(" = ", 1)
    return Assign(parse_expr(lhs), parse_expr(rhs))
