"""Final, cosmetic canonicalization of stable source-shaped statements."""

from __future__ import annotations

from tbd.ir import Slot, Statement

_COMMUTATIVE = {"+", "*"}
_RESERVED = {"AS", "AT", "DO", "FN", "GO", "IF", "LN", "ON", "OR", "PI", "TO"}
_SUFFIXES = {"integer": "%", "string": "$", "double": "#"}


def canonicalize(
    statements: tuple[Statement, ...], slots: tuple[Slot, ...]
) -> tuple[Statement, ...]:
    """Name address-based slots and normalize equivalent expression order."""

    normalized = tuple(_normalize_statement(statement) for statement in statements)
    names = _Names(slots)
    return tuple(names.statement(statement) for statement in normalized)


def _normalize_statement(statement: Statement) -> Statement:
    operands = statement.operands
    if statement.kind == "Assign":
        operands = (_normalize_expression(operands[0]), _normalize_expression(operands[1]))
    elif statement.kind == "Print":
        mode, items, newline = operands
        operands = mode, tuple(_normalize_expression(item) for item in items), newline
    elif statement.kind == "IfGoto":
        condition, left, right, target = operands
        operands = (
            condition,
            _normalize_expression(left),
            _normalize_expression(right),
            target,
        )
    elif statement.kind == "Delay":
        operands = tuple(_normalize_expression(item) for item in operands)
    return Statement(statement.index, statement.address, statement.kind, operands)


def _normalize_expression(value: object) -> object:
    if not isinstance(value, tuple) or not value:
        return value
    if value[0] == "slot":
        return value
    if value[0] == "binary" and len(value) == 4:
        left = _normalize_expression(value[2])
        right = _normalize_expression(value[3])
        if value[1] in _COMMUTATIVE and _expression_key(right) < _expression_key(left):
            left, right = right, left
        return "binary", value[1], left, right
    return tuple(_normalize_expression(item) for item in value)


def _expression_key(value: object) -> tuple[int, str]:
    tag = value[0] if isinstance(value, tuple) and value else None
    rank = {"slot": 0, "binary": 1, "const": 2, "string": 3}.get(tag, 4)
    return rank, repr(value)


class _Names:
    def __init__(self, slots: tuple[Slot, ...]) -> None:
        self._types = {slot.offset: slot.types for slot in slots}
        self._names: dict[int, str] = {}
        self._next = 0

    def statement(self, statement: Statement) -> Statement:
        operands = tuple(self._value(value) for value in statement.operands)
        return Statement(statement.index, statement.address, statement.kind, operands)

    def _value(self, value: object) -> object:
        if not isinstance(value, tuple) or not value:
            return value
        if value[0] == "slot" and len(value) >= 3 and isinstance(value[2], int):
            return self._variable(value)
        return tuple(self._value(item) for item in value)

    def _variable(self, slot: tuple[object, ...]) -> tuple[object, ...]:
        address = slot[2]
        if address not in self._names:
            self._names[address] = self._new_name()
        types = set(self._types.get(address, ()))
        if len(slot) >= 4 and isinstance(slot[3], str):
            types.add(slot[3])
        suffixes = {_SUFFIXES[item] for item in types if item in _SUFFIXES}
        name = self._names[address]
        if len(types) == 1 and len(suffixes) == 1:
            name += suffixes.pop()
        if len(types) > 1:
            return "var", name, ("types", tuple(sorted(types)))
        return "var", name

    def _new_name(self) -> str:
        while True:
            name = _letters(self._next)
            self._next += 1
            if name not in _RESERVED:
                return name


def _letters(index: int) -> str:
    result = ""
    index += 1
    while index:
        index, remainder = divmod(index - 1, 26)
        result = chr(ord("A") + remainder) + result
    return result
