"""Final, cosmetic canonicalization of stable source-shaped statements."""

from __future__ import annotations

from tbd.ir import Slot, Statement

_COMMUTATIVE = {"+", "*"}
_RESERVED = {"AS", "AT", "DO", "FN", "GO", "IF", "LN", "ON", "OR", "PI", "TO"}
_SUFFIXES = {"integer": "%", "long": "&", "string": "$", "double": "#"}


def canonicalize(
    statements: tuple[Statement, ...], slots: tuple[Slot, ...]
) -> tuple[Statement, ...]:
    """Name address-based slots and normalize equivalent expression order."""

    procedures = tuple(
        statement.operands[0]
        for statement in statements
        if statement.kind == "SubDef"
        and statement.operands
        and isinstance(statement.operands[0], int)
    )
    names = _Names(slots, procedures)
    named = tuple(names.statement(statement) for statement in statements)
    return tuple(_normalize_statement(statement) for statement in named)


def _normalize_statement(statement: Statement) -> Statement:
    operands = statement.operands
    if statement.kind == "Assign":
        operands = (normalize_expression(operands[0]), normalize_expression(operands[1]))
    elif statement.kind in {"Lset", "Rset", "Swap"}:
        operands = (normalize_expression(operands[0]), normalize_expression(operands[1]))
    elif statement.kind == "MidAssign":
        target, start, source, length = operands
        operands = (
            normalize_expression(target),
            normalize_expression(start),
            normalize_expression(source),
            None if length is None else normalize_expression(length),
        )
    elif statement.kind == "Locate":
        operands = tuple(
            None if operand is None else normalize_expression(operand)
            for operand in operands
        )
    elif statement.kind == "Read":
        operands = (tuple(normalize_expression(item) for item in operands[0]),)
    elif statement.kind == "InputFile":
        operands = (
            operands[0],
            tuple(normalize_expression(item) for item in operands[1]),
        )
    elif statement.kind == "Close":
        operands = (
            None if operands[0] is None else normalize_expression(operands[0]),
        )
    elif statement.kind == "TrapCtl":
        operands = (
            operands[0],
            None if operands[1] is None else normalize_expression(operands[1]),
            operands[2],
        )
    elif statement.kind == "OnTrap":
        operands = (
            operands[0],
            None if operands[1] is None else normalize_expression(operands[1]),
            operands[2],
        )
    elif statement.kind in {"Print", "Lprint"}:
        mode, items, newline = operands
        operands = mode, tuple(normalize_expression(item) for item in items), newline
    elif statement.kind == "Write":
        file_number, items = operands
        operands = file_number, tuple(normalize_expression(item) for item in items)
    elif statement.kind == "Field":
        file_number, fields = operands
        operands = file_number, tuple(
            (normalize_expression(width), normalize_expression(target))
            for width, target in fields
        )
    elif statement.kind == "IfGoto":
        condition, left, right, target = operands
        operands = (
            condition,
            normalize_expression(left),
            normalize_expression(right),
            target,
        )
    elif statement.kind == "Delay":
        operands = tuple(normalize_expression(item) for item in operands)
    elif statement.kind == "DefSeg":
        operands = tuple(normalize_expression(item) for item in operands)
    elif statement.kind == "SubDef":
        name, parameters, body = operands
        operands = (
            name,
            parameters,
            tuple(_normalize_statement(item) for item in body),
        )
    elif statement.kind == "CallStmt":
        name, arguments = operands
        if not _unresolved(arguments):
            arguments = tuple(normalize_expression(item) for item in arguments)
        operands = name, arguments
    return Statement(statement.index, statement.address, statement.kind, operands)


def normalize_expression(value: object) -> object:
    """Return the comparison-stable form of one source expression."""

    if not isinstance(value, tuple) or not value:
        return value
    if value[0] == "slot":
        return value
    if value[0] == "binary" and len(value) == 4:
        left = normalize_expression(value[2])
        right = normalize_expression(value[3])
        commutative = value[1] in _COMMUTATIVE and not (
            value[1] == "+"
            and (_is_string_expression(left) or _is_string_expression(right))
        )
        if commutative and _expression_key(right) < _expression_key(left):
            left, right = right, left
        return "binary", value[1], left, right
    return tuple(normalize_expression(item) for item in value)


def _is_string_expression(value: object) -> bool:
    if not isinstance(value, tuple) or not value:
        return False
    if value[0] == "string":
        return True
    if value[0] == "var":
        if len(value) >= 2 and isinstance(value[1], str) and value[1].endswith("$"):
            return True
        return (
            len(value) >= 3
            and isinstance(value[2], tuple)
            and len(value[2]) == 2
            and value[2][0] == "types"
            and "string" in value[2][1]
        )
    if value[0] == "slot":
        return len(value) >= 4 and value[3] == "string"
    return (
        value[0] == "binary"
        and len(value) == 4
        and value[1] == "+"
        and (_is_string_expression(value[2]) or _is_string_expression(value[3]))
    )


def _expression_key(value: object) -> tuple[int, str]:
    tag = value[0] if isinstance(value, tuple) and value else None
    rank = {
        "slot": 0,
        "var": 0,
        "array": 0,
        "binary": 1,
        "const": 2,
        "string": 3,
    }.get(tag, 4)
    return rank, repr(value)


class _Names:
    def __init__(self, slots: tuple[Slot, ...], procedures: tuple[int, ...]) -> None:
        self._types = {slot.offset: slot.types for slot in slots}
        self._names: dict[int, str] = {}
        self._next = 0
        self._procedures = {
            address: f"SUB{index}"
            for index, address in enumerate(procedures, start=1)
        }

    def statement(self, statement: Statement) -> Statement:
        if statement.kind == "SubDef":
            entry, parameters, body = statement.operands
            operands = (
                self._procedure(entry),
                self._value(parameters),
                tuple(self.statement(item) for item in body),
            )
            return Statement(statement.index, statement.address, statement.kind, operands)
        if statement.kind == "CallStmt":
            target, arguments = statement.operands
            operands = self._procedure(target), self._value(arguments)
            return Statement(statement.index, statement.address, statement.kind, operands)
        operands = tuple(self._value(value) for value in statement.operands)
        return Statement(statement.index, statement.address, statement.kind, operands)

    def _procedure(self, address: object) -> object:
        return self._procedures.get(address, ("procedure", address))

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


def _unresolved(value: object) -> bool:
    return (
        isinstance(value, tuple)
        and bool(value)
        and value[0] == "unresolved-call-arguments"
    )
