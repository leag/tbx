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
    functions = tuple(
        (statement.operands[0], statement.operands[1])
        for statement in statements
        if statement.kind == "DefFn"
        and len(statement.operands) == 5
        and isinstance(statement.operands[0], int)
        and isinstance(statement.operands[1], str)
    )
    names = _Names(slots, procedures, functions)
    named = tuple(names.statement(statement) for statement in statements)
    return tuple(_normalize_statement(statement) for statement in named)


def _normalize_statement(statement: Statement) -> Statement:
    operands = statement.operands
    if statement.kind == "Assign":
        operands = (normalize_expression(operands[0]), normalize_expression(operands[1]))
    elif statement.kind in {"Lset", "Rset", "Swap"}:
        operands = (normalize_expression(operands[0]), normalize_expression(operands[1]))
    elif statement.kind == "PrintUsing":
        operands = (
            operands[0],
            normalize_expression(operands[1]),
            tuple(normalize_expression(value) for value in operands[2]),
            operands[3],
        )
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
    elif statement.kind == "Input":
        prompt, targets, comma, semi = operands
        operands = (
            None if prompt is None else normalize_expression(prompt),
            normalize_expression(targets),
            comma,
            semi,
        )
    elif statement.kind == "Open":
        operands = (
            normalize_expression(operands[0]),
            operands[1],
            normalize_expression(operands[2]),
            None if operands[3] is None else normalize_expression(operands[3]),
            operands[4],
        )
    elif statement.kind == "Close":
        operands = (
            None if operands[0] is None else normalize_expression(operands[0]),
        )
    elif statement.kind in {"Color", "Screen"}:
        operands = tuple(
            None if operand is None else normalize_expression(operand)
            for operand in operands
        )
    elif statement.kind == "Files":
        operands = (
            None if operands[0] is None else normalize_expression(operands[0]),
        )
    elif statement.kind in {
        "Chdir",
        "Draw",
        "Environ",
        "Kill",
        "Mkdir",
        "Play",
        "Rmdir",
        "Shell",
    }:
        operands = (normalize_expression(operands[0]),)
    elif statement.kind == "DateTimeSet":
        operands = operands[0], normalize_expression(operands[1])
    elif statement.kind == "For":
        operands = tuple(normalize_expression(operand) for operand in operands)
    elif statement.kind == "NextStmt":
        operands = (normalize_expression(operands[0]),)
    elif statement.kind in {"Do", "Loop"}:
        kind, condition = operands
        if isinstance(condition, tuple) and len(condition) == 3:
            condition = (
                condition[0],
                normalize_expression(condition[1]),
                normalize_expression(condition[2]),
            )
        operands = kind, condition
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
    elif statement.kind in {"OnGoto", "OnGosub"}:
        operands = (normalize_expression(operands[0]), *operands[1:])
    elif statement.kind == "Run" and operands:
        operands = (normalize_expression(operands[0]),)
    elif statement.kind in {"Print", "Lprint"}:
        mode, items, newline = operands
        if not isinstance(mode, (int, str)):
            mode = normalize_expression(mode)
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
        *condition, target = operands
        operands = (*_normalize_condition(tuple(condition)), target)
    elif statement.kind == "IfInline":
        condition, body, else_body = operands
        operands = (
            _normalize_condition(condition),
            tuple(_normalize_statement(item) for item in body),
            None
            if else_body is None
            else tuple(_normalize_statement(item) for item in else_body),
        )
    elif statement.kind == "Delay":
        operands = tuple(normalize_expression(item) for item in operands)
    elif statement.kind == "DefSeg":
        operands = tuple(normalize_expression(item) for item in operands)
    elif statement.kind == "Dim":
        name, bounds, also, dynamic = operands
        operands = (
            name,
            tuple(normalize_expression(bound) for bound in bounds),
            tuple(
                (
                    other_name,
                    tuple(normalize_expression(bound) for bound in other_bounds),
                )
                for other_name, other_bounds in also
            ),
            dynamic,
        )
    elif statement.kind == "SubDef":
        name, parameters, body = operands
        operands = (
            name,
            parameters,
            tuple(_normalize_statement(item) for item in body),
        )
    elif statement.kind == "DefFn":
        name, parameters, body, is_block = operands
        operands = (
            name,
            parameters,
            tuple(_normalize_statement(item) for item in body)
            if is_block
            else normalize_expression(body),
            is_block,
        )
    elif statement.kind == "FnResult":
        operands = (normalize_expression(operands[0]),)
    elif statement.kind == "CallStmt":
        name, arguments = operands
        if not _unresolved(arguments):
            arguments = tuple(normalize_expression(item) for item in arguments)
        operands = name, arguments
    return Statement(statement.index, statement.address, statement.kind, operands)


def _normalize_condition(value: object) -> object:
    if not isinstance(value, tuple) or not value:
        return value
    if len(value) == 2 and value[0] == "group":
        return "group", _normalize_condition(value[1])
    if len(value) == 2 and value[0] == "truth":
        return "truth", normalize_expression(value[1])
    if len(value) == 3:
        return (
            value[0],
            _normalize_condition(value[1])
            if value[0] in {"AND", "OR"}
            else normalize_expression(value[1]),
            _normalize_condition(value[2])
            if value[0] in {"AND", "OR"}
            else normalize_expression(value[2]),
        )
    return value


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
    if value[0] == "unary" and len(value) == 3:
        operand = normalize_expression(value[2])
        if (
            value[1] == "-"
            and isinstance(operand, tuple)
            and len(operand) == 2
            and operand[0] == "const"
            and isinstance(operand[1], (int, float))
        ):
            return "const", -operand[1]
        return "unary", value[1], operand
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
    def __init__(
        self,
        slots: tuple[Slot, ...],
        procedures: tuple[int, ...],
        functions: tuple[tuple[object, object], ...] = (),
    ) -> None:
        self._types = {slot.offset: slot.types for slot in slots}
        self._names: dict[int, str] = {}
        self._next = 0
        for slot in slots:
            if slot.name.startswith("COMMON"):
                self._names[slot.offset] = self._new_name()
        self._procedures = {
            address: f"SUB{index}"
            for index, address in enumerate(procedures, start=1)
        }
        self._functions = {
            address: f"FNFN{index}{_SUFFIXES.get(kind, '')}"
            for index, (address, kind) in enumerate(functions, start=1)
        }
        self._function_parameters: dict[tuple[int, int], str] = {}

    def statement(self, statement: Statement) -> Statement:
        if statement.kind == "SubDef":
            entry, parameters, body = statement.operands
            operands = (
                self._procedure(entry),
                self._value(parameters),
                tuple(self.statement(item) for item in body),
            )
            return Statement(statement.index, statement.address, statement.kind, operands)
        if statement.kind == "DefFn":
            entry, _result_kind, parameters, body, is_block = statement.operands
            parameter_names = tuple(
                self._function_parameter(parameter) for parameter in parameters
            )
            operands = (
                self._function(entry),
                parameter_names,
                tuple(self.statement(item) for item in body)
                if is_block
                else self._value(body),
                is_block,
            )
            return Statement(statement.index, statement.address, statement.kind, operands)
        if statement.kind == "IfInline":
            condition, body, else_body = statement.operands
            operands = (
                self._value(condition),
                tuple(self.statement(item) for item in body),
                None
                if else_body is None
                else tuple(self.statement(item) for item in else_body),
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

    def _function(self, address: object) -> object:
        return self._functions.get(address, ("function", address))

    def _function_parameter(self, parameter: object) -> object:
        if not (
            isinstance(parameter, tuple)
            and len(parameter) == 4
            and parameter[0] == "fn-param"
            and isinstance(parameter[1], int)
            and isinstance(parameter[2], int)
            and isinstance(parameter[3], str)
        ):
            return parameter
        name = self._new_name() + _SUFFIXES.get(parameter[3], "")
        self._function_parameters[(parameter[1], parameter[2])] = name
        return name

    def _value(self, value: object) -> object:
        if not isinstance(value, tuple) or not value:
            return value
        if value[0] == "slot" and len(value) >= 3 and isinstance(value[2], int):
            return self._variable(value)
        if (
            value[0] == "fn-param"
            and len(value) == 4
            and isinstance(value[1], int)
            and isinstance(value[2], int)
        ):
            name = self._function_parameters.get((value[1], value[2]))
            return ("var", name) if name is not None else value
        if value[0] == "fn-call" and len(value) in {3, 4}:
            return (
                "call",
                self._function(value[1]),
                tuple(self._value(argument) for argument in value[2]),
            )
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
