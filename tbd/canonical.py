from __future__ import annotations

from tbd.ir import Operation, Slot, Statement
from tbd.operation_helpers import unresolved_call_arguments as _unresolved

_COMMUTATIVE = {"+", "*"}
_RESERVED = {"AS", "AT", "DO", "FN", "GO", "IF", "LN", "ON", "OR", "PI", "TO"}
_SUFFIXES = {"integer": "%", "long": "&", "string": "$", "double": "#"}


def canonicalize(
    statements: tuple[Statement, ...],
    slots: tuple[Slot, ...],
    *,
    instructions: tuple[Operation, ...] = (),
) -> tuple[Statement, ...]:
    """Convert recovered facts into stable source-level statements."""

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
    statements = _move_initial_dims_after_assignments(statements)
    names = _Names(slots, procedures, functions)
    named = tuple(names.statement(statement) for statement in statements)
    normalized = tuple(_normalize_statement(statement) for statement in named)
    procedure_indices = {
        statement.index for statement in normalized if statement.kind == "SubDef"
    }
    function_addresses = {
        statement.address for statement in normalized if statement.kind == "DefFn"
    }
    do_indices = {statement.index for statement in normalized if statement.kind == "Do"}
    loop_entry_indices = do_indices | {index + 1 for index in do_indices}
    survivors = tuple(
        statement
        for statement in normalized
        if not (
            statement.kind == "Goto"
            and (
                (
                    len(statement.operands) == 1
                    and statement.operands[0] in procedure_indices
                )
                or (
                    len(statement.operands) == 1
                    and statement.operands[0] in loop_entry_indices
                )
                or statement.address in function_addresses
            )
        )
    )
    old_indices = {statement.index: index for index, statement in enumerate(survivors)}
    old_indices = _thread_removed_jumps(normalized, old_indices)
    normalized = tuple(
        Statement(
            index,
            statement.address,
            statement.kind,
            _remap_statement_targets(statement, old_indices),
        )
        for index, statement in enumerate(survivors)
    )
    normalized = _normalize_address_targets(normalized)
    aliases = _marker_aliases(instructions)
    addresses = _statement_addresses(normalized)
    aliases = {
        source: target
        for source, target in aliases.items()
        if source not in addresses and target in addresses
    }
    return tuple(_retarget_markers(statement, aliases) for statement in normalized)


def _thread_removed_jumps(
    statements: tuple[Statement, ...], old_indices: dict[int, int]
) -> dict[int, int]:
    """Extend the index map through the structural jumps that were removed.

    Canonicalization drops declaration and loop-entry jumps.  Branching to one
    of them transfers control to its destination, so a target naming a removed
    jump is threaded along that chain to the first surviving statement.  Chains
    that close a cycle or end outside the program keep their original value, and
    surviving statements are never rerouted.
    """
    removed = {
        statement.index: statement.operands[0]
        for statement in statements
        if statement.index not in old_indices
        and statement.kind == "Goto"
        and len(statement.operands) == 1
        and isinstance(statement.operands[0], int)
    }
    threaded = dict(old_indices)
    for start, first in removed.items():
        seen = {start}
        cursor = first
        while cursor in removed and cursor not in seen:
            seen.add(cursor)
            cursor = removed[cursor]
        if cursor in old_indices:
            threaded[start] = old_indices[cursor]
    return threaded


def _statement_addresses(value: object) -> set[int]:
    if isinstance(value, Statement):
        return {value.address} | _statement_addresses(value.operands)
    if isinstance(value, tuple):
        return {address for item in value for address in _statement_addresses(item)}
    return set()


def _retarget_markers(value: object, aliases: dict[int, int]) -> object:
    if isinstance(value, Statement):
        return Statement(
            value.index,
            value.address,
            value.kind,
            _retarget_markers(value.operands, aliases),
        )
    if isinstance(value, tuple):
        if len(value) == 2 and value[0] == "address" and isinstance(value[1], int):
            return "address", aliases.get(value[1], value[1])
        return tuple(_retarget_markers(item, aliases) for item in value)
    return value


def _marker_aliases(instructions: tuple[Operation, ...]) -> dict[int, int]:
    """Alias only contiguous compiler statement markers, never unknown bytes."""
    aliases = {}
    for marker, following in reversed(tuple(zip(instructions, instructions[1:]))):
        if (
            marker.kind == "x86.int3"
            and marker.size == 1
            and marker.raw == "cc"
            and marker.end == following.offset
        ):
            aliases[marker.offset] = aliases.get(following.offset, following.offset)
    return aliases


def _normalize_address_targets(
    statements: tuple[Statement, ...],
    address_map: dict[int, int] | None = None,
) -> tuple[Statement, ...]:
    """Replace physical GOTO targets with statement indices when available."""
    addresses = address_map or {
        statement.address: statement.index
        for statement in statements
        if isinstance(statement.address, int)
    }
    result = []
    for statement in statements:
        operands = statement.operands
        if statement.kind == "Goto" and len(operands) == 1:
            target = operands[0]
            if (
                isinstance(target, tuple)
                and len(target) == 2
                and target[0] == "address"
            ):
                operands = (addresses.get(target[1], target),)
        elif statement.kind == "IfInline" and len(operands) == 3:
            condition, body, else_body = operands
            operands = (
                condition,
                _normalize_address_targets(body, addresses),
                (
                    None
                    if else_body is None
                    else _normalize_address_targets(else_body, addresses)
                ),
            )
        result.append(
            Statement(statement.index, statement.address, statement.kind, operands)
        )
    return tuple(result)


def _remap_statement_targets(
    statement: Statement, old_indices: dict[int, int]
) -> tuple[object, ...]:
    """Adjust numeric targets after structural declaration jumps are removed."""
    operands = statement.operands
    kind = statement.kind
    if kind in {"Goto", "Gosub", "Return", "Resume", "OnError"} and len(operands) == 1:
        targets = (0,)
    elif (kind == "IfGoto" and len(operands) >= 2) or (
        kind == "OnTrap" and len(operands) == 3
    ):
        targets = (len(operands) - 1,)
    elif kind in {"OnGoto", "OnGosub"} and len(operands) >= 2:
        targets = tuple(range(1, len(operands)))
    else:
        return operands
    return tuple(
        (
            old_indices.get(value, value)
            if index in targets and isinstance(value, int)
            else value
        )
        for index, value in enumerate(operands)
    )


def _move_initial_dims_after_assignments(
    statements: tuple[Statement, ...],
) -> tuple[Statement, ...]:
    """Match compiler ordering when DIM setup shares the program prologue."""
    prefix = []
    index = 0
    while index < len(statements) and statements[index].kind == "Dim":
        prefix.append(statements[index])
        index += 1
    if not prefix:
        return statements
    assignments = []
    while (
        index < len(statements)
        and statements[index].kind == "Assign"
        and not (
            statements[index].operands
            and isinstance(statements[index].operands[0], tuple)
            and statements[index].operands[0][:1] == ("array",)
        )
    ):
        assignments.append(statements[index])
        index += 1
    if not assignments:
        return statements
    if not any(
        len(statement.operands) > 1
        and isinstance(statement.operands[1], tuple)
        and statement.operands[1][:2] in {("call", "ERR"), ("call", "ERL")}
        for statement in assignments
    ):
        return statements
    return tuple(assignments + prefix + list(statements[index:]))


def _normalize_statement(statement: Statement) -> Statement:
    operands = statement.operands
    if statement.kind == "Assign":
        operands = (
            normalize_expression(operands[0]),
            normalize_expression(operands[1]),
        )
    elif statement.kind == "Local":
        declared = operands[0] if len(operands) == 1 else ()
        if not (
            isinstance(declared, tuple)
            and declared
            and all(
                isinstance(item, tuple) and item and item[:1] in {("array",), ("var",)}
                for item in declared
            )
        ):
            operands = ()
    elif statement.kind == "Erase":
        operands = statement.operands
    elif statement.kind in {"Lset", "Rset", "Swap"}:
        operands = (
            normalize_expression(operands[0]),
            normalize_expression(operands[1]),
        )
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
    elif statement.kind == "LineInput" and len(operands) == 4:
        file_number, prompt, target, leading_semicolon = operands
        operands = (
            (
                file_number
                if isinstance(file_number, int)
                else (
                    None if file_number is None else normalize_expression(file_number)
                )
            ),
            None if prompt is None else normalize_expression(prompt),
            normalize_expression(target),
            leading_semicolon,
        )
    elif statement.kind == "Width" and len(operands) == 2:
        target, width = operands
        operands = (
            (
                (
                    "file",
                    normalize_expression(target[1]),
                )
                if isinstance(target, tuple)
                and len(target) == 2
                and target[0] == "file"
                else (None if target is None else normalize_expression(target))
            ),
            normalize_expression(width),
        )
    elif statement.kind in {"Bload", "Bsave"} and len(operands) == 3:
        filename, offset, length = operands
        operands = (
            normalize_expression(filename),
            None if offset is None else normalize_expression(offset),
            None if length is None else normalize_expression(length),
        )
    elif statement.kind in {"Get", "Put", "Seek"} and len(operands) == 2:
        file_number, position = operands
        operands = (
            normalize_expression(file_number),
            None if position is None else normalize_expression(position),
        )
    elif statement.kind in {"PutString", "Ioctl"} and len(operands) == 2:
        operands = tuple(normalize_expression(operand) for operand in operands)
    elif statement.kind == "GetString" and len(operands) == 3:
        operands = tuple(normalize_expression(operand) for operand in operands)
    elif statement.kind == "Name" and len(operands) == 2:
        operands = tuple(normalize_expression(operand) for operand in operands)
    elif statement.kind == "KeyDef" and len(operands) == 2:
        operands = tuple(normalize_expression(operand) for operand in operands)
    elif statement.kind == "Open":
        operands = (
            normalize_expression(operands[0]),
            operands[1],
            normalize_expression(operands[2]),
            None if operands[3] is None else normalize_expression(operands[3]),
            operands[4],
        )
    elif statement.kind == "Close":
        operands = (None if operands[0] is None else normalize_expression(operands[0]),)
    elif statement.kind in {"Color", "Screen"}:
        operands = tuple(
            None if operand is None else normalize_expression(operand)
            for operand in operands
        )
    elif statement.kind in {"Pset", "Preset"}:
        step, x, y, color = operands
        operands = (
            step,
            normalize_expression(x),
            normalize_expression(y),
            None if color is None else normalize_expression(color),
        )
    elif statement.kind == "LineStmt":
        first_step, x1, y1, second_step, x2, y2, color, box, style = operands
        operands = (
            first_step,
            None if x1 is None else normalize_expression(x1),
            None if y1 is None else normalize_expression(y1),
            second_step,
            normalize_expression(x2),
            normalize_expression(y2),
            None if color is None else normalize_expression(color),
            box,
            None if style is None else normalize_expression(style),
        )
    elif statement.kind == "View":
        screen, x1, y1, x2, y2, fill, border = operands
        operands = (
            screen,
            *(
                None if value is None else normalize_expression(value)
                for value in (x1, y1, x2, y2, fill, border)
            ),
        )
    elif statement.kind == "Window":
        screen, x1, y1, x2, y2 = operands
        operands = (
            screen,
            *(normalize_expression(value) for value in (x1, y1, x2, y2)),
        )
    elif statement.kind == "Circle":
        step, x, y, radius, color, start, end, aspect = operands
        operands = (
            step,
            *(normalize_expression(value) for value in (x, y, radius)),
            *(
                None if value is None else normalize_expression(value)
                for value in (color, start, end, aspect)
            ),
        )
    elif statement.kind == "Paint":
        x, y, fill, border = operands
        operands = (
            normalize_expression(x),
            normalize_expression(y),
            None if fill is None else normalize_expression(fill),
            None if border is None else normalize_expression(border),
        )
    elif statement.kind == "GetGfx":
        x1, y1, x2, y2, name = operands
        operands = (
            *(normalize_expression(value) for value in (x1, y1, x2, y2)),
            name,
        )
    elif statement.kind == "PutGfx":
        x, y, name, action = operands
        operands = normalize_expression(x), normalize_expression(y), name, action
    elif statement.kind == "Files":
        operands = (None if operands[0] is None else normalize_expression(operands[0]),)
    elif statement.kind in {
        "Chain",
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
    elif statement.kind in {"CallAbsolute", "Randomize"}:
        operands = (normalize_expression(operands[0]),)
    elif statement.kind == "ErrorStmt" and len(operands) == 1:
        operands = (normalize_expression(operands[0]),)
    elif statement.kind in {"CallInterrupt", "RegSet"}:
        operands = tuple(normalize_expression(operand) for operand in operands)
    elif statement.kind in {"Palette", "Poke", "Sound"}:
        operands = tuple(normalize_expression(operand) for operand in operands)
    elif statement.kind == "For":
        operands = tuple(normalize_expression(operand) for operand in operands)
    elif statement.kind == "NextStmt":
        operands = (normalize_expression(operands[0]),)
    elif statement.kind in {"Do", "Loop"}:
        kind, condition = operands
        if isinstance(condition, tuple):
            condition = _normalize_condition(condition)
        operands = kind, condition
    elif statement.kind == "TrapCtl":
        operands = (
            operands[0],
            None if operands[1] is None else normalize_expression(operands[1]),
            operands[2],
        )
    elif statement.kind == "DefType":
        operands = ()
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
        operands = (
            mode,
            # A comma tabs to the next print zone, so it is kept.
            tuple(
                item if item == ("print-separator", ",") else normalize_expression(item)
                for item in items
            ),
            newline,
        )
    elif statement.kind == "Write":
        file_number, items = operands
        operands = file_number, tuple(normalize_expression(item) for item in items)
    elif statement.kind == "Field":
        file_number, fields = operands
        operands = (
            file_number,
            tuple(
                (normalize_expression(width), normalize_expression(target))
                for width, target in fields
            ),
        )
    elif statement.kind == "IfGoto":
        *condition, target = operands
        normalized_condition = _normalize_condition(tuple(condition))
        operands = (
            (*normalized_condition, target)
            if isinstance(normalized_condition, tuple)
            else (normalized_condition, target)
        )
    elif statement.kind == "IfInline":
        condition, body, else_body = operands
        operands = (
            _normalize_condition(condition),
            tuple(_normalize_statement(item) for item in body),
            (
                None
                if else_body is None
                else tuple(_normalize_statement(item) for item in else_body)
            ),
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
            (
                tuple(_normalize_statement(item) for item in body)
                if is_block
                else normalize_expression(body)
            ),
            is_block,
        )
    elif statement.kind == "FnResult":
        operands = (normalize_expression(operands[0]),)
    elif statement.kind in {"Incr", "Decr"}:
        operands = (normalize_expression(operands[0]),)
    elif statement.kind == "CallStmt":
        name, arguments = operands
        if not _unresolved(arguments):
            arguments = tuple(normalize_expression(item) for item in arguments)
        operands = name, arguments
    return Statement(statement.index, statement.address, statement.kind, operands)


def _normalize_condition(value: object) -> object:
    """Canonicalize condition grouping and bare boolean expressions."""
    if not isinstance(value, tuple) or not value:
        return value
    if len(value) == 2 and value[0] == "group":
        return "group", _normalize_condition(value[1])
    if len(value) == 2 and value[0] == "truth":
        return "truth", normalize_expression(value[1])
    if len(value) == 3 and value[0] == "unary" and value[1] == "NOT":
        operand = normalize_expression(value[2])
        if isinstance(operand, tuple) and len(operand) >= 2 and operand[0] == "var":
            rendered = f"Not(operand=Var(name={operand[1]!r}))"
        else:
            rendered = f"Not(operand={operand!r})"
        return "truth", ("unsupported-expression", "Not", rendered)
    if len(value) == 3:
        return (
            value[0],
            (
                _normalize_condition(value[1])
                if value[0] in {"AND", "OR"}
                else normalize_expression(value[1])
            ),
            (
                _normalize_condition(value[2])
                if value[0] in {"AND", "OR"}
                else normalize_expression(value[2])
            ),
        )
    return value


def normalize_expression(value: object) -> object:
    """Normalize an expression recursively for deterministic output."""

    if not isinstance(value, tuple) or not value:
        return value
    if len(value) == 2 and value[0] == "group":
        return "group", _normalize_condition(value[1])
    if value[0] in {"=", "<>", "<", "<=", ">", ">="} and len(value) == 3:
        return (
            "binary",
            value[0],
            normalize_expression(value[1]),
            normalize_expression(value[2]),
        )
    if value[0] == "slot":
        return value
    if value[0] == "binary" and len(value) == 4:
        left = normalize_expression(value[2])
        right = normalize_expression(value[3])
        commutative = value[1] in _COMMUTATIVE and not (
            value[1] == "+"
            and (_is_string_expression(left) or _is_string_expression(right))
        )
        comparison_first = (
            value[1] == "*"
            and isinstance(left, tuple)
            and left[:1] == ("const",)
            and isinstance(right, tuple)
            and right[:1] in {("<",), (">",), ("=",), ("<>",), ("<=",), (">=",)}
        )
        comparison_last = (
            value[1] == "*"
            and isinstance(left, tuple)
            and left[:1] in {("<",), (">",), ("=",), ("<>",), ("<=",), (">=",)}
            and isinstance(right, tuple)
            and right[:1] == ("const",)
        )
        if (
            commutative
            and not comparison_last
            and (comparison_first or _expression_key(right) < _expression_key(left))
        ):
            left, right = right, left
        # The compiler subtracts a constant by adding its negation; the
        # source said ``x - c``.
        if (
            value[1] == "+"
            and isinstance(right, tuple)
            and len(right) == 2
            and right[0] == "const"
            and isinstance(right[1], (int, float))
            and right[1] < 0
        ):
            return "binary", "-", left, ("const", -right[1])
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
    if not isinstance(tag, str):
        tag = None
    rank = {
        "slot": 0,
        "var": 0,
        "array": 0,
        "binary": 1,
        "const": 2,
        "string": 3,
    }.get(tag if tag is not None else "", 4)
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
        # A SELECT CASE scratch cell gets a name of its own, so naming it does
        # not shift the letters every other variable receives.
        selects = sorted(slot.offset for slot in slots if slot.name.startswith("SEL"))
        for number, offset in enumerate(selects, start=1):
            self._names[offset] = f"SEL{number}"
        self._procedures = {
            address: f"SUB{index}" for index, address in enumerate(procedures, start=1)
        }
        self._functions: dict[int, str] = {}
        for index, (address, kind) in enumerate(functions, start=1):
            if isinstance(address, int):
                suffix = kind if isinstance(kind, str) else ""
                self._functions[address] = f"FNFN{index}{_SUFFIXES.get(suffix, '')}"
        self._function_parameters: dict[tuple[int, int], str] = {}
        self._function_locals: dict[tuple[int, int], str] = {}
        self._function_local_arrays: dict[tuple[int, int], str] = {}
        self._procedure_parameters: dict[tuple[int, int], str] = {}
        self._procedure_array_parameters: dict[tuple[int, int], str] = {}
        self._procedure_locals: dict[tuple[int, int], str] = {}

    def statement(self, statement: Statement) -> Statement:
        operands: tuple[object, ...]
        if statement.kind == "SubDef":
            entry, parameters, body = statement.operands
            parameter_names = tuple(
                self._procedure_parameter(parameter) for parameter in parameters
            )
            body = tuple(self.statement(item) for item in body)
            if (
                len(body) == 3
                and body[0].kind == "IfGoto"
                and body[1].kind == "ExitSub"
                and body[2].kind == "Print"
                and len(body[0].operands) == 4
                and body[0].operands[0] == "<>"
            ):
                _relation, left, right, _target = body[0].operands
                body = (
                    Statement(
                        body[0].index,
                        body[0].address,
                        "IfInline",
                        (("=", left, right), (body[2],), None),
                    ),
                )
            operands = (
                self._procedure(entry),
                parameter_names,
                body,
            )
            return Statement(
                statement.index, statement.address, statement.kind, operands
            )
        if statement.kind == "DefFn":
            entry, _result_kind, parameters, body, is_block = statement.operands
            if is_block and isinstance(entry, int) and isinstance(body, tuple):
                self._seed_function_local_arrays(entry, body)
            parameter_names = tuple(
                self._function_parameter(parameter) for parameter in parameters
            )
            operands = (
                self._function(entry),
                parameter_names,
                (
                    tuple(self.statement(item) for item in body)
                    if is_block
                    else self._value(body)
                ),
                is_block,
            )
            return Statement(
                statement.index, statement.address, statement.kind, operands
            )
        if statement.kind == "Dim" and len(statement.operands) == 4:
            name, bounds, also, dynamic = statement.operands
            operands = (
                self._function_local_array_name(name) or name,
                self._value(bounds),
                tuple(
                    (
                        self._function_local_array_name(other_name) or other_name,
                        self._value(other_bounds),
                    )
                    for other_name, other_bounds in also
                ),
                dynamic,
            )
            return Statement(
                statement.index, statement.address, statement.kind, operands
            )
        if statement.kind == "Erase" and len(statement.operands) == 1:
            name = self._function_local_array_name(statement.operands[0])
            operands = (name,) if name is not None else statement.operands
            return Statement(
                statement.index, statement.address, statement.kind, operands
            )
        if statement.kind == "IfInline":
            condition, body, else_body = statement.operands
            operands = (
                self._value(condition),
                tuple(self.statement(item) for item in body),
                (
                    None
                    if else_body is None
                    else tuple(self.statement(item) for item in else_body)
                ),
            )
            return Statement(
                statement.index, statement.address, statement.kind, operands
            )
        if statement.kind == "IfBlock":
            arms, else_body = statement.operands
            operands = (
                tuple(
                    (
                        self._value(condition),
                        tuple(self.statement(item) for item in body),
                    )
                    for condition, body in arms
                ),
                (
                    None
                    if else_body is None
                    else tuple(self.statement(item) for item in else_body)
                ),
            )
            return Statement(
                statement.index, statement.address, statement.kind, operands
            )
        if statement.kind == "CallStmt":
            target, arguments = statement.operands
            operands = self._procedure(target), self._value(arguments)
            return Statement(
                statement.index, statement.address, statement.kind, operands
            )
        operands = tuple(self._value(value) for value in statement.operands)
        return Statement(statement.index, statement.address, statement.kind, operands)

    def _procedure(self, address: object) -> object:
        return (
            self._procedures.get(address, ("procedure", address))
            if isinstance(address, int)
            else ("procedure", address)
        )

    def _function(self, address: object) -> object:
        return (
            self._functions.get(address, ("function", address))
            if isinstance(address, int)
            else ("function", address)
        )

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

    def _procedure_parameter(self, parameter: object) -> object:
        if (
            isinstance(parameter, tuple)
            and len(parameter) == 5
            and parameter[0] == "proc-array-param"
            and isinstance(parameter[1], int)
            and isinstance(parameter[2], int)
            and isinstance(parameter[3], str)
            and isinstance(parameter[4], int)
        ):
            name = self._new_name() + _SUFFIXES.get(parameter[3], "")
            self._procedure_array_parameters[(parameter[1], parameter[2])] = name
            return f"{name}({parameter[4]})"
        if not (
            isinstance(parameter, tuple)
            and len(parameter) == 4
            and parameter[0] == "proc-param"
            and isinstance(parameter[1], int)
            and isinstance(parameter[2], int)
            and isinstance(parameter[3], str)
        ):
            return parameter
        name = self._new_name() + _SUFFIXES.get(parameter[3], "")
        self._procedure_parameters[(parameter[1], parameter[2])] = name
        return name

    def _value(self, value: object) -> object:
        if not isinstance(value, tuple) or not value:
            return value
        if value[0] == "slot" and len(value) >= 3 and isinstance(value[2], int):
            return self._variable(value)
        if self._names_recovered_slot(value):
            return self._variable(("slot", None, value[1], value[2]))
        if (
            value[0] == "fn-param"
            and len(value) == 4
            and isinstance(value[1], int)
            and isinstance(value[2], int)
        ):
            name = self._function_parameters.get((value[1], value[2]))
            return ("var", name) if name is not None else value
        if (
            value[0] == "fn-local"
            and len(value) == 4
            and isinstance(value[1], int)
            and isinstance(value[2], int)
            and isinstance(value[3], str)
        ):
            key = value[1], value[2]
            if key not in self._function_locals:
                self._function_locals[key] = self._new_name() + _SUFFIXES.get(
                    value[3], ""
                )
            return "var", self._function_locals[key]
        if value[0] == "fn-local-array" and len(value) == 4:
            name = self._function_local_array_name(value)
            return ("array", name, ()) if name is not None else value
        if value[0] == "fn-local-array-element" and len(value) == 5:
            name = self._function_local_array_name(value)
            return (
                (
                    "array",
                    name,
                    tuple(self._value(index) for index in value[4]),
                )
                if name is not None
                else value
            )
        if (
            value[0] == "proc-array-param"
            and len(value) == 5
            and isinstance(value[1], int)
            and isinstance(value[2], int)
        ):
            name = self._procedure_array_parameters.get((value[1], value[2]))
            return ("array", name, ()) if name is not None else value
        if (
            value[0] == "proc-array-element"
            and len(value) == 6
            and isinstance(value[1], int)
            and isinstance(value[2], int)
            and isinstance(value[5], tuple)
        ):
            name = self._procedure_array_parameters.get((value[1], value[2]))
            return (
                (
                    "array",
                    name,
                    tuple(self._value(index) for index in value[5]),
                )
                if name is not None
                else value
            )
        if (
            value[0] == "proc-param"
            and len(value) == 4
            and isinstance(value[1], int)
            and isinstance(value[2], int)
        ):
            name = self._procedure_parameters.get((value[1], value[2]))
            return ("var", name) if name is not None else value
        if (
            value[0] == "proc-local"
            and len(value) == 4
            and isinstance(value[1], int)
            and isinstance(value[2], int)
            and isinstance(value[3], str)
        ):
            key = value[1], value[2]
            if key not in self._procedure_locals:
                self._procedure_locals[key] = self._new_name() + _SUFFIXES.get(
                    value[3], ""
                )
            return "var", self._procedure_locals[key]
        if value[0] == "fn-call" and len(value) in {3, 4}:
            return (
                "call",
                self._function(value[1]),
                tuple(self._value(argument) for argument in value[2]),
            )
        return tuple(self._value(item) for item in value)

    def _seed_function_local_arrays(
        self, entry: int, body: tuple[Statement, ...]
    ) -> None:
        for statement in body:
            if statement.kind == "Local":
                continue
            self._find_function_local_arrays(entry, statement.operands)

    def _find_function_local_arrays(self, entry: int, value: object) -> None:
        if isinstance(value, Statement):
            self._find_function_local_arrays(entry, value.operands)
            return
        if not isinstance(value, tuple) or not value:
            return
        if value[0] in {"fn-local-array", "fn-local-array-element"} and value[1:2] == (
            entry,
        ):
            self._function_local_array_name(value)
            return
        for item in value:
            self._find_function_local_arrays(entry, item)

    def _function_local_array_name(self, value: object) -> str | None:
        if not (
            isinstance(value, tuple)
            and len(value) in {4, 5}
            and value[0] in {"fn-local-array", "fn-local-array-element"}
            and isinstance(value[1], int)
            and isinstance(value[2], int)
            and isinstance(value[3], str)
        ):
            return None
        key = value[1], value[2]
        if key not in self._function_local_arrays:
            index = sum(
                owner == value[1] for owner, _offset in self._function_local_arrays
            )
            self._function_local_arrays[key] = f"V{index}{_SUFFIXES.get(value[3], '')}"
        return self._function_local_arrays[key]

    def _names_recovered_slot(self, value: tuple[object, ...]) -> bool:
        """Report whether a raw memory reference names a recovered slot.

        Some passes still describe a scalar by its address.  Naming it is only
        safe when slot materialization already recovered that exact address and
        agreed on the type the reference uses; anything else stays opaque.
        """
        return (
            value[0] == "memory"
            and len(value) == 3
            and isinstance(value[1], int)
            and isinstance(value[2], str)
            and value[2] in self._types.get(value[1], ())
        )

    def _variable(self, slot: tuple[object, ...]) -> tuple[object, ...]:
        address = slot[2]
        if not isinstance(address, int):
            return "var", str(address)
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
