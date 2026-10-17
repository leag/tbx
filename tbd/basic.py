"""Best-effort rendering of TBD's canonical IR as Turbo Basic source."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace

from tbd.canonical import _remap_statement_targets
from tbd.ir import Program, Statement
from tbd.operation_helpers import unresolved_call_arguments as _unresolved


class BasicTranslationError(ValueError):
    """A recovered statement cannot be represented by the simple emitter."""


_EXPRESSION_TAGS = {
    "array",
    "binary",
    "call",
    "const",
    "group",
    "string",
    "unary",
    "var",
}
_BINARY_PRECEDENCE = {
    "OR": 1,
    "AND": 2,
    "=": 3,
    "<>": 3,
    "<": 3,
    "<=": 3,
    ">": 3,
    ">=": 3,
    "+": 4,
    "-": 4,
    "*": 5,
    "/": 5,
    "\\": 5,
    "MOD": 5,
    "^": 6,
}
_RIGHT_SENSITIVE = {"-", "/", "\\", "MOD", "^"}
_BARE_NULLARY_INTRINSICS = {
    "COMMAND$",
    "CSRLIN",
    "DATE$",
    "ERL",
    "ERR",
    "ERDEV$",
    "INKEY$",
    "INSTAT",
    "MTIMER",
    "RND",
    "TIME$",
    "TIMER",
}
_BARE_STATEMENTS = {
    "Beep": "BEEP",
    "Clear": "CLEAR",
    "Cls": "CLS",
    "End": "END",
    "ExitDef": "EXIT DEF",
    "ExitLoop": "EXIT LOOP",
    "ExitSub": "EXIT SUB",
    "KeyList": "KEY LIST",
    "Mtimer": "MTIMER",
    "Rem": "REM",
    "Reset": "RESET",
    "Segment": "$SEGMENT",
    "Stop": "STOP",
    "System": "SYSTEM",
    "Troff": "TROFF",
    "Tron": "TRON",
}
_SINGLE_EXPRESSION_STATEMENTS = {
    "Chain": "CHAIN",
    "Chdir": "CHDIR",
    "Draw": "DRAW",
    "Environ": "ENVIRON",
    "Kill": "KILL",
    "Mkdir": "MKDIR",
    "Play": "PLAY",
    "Rmdir": "RMDIR",
    "Shell": "SHELL",
}


def to_basic(program: Program, *, strict: bool = False) -> str:
    """Render the best recovered statement stream as compilable BASIC.

    Canonical statements are preferred because they carry stable source-level
    names. Unsupported statements become explicit REM lines unless ``strict``
    is true, in which case :class:`BasicTranslationError` is raised.
    """

    statements = program.canonical_statements or program.statements
    hooks = {
        instruction.offset: instruction.end
        for instruction in program.instructions
        if instruction.kind == "x86.int3"
    }
    epilogue = next(
        (
            instruction.offset
            for instruction in program.instructions
            if instruction.kind == "tb.epilogue"
        ),
        None,
    )
    return emit_basic(statements, strict=strict, hooks=hooks, epilogue=epilogue)


def emit_basic(
    statements: Sequence[Statement],
    *,
    strict: bool = False,
    first_line: int = 10,
    line_step: int = 10,
    hooks: Mapping[int, int] | None = None,
    epilogue: int | None = None,
) -> str:
    """Render canonical statements as numbered Turbo Basic source lines.

    ``hooks`` maps the address of each event-trap poll stamp (``int3``) to
    the address after it.  The compiler places one before a statement, and a
    branch that lands on it lands on that statement.  ``epilogue`` is the
    address of the compiled end of the main program; a branch there is a jump
    to the program's end, written as a final ``REM`` line: falling off the
    last line is that end, and a REM compiles to no code, where an ``END``
    the source did not have would.
    """

    if first_line <= 0 or line_step <= 0:
        raise ValueError("BASIC line numbers must be positive")
    sequence = _blockify(tuple(statements))
    if (
        epilogue is not None
        and epilogue in _branch_targets(sequence)
        and epilogue not in _statement_addresses(sequence)
    ):
        index = max((statement.index for statement in sequence), default=-1) + 1
        sequence = (*sequence, Statement(index, epilogue, "Rem", ()))
    sequence = _subs_out_of_loops(sequence)
    sequence = _exits_without_loop(sequence, [0])
    layout = _number_scope(sequence, [first_line], line_step)
    for hook in sorted(hooks or {}, reverse=True):
        after = hook
        while after in (hooks or {}) and after not in layout.addresses:
            after = (hooks or {})[after]
        if hook not in layout.addresses and after in layout.addresses:
            layout.addresses[hook] = layout.addresses[after]
    _alias_block_targets(sequence, layout.addresses)
    lines = _emit_scope(sequence, layout, strict)
    if not lines:
        return "10 REM TBD: no recoverable statements\n20 END\n"
    return "\n".join(lines) + "\n"


def _exits_without_loop(
    sequence: tuple[Statement, ...], depth: list[int]
) -> tuple[Statement, ...]:
    """Write an EXIT LOOP no recovered DO encloses as the jump it compiles to.

    A LOOP that is not the one jump back to its DO is written as its jump
    and the DO dropped, which leaves the loop's exits outside any loop;
    Turbo Basic rejects that (error 435, ``stat.exe``). ``depth`` counts the
    DOs open in document order, across IF bodies; a procedure has its own.
    """
    result = []
    for statement in sequence:
        if statement.kind == "Do":
            depth[0] += 1
        elif statement.kind == "Loop":
            depth[0] = max(0, depth[0] - 1)
        elif statement.kind == "ExitLoop" and depth[0] == 0 and statement.operands:
            statement = replace(
                statement, kind="Goto", operands=(("address", statement.operands[0]),)
            )
        elif statement.kind in {"SubDef", "DefFn"}:
            position = 2 if statement.kind == "SubDef" else 3
            body = statement.operands[position]
            if isinstance(body, tuple):
                operands = list(statement.operands)
                operands[position] = _exits_without_loop(body, [0])
                statement = replace(statement, operands=tuple(operands))
        elif statement.kind == "IfBlock" and len(statement.operands) == 2:
            arms, else_body = statement.operands
            arms = tuple(
                (condition, _exits_without_loop(body, depth))
                for condition, body in arms
            )
            if else_body is not None:
                else_body = _exits_without_loop(else_body, depth)
            statement = replace(statement, operands=(arms, else_body))
        elif statement.kind == "IfInline" and len(statement.operands) == 3:
            condition, body, else_body = statement.operands
            body = _exits_without_loop(body, depth)
            if else_body is not None:
                else_body = _exits_without_loop(else_body, depth)
            statement = replace(statement, operands=(condition, body, else_body))
        result.append(statement)
    return tuple(result)


def _subs_out_of_loops(sequence: tuple[Statement, ...]) -> tuple[Statement, ...]:
    """Move a SUB defined inside an open FOR loop after the program.

    Turbo Basic rejects a SUB inside a FOR (error 470), though a compiler
    placed one there in ``mf.exe``. A SUB runs only when called, so where
    it is defined does not change what the program does.
    """
    open_loops: list[object] = []
    kept, moved = [], []
    for statement in sequence:
        if statement.kind == "For" and statement.operands:
            open_loops.append(statement.operands[0])
        for variable in _next_variables(statement):
            if variable in open_loops:
                del open_loops[len(open_loops) - 1 - open_loops[::-1].index(variable) :]
        if statement.kind == "SubDef" and open_loops:
            moved.append(statement)
        else:
            kept.append(statement)
    return (*kept, *moved)


def _next_variables(value: object) -> list[object]:
    """Return the loop variables every NEXT in a statement tree closes."""
    if isinstance(value, Statement):
        if value.kind == "NextStmt":
            return list(value.operands)
        if value.kind == "SubDef":
            return []
        return _next_variables(value.operands)
    if isinstance(value, tuple):
        return [variable for item in value for variable in _next_variables(item)]
    return []


def _alias_block_targets(
    sequence: tuple[Statement, ...], addresses: dict[int, int]
) -> None:
    """Resolve a branch into a block IF with no statement of its own.

    At the top level a target with only unrecovered code at it names the
    next statement; a target inside a block IF is left for this pass, and
    names the next statement inside that block.
    """
    targets = _branch_targets(sequence)
    for block in _blocks(sequence):
        inner = sorted(_statement_addresses(block.operands))
        for target in targets:
            if target in addresses or not inner or not block.address < target:
                continue
            following = next((address for address in inner if address >= target), None)
            if following is not None and following in addresses:
                addresses[target] = addresses[following]


def _blocks(value: object) -> list[Statement]:
    """Collect every block IF in a statement tree, innermost last."""
    found: list[Statement] = []
    if isinstance(value, Statement):
        if value.kind == "IfBlock":
            found.append(value)
        return found + _blocks(value.operands)
    if isinstance(value, tuple):
        for item in value:
            found += _blocks(item)
    return found


def _branch_targets(value: object) -> set[int]:
    """Collect every ``("address", n)`` a statement tree branches to."""
    found: set[int] = set()
    if isinstance(value, Statement):
        return _branch_targets(value.operands)
    if isinstance(value, tuple):
        if len(value) == 2 and value[0] == "address" and isinstance(value[1], int):
            found.add(value[1])
        for item in value:
            found |= _branch_targets(item)
    return found


def _statement_addresses(value: object) -> set[int]:
    """Collect the address of every statement in a tree, nested ones too."""
    found: set[int] = set()
    if isinstance(value, Statement):
        found.add(value.address)
        return found | _statement_addresses(value.operands)
    if isinstance(value, tuple):
        for item in value:
            found |= _statement_addresses(item)
    return found


def _is_block(statement: Statement) -> bool:
    """Return whether a statement needs lines of its own to be written."""
    operands = statement.operands
    return statement.kind in {"IfBlock", "SubDef"} or (
        statement.kind == "DefFn" and len(operands) == 4 and operands[3] is True
    )


def _blockify(statements: tuple[Statement, ...]) -> tuple[Statement, ...]:
    """Rewrite inline IFs that hold a block statement as block IFs.

    ``IF c THEN s1: s2`` and a block IF over the same statements mean the
    same thing, but a block statement has no single-line form.  The rewrite is
    bottom-up, so an inline IF around one that was rewritten is rewritten too,
    and it happens before numbering so the nested statements get lines that
    branches can name.
    """
    # An inline IF's body branches to statements of the scope around it by
    # index; a block numbers its body on its own, so they become addresses.
    addresses = {
        statement.index: ("address", statement.address) for statement in statements
    }
    result = []
    for statement in statements:
        statement = _blockify_children(statement)
        statement = _inline_next(statement)
        if statement.kind == "IfInline" and len(statement.operands) == 3:
            condition, body, else_body = statement.operands
            branches = tuple(body) + (tuple(else_body) if else_body else ())
            if any(_is_block(item) for item in branches) or _swallowing_if(
                tuple(body), tuple(else_body) if else_body else ()
            ):
                body = _addressed(tuple(body), addresses)
                if else_body:
                    else_body = _addressed(tuple(else_body), addresses)
                statement = replace(
                    statement,
                    kind="IfBlock",
                    operands=(((condition, body),), else_body),
                )
        result.append(statement)
    return tuple(result)


def _addressed(
    statements: tuple[Statement, ...], addresses: dict[int, object]
) -> tuple[Statement, ...]:
    """Name an inline body's targets by address, inline IFs in it included."""
    result = []
    for statement in statements:
        operands = _remap_statement_targets(statement, addresses)
        if statement.kind == "IfInline" and len(operands) == 3:
            condition, body, else_body = operands
            operands = (
                condition,
                _addressed(tuple(body), addresses),
                None if else_body is None else _addressed(tuple(else_body), addresses),
            )
        result.append(replace(statement, operands=operands))
    return tuple(result)


def _inline_next(statement: Statement) -> Statement:
    """Write a one-arm block IF holding a NEXT as the one-line IF it was.

    ``IF c THEN NEXT I: GOTO 100`` is valid on one line, but as a block the
    NEXT closes a FOR opened outside the block, which does not nest.
    """
    if statement.kind != "IfBlock" or len(statement.operands) != 2:
        return statement
    arms, else_body = statement.operands
    if not isinstance(arms, tuple) or len(arms) != 1:
        return statement
    condition, body = arms[0]
    body = tuple(body)
    else_body = tuple(else_body) if else_body else ()
    branches = body + else_body
    if not any(item.kind == "NextStmt" for item in branches) or any(
        _is_block(item) for item in branches
    ):
        return statement
    if _swallowing_if(body, else_body) and not else_body:
        body = _else_of_nested_if(body)
    if _swallowing_if(body, else_body):
        return statement
    return replace(
        statement,
        kind="IfInline",
        operands=(condition, body, else_body or None),
    )


def _else_of_nested_if(body: tuple[Statement, ...]) -> tuple[Statement, ...]:
    """``IF d THEN t: s...`` on one line means ``IF d THEN GOTO t ELSE s...``.

    Only the first nested IF is rewritten, and only when nothing after it
    is an IF, so the ELSE holds exactly the statements that followed it.
    """
    nested = {"IfGoto", "IfInline"}
    first = next(
        (index for index, item in enumerate(body) if item.kind in nested), None
    )
    if first is None or body[first].kind != "IfGoto" or len(body[first].operands) < 2:
        return body
    rest = body[first + 1 :]
    if not rest or any(item.kind in nested for item in rest):
        return body
    branch = body[first]
    goto = replace(branch, kind="Goto", operands=(branch.operands[-1],))
    inline = replace(
        branch,
        kind="IfInline",
        operands=(tuple(branch.operands[:-1]), (goto,), rest),
    )
    return (*body[:first], inline)


def _swallowing_if(
    body: tuple[Statement, ...], else_body: tuple[Statement, ...]
) -> bool:
    """Whether a nested IF would take statements that are not its own.

    On one line, an IF's THEN runs to the end of the line and a trailing
    ELSE binds to the nearest IF, so a nested IF followed by statements, or
    one in a THEN that has an ELSE, needs the outer IF written as a block.
    """
    nested = {"IfGoto", "IfInline"}
    return (
        any(item.kind in nested for item in body[:-1])
        or bool(else_body and any(item.kind in nested for item in body))
        or any(item.kind in nested for item in else_body[:-1])
    )


def _blockify_children(statement: Statement) -> Statement:
    operands = statement.operands
    if statement.kind == "IfInline" and len(operands) == 3:
        condition, body, else_body = operands
        if isinstance(body, tuple):
            body = _blockify(body)
        if isinstance(else_body, tuple):
            else_body = _blockify(else_body)
        return replace(statement, operands=(condition, body, else_body))
    if statement.kind == "IfBlock" and len(operands) == 2:
        arms, else_body = operands
        if isinstance(arms, tuple):
            arms = tuple(
                (arm[0], _blockify(arm[1]))
                if isinstance(arm, tuple)
                and len(arm) == 2
                and isinstance(arm[1], tuple)
                else arm
                for arm in arms
            )
        if isinstance(else_body, tuple):
            else_body = _blockify(else_body)
        return replace(statement, operands=(arms, else_body))
    body_holder = statement.kind == "SubDef" and len(operands) == 3
    if body_holder and isinstance(operands[2], tuple):
        return replace(statement, operands=(*operands[:2], _blockify(operands[2])))
    multiline_function = statement.kind == "DefFn" and _is_block(statement)
    if multiline_function and isinstance(operands[2], tuple):
        return replace(
            statement, operands=(*operands[:2], _blockify(operands[2]), operands[3])
        )
    return statement


@dataclass(frozen=True)
class _ScopeLayout:
    labels: dict[int, int]
    children: dict[object, _ScopeLayout]
    addresses: dict[int, int]


def _number_scope(
    statements: tuple[Statement, ...], next_line: list[int], line_step: int
) -> _ScopeLayout:
    labels: dict[int, int] = {}
    children: dict[object, _ScopeLayout] = {}
    addresses: dict[int, int] = {}
    for statement in statements:
        labels[statement.index] = next_line[0]
        addresses[statement.address] = next_line[0]
        next_line[0] += line_step
        if statement.kind == "SubDef" and len(statement.operands) == 3:
            body = statement.operands[2]
            if isinstance(body, tuple):
                children[statement.index] = _number_scope(body, next_line, line_step)
                addresses.update(children[statement.index].addresses)
        if statement.kind == "IfBlock" and len(statement.operands) == 2:
            arms, else_body = statement.operands
            if isinstance(arms, tuple):
                for arm_index, arm in enumerate(arms):
                    if isinstance(arm, tuple) and len(arm) == 2:
                        body = arm[1]
                        if isinstance(body, tuple):
                            children[(statement.index, arm_index)] = _number_scope(
                                body, next_line, line_step
                            )
                            addresses.update(
                                children[(statement.index, arm_index)].addresses
                            )
            if isinstance(else_body, tuple):
                children[(statement.index, "else")] = _number_scope(
                    else_body, next_line, line_step
                )
                addresses.update(children[(statement.index, "else")].addresses)
        if (
            statement.kind == "DefFn"
            and len(statement.operands) == 4
            and statement.operands[3] is True
        ):
            body = statement.operands[2]
            if isinstance(body, tuple):
                children[statement.index] = _number_scope(body, next_line, line_step)
                addresses.update(children[statement.index].addresses)
    return _ScopeLayout(labels, children, addresses)


def _emit_scope(
    statements: tuple[Statement, ...],
    layout: _ScopeLayout,
    strict: bool,
    function_name: str | None = None,
    address_labels: dict[int, int] | None = None,
) -> list[str]:
    if address_labels is None:
        address_labels = layout.addresses
    emitter = _Emitter(layout.labels, function_name, address_labels)
    lines = []
    for statement in statements:
        line_number = emitter.labels[statement.index]
        try:
            if statement.kind == "SubDef":
                header, body = emitter.sub_definition(statement)
                lines.append(f"{line_number} {header}")
                lines.extend(
                    _emit_scope(
                        body,
                        layout.children[statement.index],
                        strict,
                        address_labels=address_labels,
                    )
                )
                lines.append("END SUB")
                continue
            if statement.kind == "DefFn":
                header, function_body, name = emitter.function_definition(statement)
                lines.append(f"{line_number} {header}")
                if function_body is not None:
                    lines.extend(
                        _emit_scope(
                            function_body,
                            layout.children[statement.index],
                            strict,
                            function_name=name,
                            address_labels=address_labels,
                        )
                    )
                    lines.append("END DEF")
                continue
            if statement.kind == "IfBlock" and len(statement.operands) == 2:
                arms, else_body = statement.operands
                if not isinstance(arms, tuple) or not arms:
                    raise emitter.error(statement, "empty block IF")
                for arm_index, arm in enumerate(arms):
                    if not isinstance(arm, tuple) or len(arm) != 2:
                        raise emitter.error(statement, "unresolved block IF arm")
                    condition, body = arm
                    if not isinstance(body, tuple):
                        raise emitter.error(statement, "unresolved block IF body")
                    keyword = "IF" if arm_index == 0 else "ELSEIF"
                    prefix = f"{line_number} " if arm_index == 0 else ""
                    lines.append(f"{prefix}{keyword} {_condition(condition)} THEN")
                    lines.extend(
                        _emit_scope(
                            body,
                            layout.children[(statement.index, arm_index)],
                            strict,
                            function_name=function_name,
                            address_labels=address_labels,
                        )
                    )
                if else_body is not None:
                    if not isinstance(else_body, tuple):
                        raise emitter.error(statement, "unresolved block ELSE body")
                    lines.append("ELSE")
                    lines.extend(
                        _emit_scope(
                            else_body,
                            layout.children[(statement.index, "else")],
                            strict,
                            function_name=function_name,
                            address_labels=address_labels,
                        )
                    )
                lines.append("END IF")
                continue
            rendered = emitter.statement(statement)
        except BasicTranslationError:
            if strict:
                raise
            rendered = _unsupported(statement)
        first, *rest = _split_long(emitter, statement, f"{line_number} {rendered}")
        lines.append(first)
        lines.extend(rest)
    return lines


_LINE_LIMIT = 240
"""Below the 249 characters the IDE's editor keeps on one line."""


def _split_long(emitter: _Emitter, statement: Statement, line: str) -> list[str]:
    """Write a PRINT or COMMON too long for the editor as several of its kind.

    ``PRINT a; b`` prints what ``PRINT a;`` and ``PRINT b`` print, two
    COMMON lists declare what their union does, and two $INLINE lines hold
    their bytes in order; the lines after the first need no numbers.
    """
    operands = statement.operands
    if len(line) <= _LINE_LIMIT:
        return [line]
    if statement.kind in {"Print", "Lprint"} and len(operands) == 3:
        mode, items, newline = operands
        items = tuple(_items(items))
        if any(
            isinstance(item, tuple) and item[:1] == ("print_using",) for item in items
        ):
            return [line]

        def render(chunk: tuple[object, ...], last: bool) -> str:
            return emitter.statement(
                replace(statement, operands=(mode, chunk, newline if last else False))
            )

    elif statement.kind == "Common" and len(operands) == 1:
        items = tuple(operands[0])

        def render(chunk: tuple[object, ...], last: bool) -> str:
            return emitter.statement(replace(statement, operands=(chunk,)))

    elif (
        statement.kind == "Inline"
        and len(operands) == 1
        and isinstance(operands[0], str)
    ):
        # Consecutive $INLINE lines place their bytes one after another.
        items = tuple(f"{byte:02x}" for byte in bytes.fromhex(operands[0]))

        def render(chunk: tuple[object, ...], last: bool) -> str:
            return emitter.statement(replace(statement, operands=("".join(chunk),)))

    else:
        return [line]
    number = line.split(" ", 1)[0]
    chunks: list[tuple[object, ...]] = [()]
    for item in items:
        candidate = chunks[-1] + (item,)
        prefix = len(number) + 1 if len(chunks) == 1 else 0
        if chunks[-1] and prefix + len(render(candidate, False)) > _LINE_LIMIT:
            chunks.append((item,))
        else:
            chunks[-1] = candidate
    rendered = [
        render(chunk, index == len(chunks) - 1) for index, chunk in enumerate(chunks)
    ]
    return [f"{number} {rendered[0]}", *rendered[1:]]


class _Emitter:
    def __init__(
        self,
        labels: dict[int, int],
        function_name: str | None = None,
        address_labels: dict[int, int] | None = None,
    ) -> None:
        self.labels = labels
        self.function_name = function_name
        self.address_labels = address_labels or {}

    def statement(self, statement: Statement) -> str:
        kind = statement.kind
        operands = statement.operands
        if kind in _BARE_STATEMENTS and (not operands or kind == "ExitLoop"):
            return _BARE_STATEMENTS[kind]
        if kind == "Common" and len(operands) == 1:
            return "COMMON " + _common_declarations(operands[0])
        if kind == "Assign" and len(operands) == 2:
            return f"{_expression(operands[0])} = {_expression(operands[1])}"
        if kind in {"Lset", "Rset", "Swap"} and len(operands) == 2:
            keyword = {"Lset": "LSET", "Rset": "RSET", "Swap": "SWAP"}[kind]
            separator = " = " if kind != "Swap" else ", "
            return separator.join(
                (keyword + " " + _expression(operands[0]), _expression(operands[1]))
            )
        if kind == "MidAssign" and len(operands) == 4:
            target, start, source, length = operands
            arguments = [_expression(target), _expression(start)]
            if length is not None:
                arguments.append(_expression(length))
            return f"MID$({', '.join(arguments)}) = {_expression(source)}"
        if kind in {"Print", "Lprint"} and len(operands) == 3:
            return self._print(kind, *operands)
        if kind == "PrintUsing" and len(operands) == 4:
            return self._print_using(*operands)
        if kind == "Write" and len(operands) == 2:
            file_number, items = operands
            prefix = "WRITE"
            if file_number is not None:
                prefix += f" {_file_number(file_number)},"
            values = ", ".join(_expression(item) for item in items)
            return f"{prefix} {values}".rstrip()
        if kind == "Input" and len(operands) == 4:
            return self._input(*operands)
        if kind == "InputFile" and len(operands) == 2:
            file_number, targets = operands
            values = ", ".join(_expression(item) for item in _items(targets))
            return f"INPUT {_file_number(file_number)}, {values}"
        if kind == "LineInput" and len(operands) == 4:
            file_number, prompt, target, leading_semicolon = operands
            if file_number is not None:
                return f"LINE INPUT {_file_number(file_number)}, {_expression(target)}"
            result = "LINE INPUT" + (";" if leading_semicolon else "")
            if prompt is not None:
                result += f" {_expression(prompt)};"
            return f"{result} {_expression(target)}"
        if kind == "Width" and len(operands) == 2:
            target, width = operands
            if target is None:
                return f"WIDTH {_expression(width)}"
            if isinstance(target, tuple) and len(target) == 2 and target[0] == "file":
                return f"WIDTH {_file_number(target[1])}, {_expression(width)}"
            return f"WIDTH {_expression(target)}, {_expression(width)}"
        if kind == "Bload" and len(operands) == 3:
            filename, offset, length = operands
            if length is not None:
                raise self.error(statement, "unexpected BLOAD length")
            result = f"BLOAD {_expression(filename)}"
            if offset is not None:
                result += f", {_expression(offset)}"
            return result
        if kind == "Bsave" and len(operands) == 3:
            filename, offset, length = operands
            if offset is None or length is None:
                raise self.error(statement, "missing BSAVE range")
            return (
                f"BSAVE {_expression(filename)}, {_expression(offset)}, "
                f"{_expression(length)}"
            )
        if kind == "Seek" and len(operands) == 2:
            return f"SEEK {_file_number(operands[0])}, {_expression(operands[1])}"
        if kind in {"Get", "Put"} and len(operands) == 2:
            file_number, position = operands
            result = f"{kind.upper()} {_file_number(file_number)}"
            if position is not None:
                result += f", {_expression(position)}"
            return result
        if kind in {"PutString", "Ioctl"} and len(operands) == 2:
            keyword = "PUT$" if kind == "PutString" else "IOCTL"
            return f"{keyword} {_file_number(operands[0])}, {_expression(operands[1])}"
        if kind == "GetString" and len(operands) == 3:
            return (
                f"GET$ {_file_number(operands[0])}, "
                f"{_expression(operands[1])}, {_expression(operands[2])}"
            )
        if kind == "Name" and len(operands) == 2:
            return f"NAME {_expression(operands[0])} AS {_expression(operands[1])}"
        if kind == "Inline" and len(operands) == 1 and isinstance(operands[0], str):
            raw = bytes.fromhex(operands[0])
            return "$INLINE " + ", ".join(f"&H{byte:02X}" for byte in raw)
        if kind == "Read" and len(operands) == 1:
            return "READ " + ", ".join(
                _expression(item) for item in _items(operands[0])
            )
        if kind == "Local" and len(operands) == 1:
            return "LOCAL " + ", ".join(
                _expression(item) for item in _items(operands[0])
            )
        if kind == "Data" and len(operands) == 1:
            return "DATA " + ",".join(_data_item(item) for item in operands[0])
        if kind == "IfGoto" and len(operands) >= 2:
            condition = _condition(tuple(operands[:-1]))
            return f"IF {condition} THEN {self.target(operands[-1])}"
        if kind == "IfInline" and len(operands) == 3:
            condition, body, else_body = operands
            then_text = ": ".join(self.statement(item) for item in body)
            if not then_text:
                raise self.error(statement, "empty inline IF body")
            result = f"IF {_condition(condition)} THEN {then_text}"
            if else_body is not None:
                else_text = ": ".join(self.statement(item) for item in else_body)
                if not else_text:
                    raise self.error(statement, "empty inline ELSE body")
                result += f" ELSE {else_text}"
            return result
        if kind in {"Goto", "Gosub"} and len(operands) == 1:
            return f"{kind.upper()} {self.target(operands[0])}"
        if kind == "Return":
            return "RETURN" + (f" {self.target(operands[0])}" if operands else "")
        if kind == "Resume":
            if not operands:
                return "RESUME"
            if operands[0] == "NEXT":
                return "RESUME NEXT"
            return f"RESUME {self.target(operands[0])}"
        if kind == "OnError" and len(operands) == 1:
            target = "0" if operands[0] is None else self.target(operands[0])
            return f"ON ERROR GOTO {target}"
        if kind in {"OnGoto", "OnGosub"} and len(operands) >= 2:
            keyword = "GOTO" if kind == "OnGoto" else "GOSUB"
            targets = ", ".join(self.target(target) for target in operands[1:])
            return f"ON {_expression(operands[0])} {keyword} {targets}"
        if kind == "OnTrap" and len(operands) == 3:
            name, argument, target = operands
            trigger = str(name)
            if argument is not None:
                trigger += f"({_expression(argument)})"
            return f"ON {trigger} GOSUB {self.target(target)}"
        if kind == "TrapCtl" and len(operands) == 3:
            name, argument, action = operands
            trigger = str(name)
            if argument is not None:
                trigger += f"({_expression(argument)})"
            return f"{trigger} {action}"
        if kind == "For" and len(operands) == 4:
            variable, start, stop, step = operands
            result = (
                f"FOR {_expression(variable)} = {_expression(start)} "
                f"TO {_expression(stop)}"
            )
            if step != ("const", 1):
                result += f" STEP {_expression(step)}"
            return result
        if kind == "NextStmt" and len(operands) == 1:
            return f"NEXT {_expression(operands[0])}"
        if kind in {"Do", "Loop"} and len(operands) == 2:
            modifier, condition = operands
            result = kind.upper()
            if modifier is not None:
                result += f" {modifier} {_condition(condition)}"
            return result
        if kind == "Dim" and len(operands) == 4:
            return self._dim(*operands)
        if kind == "OptionBase" and len(operands) == 1:
            return f"OPTION BASE {operands[0]}"
        if kind in _SINGLE_EXPRESSION_STATEMENTS and len(operands) == 1:
            return f"{_SINGLE_EXPRESSION_STATEMENTS[kind]} {_expression(operands[0])}"
        if kind == "DateTimeSet" and len(operands) == 2:
            name, value = operands
            if name not in {"DATE$", "TIME$"}:
                raise self.error(statement, "unresolved date/time target")
            return f"{name} = {_expression(value)}"
        if kind == "Files" and len(operands) == 1:
            return "FILES" + (
                f" {_expression(operands[0])}" if operands[0] is not None else ""
            )
        if kind == "Key" and len(operands) == 1 and isinstance(operands[0], bool):
            return "KEY ON" if operands[0] else "KEY OFF"
        if kind == "KeyDef" and len(operands) == 2:
            return f"KEY {_expression(operands[0])}, {_expression(operands[1])}"
        if (
            kind in {"CallAbsolute", "CallInterrupt", "ErrorStmt", "Randomize"}
            and len(operands) == 1
        ):
            keyword = {
                "CallAbsolute": "CALL ABSOLUTE",
                "CallInterrupt": "CALL INTERRUPT",
                "ErrorStmt": "ERROR",
            }.get(kind, kind.upper())
            return f"{keyword} {_expression(operands[0])}"
        if kind in {"Poke", "RegSet", "Sound"} and len(operands) == 2:
            keyword = {"RegSet": "REG"}.get(kind, kind.upper())
            return f"{keyword} {_expression(operands[0])}, {_expression(operands[1])}"
        if kind in {"Incr", "Decr"} and len(operands) == 1:
            return f"{kind.upper()} {_expression(operands[0])}"
        if kind == "Palette" and len(operands) in {0, 2}:
            return "PALETTE" + (
                " " + ", ".join(_expression(operand) for operand in operands)
                if operands
                else ""
            )
        if kind == "PaletteUsing" and len(operands) == 1:
            return f"PALETTE USING {_expression(operands[0])}"
        if kind == "DefSeg" and len(operands) in {0, 1}:
            return "DEF SEG" + (f" = {_expression(operands[0])}" if operands else "")
        if kind in {"Delay", "Run"}:
            keyword = kind.upper()
            return keyword + (
                " " + ", ".join(_expression(value) for value in operands)
                if operands
                else ""
            )
        if kind in {"Out", "Wait"} and len(operands) in {2, 3}:
            return (
                kind.upper() + " " + ", ".join(_expression(value) for value in operands)
            )
        if kind in {"Locate", "Color", "Screen"} and operands:
            return kind.upper() + " " + _optional_arguments(operands)
        if kind in {"Pset", "Preset"} and len(operands) == 4:
            step, x, y, color = operands
            result = kind.upper() + (" STEP" if step else "")
            result += f" ({_expression(x)}, {_expression(y)})"
            if color is not None:
                result += f", {_expression(color)}"
            return result
        if kind == "LineStmt" and len(operands) == 9:
            first_step, x1, y1, second_step, x2, y2, color, box, style = operands
            result = "LINE" + (" STEP" if first_step else "")
            if x1 is None:
                result += " -"
            else:
                result += f" ({_expression(x1)}, {_expression(y1)})-"
            result += "STEP " if second_step else ""
            result += f"({_expression(x2)}, {_expression(y2)})"
            if color is not None or box is not None or style is not None:
                result += ", " + ("" if color is None else _expression(color))
            if box is not None or style is not None:
                result += ", " + ("" if box is None else str(box))
            if style is not None:
                result += f", {_line_style(style)}"
            return result
        if kind == "View" and len(operands) == 7:
            screen, x1, y1, x2, y2, fill, border = operands
            result = "VIEW" + (" SCREEN" if screen else "")
            if x1 is None:
                return result
            result += (
                f" ({_expression(x1)}, {_expression(y1)})-"
                f"({_expression(x2)}, {_expression(y2)})"
            )
            if fill is not None or border is not None:
                result += ", " + ("" if fill is None else _expression(fill))
            if border is not None:
                result += f", {_expression(border)}"
            return result
        if kind == "Window" and len(operands) == 5:
            screen, x1, y1, x2, y2 = operands
            return (
                "WINDOW"
                + (" SCREEN" if screen else "")
                + f" ({_expression(x1)}, {_expression(y1)})-"
                + f"({_expression(x2)}, {_expression(y2)})"
            )
        if kind == "Circle" and len(operands) == 8:
            step, x, y, radius, color, start, end, aspect = operands
            result = "CIRCLE" + (" STEP" if step else "")
            result += f" ({_expression(x)}, {_expression(y)}), {_expression(radius)}"
            optional = (color, start, end, aspect)
            last = max(
                (index for index, value in enumerate(optional) if value is not None),
                default=-1,
            )
            for value in optional[: last + 1]:
                result += ", " + ("" if value is None else _expression(value))
            return result
        if kind == "Paint" and len(operands) == 4:
            x, y, fill, border = operands
            result = f"PAINT ({_expression(x)}, {_expression(y)})"
            if fill is not None or border is not None:
                result += ", " + ("" if fill is None else _expression(fill))
            if border is not None:
                result += f", {_expression(border)}"
            return result
        if kind == "GetGfx" and len(operands) == 5:
            x1, y1, x2, y2, name = operands
            if not isinstance(name, str):
                raise self.error(statement, "unresolved graphics array")
            return (
                f"GET ({_expression(x1)}, {_expression(y1)})-"
                f"({_expression(x2)}, {_expression(y2)}), {name}"
            )
        if kind == "PutGfx" and len(operands) == 4:
            x, y, name, action = operands
            actions = {0: None, 1: "OR", 2: "AND", 3: "PSET", 4: "PRESET"}
            if not isinstance(name, str) or action not in actions:
                raise self.error(statement, "unresolved graphics array or action")
            suffix = "" if actions[action] is None else f", {actions[action]}"
            return f"PUT ({_expression(x)}, {_expression(y)}), {name}{suffix}"
        if kind == "Erase" and len(operands) == 1 and isinstance(operands[0], str):
            return f"ERASE {operands[0]}"
        if (
            kind == "DefType"
            and len(operands) == 3
            and operands[0] in {"INT", "LNG", "SNG", "DBL", "STR"}
            and all(
                isinstance(letter, str)
                and len(letter) == 1
                and "A" <= letter.upper() <= "Z"
                for letter in operands[1:]
            )
        ):
            start, end = (str(letter).upper() for letter in operands[1:])
            return f"DEF{operands[0]} {start}-{end}"
        if kind == "Open" and len(operands) == 5:
            return self._open(*operands)
        if kind == "Close" and len(operands) == 1:
            return "CLOSE" + (
                f" {_file_number(operands[0])}" if operands[0] is not None else ""
            )
        if kind == "Field" and len(operands) == 2:
            file_number, fields = operands
            rendered = ", ".join(
                f"{_expression(width)} AS {_expression(target)}"
                for width, target in fields
            )
            return f"FIELD {_file_number(file_number)}, {rendered}"
        if kind == "CallStmt" and len(operands) == 2:
            name, arguments = operands
            if not isinstance(name, str) or _unresolved(arguments):
                raise self.error(statement, "unresolved procedure call")
            call_values = tuple(arguments)
            return f"CALL {name}" + (
                f"({', '.join(_expression(item) for item in call_values)})"
                if call_values
                else ""
            )
        if kind == "FnResult" and len(operands) == 1 and self.function_name:
            return f"{self.function_name} = {_expression(operands[0])}"
        raise self.error(statement, "statement kind is not supported")

    def function_definition(
        self, statement: Statement
    ) -> tuple[str, tuple[Statement, ...] | None, str]:
        if len(statement.operands) != 4:
            raise self.error(statement, "malformed function definition")
        name, parameters, body, is_block = statement.operands
        if (
            not isinstance(name, str)
            or not isinstance(parameters, tuple)
            or not all(isinstance(parameter, str) for parameter in parameters)
            or not isinstance(is_block, bool)
        ):
            raise self.error(statement, "unresolved function definition")
        suffix = f"({', '.join(parameters)})" if parameters else ""
        header = f"DEF {name}{suffix}"
        if not is_block:
            return f"{header} = {_expression(body)}", None, name
        if not isinstance(body, tuple) or not all(
            isinstance(item, Statement) for item in body
        ):
            raise self.error(statement, "malformed function body")
        return header, body, name

    def sub_definition(self, statement: Statement) -> tuple[str, tuple[Statement, ...]]:
        if len(statement.operands) != 3:
            raise self.error(statement, "malformed procedure definition")
        name, parameters, body = statement.operands
        if (
            not isinstance(name, str)
            or not isinstance(parameters, tuple)
            or not all(isinstance(parameter, str) for parameter in parameters)
            or not isinstance(body, tuple)
        ):
            raise self.error(statement, "unresolved procedure definition")
        if not all(isinstance(item, Statement) for item in body):
            raise self.error(statement, "malformed procedure body")
        suffix = f"({', '.join(parameters)})" if parameters else ""
        inline = body and body[0].kind == "Inline"
        return f"SUB {name}{suffix}{' INLINE' if inline else ''}", body

    def target(self, target: object) -> str:
        if isinstance(target, int) and target in self.labels:
            return str(self.labels[target])
        if (
            isinstance(target, tuple)
            and len(target) == 2
            and target[0] == "address"
            and target[1] in self.address_labels
        ):
            return str(self.address_labels[target[1]])
        raise BasicTranslationError(f"unresolved BASIC branch target: {target!r}")

    def error(self, statement: Statement, reason: str) -> BasicTranslationError:
        return BasicTranslationError(
            f"cannot translate {statement.kind} at {statement.address:#x}: {reason}"
        )

    def _print(self, kind: str, mode: object, items: object, newline: object) -> str:
        keyword = "PRINT" if kind == "Print" else "LPRINT"
        if mode not in {None, "console", "printer"}:
            keyword += f" {_file_number(mode)},"
        values = ""
        after_comma = False
        for item in _items(items):
            # A comma tabs to the next print zone wherever it stands, before
            # the first item and after the last as well as between two.
            if item == ("print-separator", ","):
                values += ","
                after_comma = True
                continue
            if isinstance(item, tuple) and len(item) == 5 and item[0] == "print_using":
                _tag, _mode, pattern, using_items, _newline = item
                rendered = f"USING {_expression(pattern)}"
                using_values = tuple(using_items)
                if using_values:
                    rendered += "; " + "; ".join(
                        _expression(value) for value in using_values
                    )
            else:
                rendered = _expression(item)
            if values:
                values += " " if after_comma else "; "
            values += rendered
            after_comma = False
        result = f"{keyword} {values}".rstrip()
        if not newline and not after_comma:
            result += ";"
        return result

    def _print_using(
        self, mode: object, pattern: object, items: object, newline: object
    ) -> str:
        prefix = "LPRINT" if mode == "printer" else "PRINT"
        if mode not in {None, "console", "printer"}:
            prefix += f" {_file_number(mode)},"
        result = f"{prefix} USING {_expression(pattern)}"
        values = _items(items)
        if values:
            result += "; " + "; ".join(_expression(item) for item in values)
        if not newline:
            result += ";"
        return result

    def _input(
        self, prompt: object, targets: object, comma: object, semicolon: object
    ) -> str:
        values = ", ".join(_expression(item) for item in _items(targets))
        if prompt is None:
            return f"INPUT {values}"
        separator = ";" if semicolon or not comma else ","
        return f"INPUT {_expression(prompt)}{separator} {values}"

    def _dim(self, name: object, bounds: object, also: object, dynamic: object) -> str:
        if not isinstance(name, str):
            raise BasicTranslationError(f"unresolved array name: {name!r}")
        arrays: list[tuple[object, tuple[object, ...]]] = [(name, _items(bounds))]
        for item in _items(also):
            if not isinstance(item, tuple) or len(item) != 2:
                raise BasicTranslationError(f"unresolved array declaration: {item!r}")
            array_name, array_bounds = item
            arrays.append((array_name, _items(array_bounds)))
        declarations = []
        for array_name, array_bounds in arrays:
            if not isinstance(array_name, str):
                raise BasicTranslationError(f"unresolved array name: {array_name!r}")
            bounds = ", ".join(_dim_bound(bound) for bound in array_bounds)
            declarations.append(f"{array_name}({bounds})")
        prefix = "DIM DYNAMIC" if dynamic else "DIM"
        return f"{prefix} {', '.join(declarations)}"

    def _open(
        self,
        mode: object,
        file_number: object,
        filename: object,
        record_length: object,
        _modern: object,
    ) -> str:
        mode_name = None
        if isinstance(mode, tuple) and len(mode) == 2 and mode[0] == "string":
            mode_name = {
                "I": "INPUT",
                "O": "OUTPUT",
                "A": "APPEND",
                "R": "RANDOM",
                "B": "BINARY",
            }.get(str(mode[1]).upper())
        if mode_name is None:
            raise BasicTranslationError(f"unresolved OPEN mode: {mode!r}")
        result = (
            f"OPEN {_expression(filename)} FOR {mode_name} "
            f"AS {_file_number(file_number)}"
        )
        if record_length is not None:
            result += f" LEN = {_expression(record_length)}"
        return result


def _common_declarations(value: object) -> str:
    if (
        not isinstance(value, tuple)
        or not value
        or not all(isinstance(name, str) and name for name in value)
    ):
        raise BasicTranslationError(f"unresolved COMMON declarations: {value!r}")
    return ", ".join(value)


def _dim_bound(value: object) -> str:
    if (
        isinstance(value, tuple)
        and len(value) == 2
        and all(isinstance(item, (int, float)) for item in value)
    ):
        return f"{_number(value[0])}:{_number(value[1])}"
    return _expression(("const", value) if isinstance(value, (int, float)) else value)


def _line_style(value: object) -> str:
    if (
        isinstance(value, tuple)
        and len(value) == 2
        and value[0] == "const"
        and isinstance(value[1], int)
        and 0 <= value[1] <= 0xFFFF
    ):
        return f"&H{value[1]:04X}"
    return _expression(value)


def _expression(value: object, parent_precedence: int = 0, right: bool = False) -> str:
    if not isinstance(value, tuple) or not value:
        raise BasicTranslationError(f"unresolved BASIC expression: {value!r}")
    tag = value[0]
    if tag == "const" and len(value) == 2:
        return _number(value[1])
    if tag == "string" and len(value) == 2 and isinstance(value[1], str):
        return '"' + value[1].replace('"', '""') + '"'
    if tag == "var" and len(value) >= 2 and isinstance(value[1], str):
        return value[1]
    if tag == "array" and len(value) == 3 and isinstance(value[1], str):
        indices = ", ".join(_expression(item) for item in value[2])
        return f"{value[1]}({indices})"
    if tag == "call" and len(value) == 3 and isinstance(value[1], str):
        name = value[1]
        values = tuple(value[2])
        if not values and (
            name.upper() in _BARE_NULLARY_INTRINSICS or name.upper().startswith("FN")
        ):
            return name
        arguments = ", ".join(_expression(item) for item in values)
        return f"{name}({arguments})"
    if tag == "group" and len(value) == 2:
        return f"({_expression(value[1])})"
    if tag == "unary" and len(value) == 3:
        operator = str(value[1]).upper()
        rendered = _expression(value[2], 7)
        result = (
            f"{operator} {rendered}" if operator == "NOT" else f"{operator}{rendered}"
        )
        return f"({result})" if 7 < parent_precedence else result
    if tag == "binary" and len(value) == 4:
        operator = str(value[1]).upper()
        precedence = _BINARY_PRECEDENCE.get(operator)
        if precedence is None:
            raise BasicTranslationError(f"unsupported BASIC operator: {operator!r}")
        left = _expression(value[2], precedence)
        right_value = _expression(
            value[3], precedence + (1 if operator in _RIGHT_SENSITIVE else 0), True
        )
        result = f"{left} {operator} {right_value}"
        needs_group = precedence < parent_precedence or (
            right and precedence == parent_precedence and operator in _RIGHT_SENSITIVE
        )
        return f"({result})" if needs_group else result
    raise BasicTranslationError(f"unsupported BASIC expression: {value!r}")


def _condition(value: object, parent_precedence: int = 0) -> str:
    if not isinstance(value, tuple) or not value:
        raise BasicTranslationError(f"unresolved BASIC condition: {value!r}")
    if len(value) == 2 and value[0] == "group":
        return f"({_condition(value[1])})"
    if len(value) == 2 and value[0] == "truth":
        return _expression(value[1], parent_precedence)
    if value[0] in _EXPRESSION_TAGS:
        return _expression(value, parent_precedence)
    if len(value) == 3:
        operator = str(value[0]).upper()
        precedence = _BINARY_PRECEDENCE.get(operator)
        if precedence is None:
            raise BasicTranslationError(f"unsupported BASIC condition: {value!r}")
        if operator in {"AND", "OR"}:
            left = _condition(value[1], precedence)
            right = _condition(value[2], precedence)
        else:
            left = _expression(value[1], precedence)
            right = _expression(value[2], precedence)
        rendered = f"{left} {operator} {right}"
        return f"({rendered})" if precedence < parent_precedence else rendered
    raise BasicTranslationError(f"unsupported BASIC condition: {value!r}")


def _number(value: object) -> str:
    if isinstance(value, bool):
        return "-1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float) and math.isfinite(value):
        return repr(value).replace("e", "E")
    raise BasicTranslationError(f"unsupported BASIC number: {value!r}")


def _items(value: object) -> tuple[object, ...]:
    if isinstance(value, tuple) and value and value[0] in _EXPRESSION_TAGS:
        return (value,)
    if isinstance(value, tuple):
        return value
    raise BasicTranslationError(f"unresolved BASIC item list: {value!r}")


def _data_item(value: object) -> str:
    if not (
        isinstance(value, tuple)
        and len(value) == 2
        and isinstance(value[0], str)
        and isinstance(value[1], bool)
    ):
        raise BasicTranslationError(f"unresolved DATA item: {value!r}")
    return '"' + value[0].replace('"', '""') + '"' if value[1] else value[0]


def _file_number(value: object) -> str:
    return f"#{value}" if isinstance(value, int) else f"#{_expression(value)}"


def _optional_arguments(values: Sequence[object]) -> str:
    trimmed = list(values)
    while trimmed and trimmed[-1] is None:
        trimmed.pop()
    return ", ".join("" if value is None else _expression(value) for value in trimmed)


def _unsupported(statement: Statement) -> str:
    return f"REM TBD: unsupported {statement.kind} at &H{statement.address:X}"
