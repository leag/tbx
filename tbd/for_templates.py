"""Pure FOR/NEXT matchers ported from the calibrated decoder vocabulary."""

from __future__ import annotations

from dataclasses import dataclass

from tbd.compiler_ops import CompilerOp


@dataclass(frozen=True)
class FpForTemplate:
    """The complete x87 sign split and its two comparison arms."""

    stop: int
    end: int
    limit: int
    step: int
    variable: int
    body: int
    wide: bool
    evidence: tuple[int, ...]


@dataclass(frozen=True)
class VariableStepBranch:
    """One INTEGER computed-STEP comparison arm."""

    stop: int
    limit_kind: str
    limit: int


@dataclass(frozen=True)
class VariableStepTemplate:
    """Complete computed-STEP sign split and matching comparison arms."""

    stop: int
    end: int
    limit_kind: str
    limit: int
    evidence: tuple[int, ...]


def match_fp_for_test(
    operations: tuple[CompilerOp, ...],
    index: int,
    staged: tuple[int, int, int],
) -> FpForTemplate | None:
    """Port the reference decoder's complete loose/x87 FOR matcher."""

    prefix = _fp_prefix(operations, index)
    if prefix is None:
        return None
    test, skip, pair, first_load, first_compare, cursor = prefix
    positive = _body_branch(operations, cursor, 0x73, 0x72)
    if positive is None:
        return None
    body, cursor = positive
    if cursor >= len(operations) or operations[cursor].kind != "jmp":
        return None
    exit_jump = operations[cursor]
    cursor += 1
    negative_start = cursor
    cursor = _fp_compare(operations, cursor, pair)
    if cursor is None:
        return None
    negative = _body_branch(operations, cursor, 0x76, 0x77, body)
    if negative is None:
        return None
    body, cursor = negative
    if not _same_code_offset(skip.args[0], operations[negative_start].offset):
        return None
    limit, variable = first_load.args[0], first_compare.args[0]
    step = test.args[0] - (6 if pair[0] == "fld64" else 2)
    if staged != (limit, step, variable):
        return None
    # The reference operation stream omits commit/runtime glue.  The template's
    # physical exit is therefore the end of its final branch, not the address
    # of the next translated operation (which may be a later source construct).
    end = operations[cursor - 1].end
    if not _same_code_offset(exit_jump.args[0], end):
        return None
    evidence = tuple(operation.offset for operation in operations[index:cursor])
    return FpForTemplate(
        cursor,
        end,
        limit,
        step,
        variable,
        body,
        pair[0] == "fld64",
        evidence,
    )


def match_variable_step_branch(
    operations: tuple[CompilerOp, ...],
    index: int,
    *,
    variable: int,
    body: int,
    wanted: tuple[int, ...],
    inverse: tuple[int, ...],
) -> VariableStepBranch | None:
    """Port one computed-STEP INTEGER comparison arm."""

    if index >= len(operations):
        return None
    first = operations[index]
    if first.kind in {"cmp_mi8", "cmp_mi16", "cmp_bpi8", "cmp_bpi16"}:
        if first.args[0] != variable:
            return None
        limit_kind, limit, branch_index = "literal", first.args[1], index + 1
    elif first.kind in {"movax_m", "movax_bp"}:
        if index + 1 >= len(operations):
            return None
        compare = operations[index + 1]
        expected = {"movax_m": "cmpm_ax", "movax_bp": "cmpm_ax_bp"}[first.kind]
        if compare.kind != expected or compare.args[0] != variable:
            return None
        limit_kind, limit, branch_index = "cell", first.args[0], index + 2
    else:
        return None
    stop = _branch_stop(operations, branch_index, body, wanted, inverse)
    return (
        None
        if stop is None
        else VariableStepBranch(stop, limit_kind, limit)
    )


def match_variable_step_test(
    operations: tuple[CompilerOp, ...],
    index: int,
    *,
    variable: int,
    body: int,
) -> VariableStepTemplate | None:
    """Port the reference decoder's complete computed-STEP NEXT matcher."""

    if index + 2 >= len(operations) or operations[index].kind != "orax_self":
        return None
    sign_branch, descending_jump = operations[index + 1 : index + 3]
    if (
        sign_branch.kind != "jcc"
        or sign_branch.args[0] != 0x79
        or descending_jump.kind != "jmp"
        or sign_branch.args[1] != descending_jump.offset + 3
    ):
        return None
    ascending = match_variable_step_branch(
        operations,
        index + 3,
        variable=variable,
        body=body,
        wanted=(0x7E, 0x76),
        inverse=(0x7F, 0x77),
    )
    if ascending is None or ascending.stop + 1 >= len(operations):
        return None
    skip = operations[ascending.stop]
    descending_start = ascending.stop + 1
    if (
        skip.kind != "jmp"
        or operations[descending_start].offset != descending_jump.args[0]
    ):
        return None
    descending = match_variable_step_branch(
        operations,
        descending_start,
        variable=variable,
        body=body,
        wanted=(0x7D,),
        inverse=(0x7C,),
    )
    if descending is None:
        return None
    if (ascending.limit_kind, ascending.limit) != (
        descending.limit_kind,
        descending.limit,
    ):
        return None
    end = operations[descending.stop - 1].end
    if not _same_code_offset(skip.args[0], end):
        return None
    evidence = tuple(operation.offset for operation in operations[index:descending.stop])
    return VariableStepTemplate(
        descending.stop,
        end,
        ascending.limit_kind,
        ascending.limit,
        evidence,
    )


def _fp_prefix(
    operations: tuple[CompilerOp, ...], index: int
) -> tuple[CompilerOp, CompilerOp, tuple[str, str], CompilerOp, CompilerOp, int] | None:
    if index + 5 >= len(operations):
        return None
    test, branch, skip = operations[index : index + 3]
    if test.kind not in {"testw", "testw_bp"}:
        return None
    if branch.kind != "jcc" or branch.args[0] != 0x74 or skip.kind != "jmp":
        return None
    first_load, first_compare, status = operations[index + 3 : index + 6]
    pair = first_load.kind, first_compare.kind
    valid = {
        ("fld", "fcomp"),
        ("fld", "fcomp_bp"),
        ("fld_bp", "fcomp"),
        ("fld_bp", "fcomp_bp"),
        ("fld64", "fcomp64"),
    }
    if pair not in valid or status.kind != "fstsw":
        return None
    if (test.kind == "testw_bp") != (first_load.kind == "fld_bp"):
        return None
    if branch.args[1] != first_load.offset:
        return None
    return test, skip, pair, first_load, first_compare, index + 6


def _fp_compare(
    operations: tuple[CompilerOp, ...], index: int, pair: tuple[str, str]
) -> int | None:
    if index + 2 >= len(operations):
        return None
    load, compare, status = operations[index : index + 3]
    if (load.kind, compare.kind) != pair or status.kind != "fstsw":
        return None
    return index + 3


def _body_branch(
    operations: tuple[CompilerOp, ...],
    index: int,
    wanted: int,
    inverse: int,
    body: int | None = None,
) -> tuple[int, int] | None:
    if index >= len(operations):
        return None
    branch = operations[index]
    if branch.kind == "jcc" and branch.args[0] == wanted:
        target = branch.args[1]
        if body is None or _same_code_offset(target, body):
            return target, index + 1
    if index + 1 >= len(operations):
        return None
    jump = operations[index + 1]
    if (
        branch.kind == "jcc"
        and branch.args[0] == inverse
        and branch.args[1] == branch.offset + 5
        and jump.kind == "jmp"
        and (body is None or _same_code_offset(jump.args[0], body))
    ):
        return jump.args[0], index + 2
    return None


def _branch_stop(
    operations: tuple[CompilerOp, ...],
    index: int,
    body: int,
    wanted: tuple[int, ...],
    inverse: tuple[int, ...],
) -> int | None:
    branch = operations[index] if index < len(operations) else None
    if (
        branch is not None
        and branch.kind == "jcc"
        and branch.args[0] in wanted
        and branch.args[1] == body
    ):
        return index + 1
    jump = operations[index + 1] if index + 1 < len(operations) else None
    if (
        branch is not None
        and branch.kind == "jcc"
        and branch.args[0] in inverse
        and jump is not None
        and jump.kind == "jmp"
        and jump.args[0] == body
        and branch.args[1] == jump.offset + 3
    ):
        return index + 2
    return None


def _same_code_offset(left: int, right: int) -> bool:
    return (left - right) % 0x10000 == 0
