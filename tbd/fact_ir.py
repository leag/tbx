from __future__ import annotations

from bisect import bisect_right
from collections import Counter
from itertools import accumulate

from tbd.facts import Evidence, facts_by_kind
from tbd.ir import Fact, Operation
from tbd.semantic import resolve_expression

_OPERATION_KINDS = {
    "semantic.assign": "ir.assign",
    "semantic.out": "ir.out",
    "semantic.wait": "ir.wait",
    "semantic.lprint": "ir.lprint",
    "semantic.print_using": "ir.print_using",
    "semantic.write": "ir.write",
    "semantic.lset": "ir.lset",
    "semantic.rset": "ir.rset",
    "semantic.field": "ir.field",
    "semantic.mid_assign": "ir.mid_assign",
    "semantic.swap": "ir.swap",
    "semantic.locate": "ir.locate",
    "semantic.read": "ir.read",
    "semantic.input_file": "ir.input_file",
    "semantic.input": "ir.input",
    "semantic.open": "ir.open",
    "semantic.close": "ir.close",
    "semantic.color": "ir.color",
    "semantic.screen": "ir.screen",
    "semantic.files": "ir.files",
    "semantic.for": "ir.for",
    "semantic.next": "ir.next",
    "semantic.do": "ir.do",
    "semantic.do_codeless": "ir.do",
    "semantic.loop": "ir.loop",
    "semantic.exit_loop": "ir.exit_loop",
    "semantic.trap_ctl": "ir.trap_ctl",
    "semantic.on_trap": "ir.on_trap",
    "semantic.on_goto": "ir.on_goto",
    "semantic.on_gosub": "ir.on_gosub",
    "semantic.print": "ir.print",
    "semantic.if_goto": "ir.if_goto",
    "semantic.if_goto_condition": "ir.if_goto_condition",
    "semantic.if_inline": "ir.if_inline",
    "semantic.if_block": "ir.if_block",
    "semantic.goto": "ir.goto",
    "semantic.inline": "ir.inline",
    "semantic.delay": "ir.delay",
    "semantic.defseg": "ir.defseg",
    "semantic.def_type": "ir.def_type",
    "semantic.data": "ir.data",
    "semantic.dim": "ir.dim",
    "semantic.local_dim": "ir.dim",
    "semantic.common": "ir.common",
    "semantic.option_base": "ir.option_base",
    "semantic.dynamic_dim": "ir.dynamic_dim",
    "semantic.gosub": "ir.gosub",
    "semantic.return": "ir.return",
    "semantic.resume": "ir.resume",
    "semantic.run": "ir.run",
    "semantic.call": "ir.call",
    "semantic.sub_def": "ir.sub_def",
    "semantic.exit_sub": "ir.exit_sub",
    "semantic.local": "ir.local",
    "semantic.def_fn": "ir.def_fn",
    "semantic.fn_result": "ir.fn_result",
    "semantic.exit_def": "ir.exit_def",
    "semantic.tron": "ir.tron",
    "semantic.troff": "ir.troff",
    "semantic.statement": "tb.statement",
}


def _condition_atoms(value: object) -> tuple[str, ...]:
    if isinstance(value, tuple) and len(value) == 3 and value[0] in {"AND", "OR"}:
        return _condition_atoms(value[1]) + _condition_atoms(value[2])
    return (repr(value),)


def build_operations(
    evidence: Evidence, facts: tuple[Fact, ...]
) -> tuple[Operation, ...]:
    """Materialize semantic facts while removing consumed control-flow tails."""

    operations = []
    by_kind = facts_by_kind(facts)
    snapshot = frozenset(facts)
    materialized: set[tuple[object, ...]] = set()
    resolved_procedures = {
        fact.value[0]
        for fact in facts
        if fact.kind == "semantic.sub_def"
        and len(fact.value) == 2
        and not _unresolved_procedure_values(fact.value[1])
    }
    resolved_calls = {
        (fact.value[0], fact.subject[1])
        for fact in facts
        if fact.kind == "semantic.call"
        and len(fact.subject) == 2
        and len(fact.value) == 2
        and not _unresolved_procedure_values(fact.value[1])
    }
    exit_sub_subjects = {
        fact.subject for fact in facts if fact.kind == "semantic.exit_sub"
    }
    # The far jump closing a code segment is $SEGMENT, not a GOTO.
    segment_subjects = {
        fact.subject
        for fact in facts
        if fact.kind == "semantic.statement" and fact.value[:1] == ("SEGMENT",)
    }
    exit_sub_targets = {
        fact.subject: fact.evidence[-1]
        for fact in facts
        if fact.kind == "semantic.exit_sub" and len(fact.evidence) == 2
    }
    exit_def_subjects = {
        fact.subject for fact in facts if fact.kind == "semantic.exit_def"
    }
    anchored_statements = tuple(
        fact
        for fact in facts
        if fact.kind == "semantic.statement"
        and fact.confidence == "anchored"
        and len(fact.subject) == 2
        and len(fact.value) >= 2
    )
    end_statement_starts = {
        fact.subject[0]
        for fact in facts
        if fact.kind == "signature"
        and fact.subject
        and isinstance(fact.subject[0], int)
        and fact.value[:2] == ("tb.statement", ("END", 50))
    }
    for_starts = {
        fact.subject[1]
        for fact in facts
        if fact.kind == "semantic.for"
        and len(fact.subject) == 2
        and isinstance(fact.subject[1], int)
    }
    if_block_spans = tuple(
        fact.subject
        for fact in facts
        if fact.kind == "semantic.if_block"
        and len(fact.subject) == 2
        and all(isinstance(value, int) for value in fact.subject)
    )
    inline_starts = {
        fact.subject[0]
        for fact in facts
        if fact.kind == "semantic.if_inline"
        and fact.subject
        and isinstance(fact.subject[0], int)
    }
    block_if_subjects = tuple(
        fact.subject
        for fact in facts
        if fact.kind == "semantic.if_block"
        and len(fact.subject) == 2
        and all(isinstance(value, int) for value in fact.subject)
    )
    # The bodies of each block IF, by its span: its arms and its ELSE.
    block_bodies: dict[tuple[object, ...], list[tuple[int, int]]] = {}
    for fact in facts:
        if fact.kind != "semantic.if_block" or len(fact.value) != 2:
            continue
        arms, else_bounds = fact.value
        bodies = block_bodies.setdefault(fact.subject, [])
        if isinstance(arms, tuple):
            bodies.extend(
                (arm[1], arm[2])
                for arm in arms
                if isinstance(arm, tuple)
                and len(arm) == 3
                and isinstance(arm[1], int)
                and isinstance(arm[2], int)
            )
        if (
            isinstance(else_bounds, tuple)
            and len(else_bounds) == 2
            and all(isinstance(value, int) for value in else_bounds)
        ):
            bodies.append(else_bounds)
    block_if_exits = {
        (arm[2], fact.subject[1])
        for fact in facts
        if fact.kind == "semantic.if_block"
        and len(fact.subject) == 2
        and isinstance(fact.subject[1], int)
        and len(fact.value) == 2
        and isinstance(fact.value[0], tuple)
        for arm in fact.value[0]
        if isinstance(arm, tuple) and len(arm) == 3 and isinstance(arm[2], int)
    }
    arm_closes = {
        arm_end: block_end
        for arm_end, block_end in block_if_exits
        if isinstance(arm_end, int) and arm_end != block_end
    }
    inline_subjects = tuple(
        fact.subject
        for fact in facts
        if fact.kind == "semantic.if_inline"
        and len(fact.subject) == 2
        and all(isinstance(value, int) for value in fact.subject)
    )
    # An inline IF renders the statements inside its body range, so a fact
    # there is the body rather than a duplicate of the condition.
    inline_bodies = tuple(
        (fact.value[1], fact.value[2])
        for fact in facts
        if fact.kind == "semantic.if_inline"
        and len(fact.value) == 4
        and isinstance(fact.value[1], int)
        and isinstance(fact.value[2], int)
    )
    resume_subjects = tuple(
        fact.subject
        for fact in facts
        if fact.kind == "semantic.resume"
        and len(fact.subject) == 2
        and all(isinstance(value, int) for value in fact.subject)
    )
    # ``IF c THEN ...: GOTO <the IF>: END IF`` has a back edge ending the
    # block's body.  Read as a DO/LOOP around the block it loses the GOTO the
    # body holds, so those loops and their DOs give way to the block.
    block_spans = {
        fact.subject
        for fact in facts
        if fact.kind == "semantic.if_block" and len(fact.subject) == 2
    }
    back_edges = [
        fact
        for fact in facts
        if fact.kind == "flow.goto"
        and len(fact.subject) == 2
        and len(fact.value) == 1
        and (fact.value[0], fact.subject[1]) in block_spans
    ]
    block_gotos = {
        (fact.kind, fact.subject)
        for fact in facts
        if fact.kind == "semantic.loop"
        and fact.value[:2] == (None, None)
        and len(fact.subject) == 2
        and any(
            edge.subject[1] == fact.subject[1] and fact.subject[0] <= edge.subject[0]
            for edge in back_edges
        )
    }
    block_goto_targets = {
        edge.value[0]
        for edge in back_edges
        if any(subject[1] == edge.subject[1] for _kind, subject in block_gotos)
    }
    loop_subjects = tuple(
        fact.subject
        for fact in facts
        if fact.kind == "semantic.loop"
        and len(fact.subject) == 2
        and (fact.kind, fact.subject) not in block_gotos
    )
    if_goto_starts = Counter(
        fact.subject[0]
        for fact in facts
        if fact.kind == "semantic.if_goto"
        and len(fact.subject) == 2
        and isinstance(fact.subject[0], int)
    )
    dispatch_if_starts = {start for start, count in if_goto_starts.items() if count > 1}
    exit_loop_subjects = {
        fact.subject for fact in facts if fact.kind == "semantic.exit_loop"
    }
    print_spans = {
        (fact.subject, fact.value) for fact in facts if fact.kind == "semantic.print"
    }
    print_items = {
        (fact.subject, fact.value[1])
        for fact in facts
        if fact.kind == "semantic.print" and len(fact.value) >= 2
    }
    print_tail_starts: dict[tuple[object, object], list[int]] = {}
    for fact in facts:
        if (
            fact.kind == "semantic.print"
            and len(fact.value) >= 2
            and len(fact.subject) == 2
            and isinstance(fact.subject[0], int)
        ):
            print_tail_starts.setdefault((fact.subject[1], fact.value[1]), []).append(
                fact.subject[0]
            )
    split_print_spans = frozenset(
        fact.subject
        for fact in facts
        if (
            fact.kind == "semantic.print"
            and len(fact.value) >= 3
            and fact.value[2] is False
            and isinstance(fact.value[1], tuple)
            and len(fact.value[1]) > 1
            and len(fact.subject) == 2
            and any(
                start > fact.subject[0]
                for start in print_tail_starts.get(
                    (fact.subject[1], (fact.value[1][-1],)), ()
                )
            )
        )
    )
    semantic_spans = tuple(
        (fact.kind, fact.subject[0], fact.subject[1])
        for fact in facts
        if fact.kind.startswith("semantic.")
        and fact.kind != "semantic.if_goto"
        and len(fact.subject) == 2
        and all(isinstance(value, int) for value in fact.subject)
        and fact.subject[1] > fact.subject[0]
        and fact.subject not in split_print_spans
    )
    richer_if_gotos = {
        fact.subject
        for fact in facts
        if (
            fact.kind == "semantic.if_goto"
            and len(fact.subject) == 2
            and len(fact.value) >= 3
            and isinstance(fact.value[2], tuple)
            and fact.value[2][:2] == ("call", "LEN")
        )
    }
    preferred_len_if_gotos = {
        (fact.value[3], fact.value[4])
        for fact in facts
        if (
            fact.kind == "semantic.if_goto"
            and len(fact.subject) == 2
            and len(fact.value) >= 3
            and isinstance(fact.value[1], tuple)
            and fact.value[1][:2] == ("call", "LEN")
            and fact.value[2] == ("const", 4)
        )
    }
    inline_groups: dict[tuple[object, ...], tuple[bool, bool]] = {}
    for fact in facts:
        if (
            fact.kind == "semantic.if_inline"
            and len(fact.value) >= 2
            and isinstance(fact.value[0], tuple)
            and fact.value[0][:1] == ("AND",)
        ):
            key = fact.subject, fact.value[1:]
            has_group, has_plain = inline_groups.get(key, (False, False))
            inline_groups[key] = (
                has_group or "group" in repr(fact.value[0]),
                has_plain or "group" not in repr(fact.value[0]),
            )
    grouped_inline_duplicates = {
        (fact.subject, fact.value[1:])
        for fact in facts
        if fact.kind == "semantic.if_inline"
        and len(fact.value) >= 2
        and isinstance(fact.value[0], tuple)
        and fact.value[0][:1] == ("AND",)
        and inline_groups.get((fact.subject, fact.value[1:]), (False, False))[1]
    }
    compound_if_goto_spans = tuple(
        fact.subject
        for fact in facts
        if fact.kind == "semantic.if_goto"
        and len(fact.subject) == 2
        and len(fact.value) >= 3
        and fact.value[0] == "AND"
    )
    for fact in facts:
        if (
            fact.kind == "semantic.if_goto_condition"
            and len(fact.subject) == 2
            and any(
                start == fact.subject[0] and end >= fact.subject[1]
                for start, end in inline_subjects
            )
        ):
            continue
        if (
            fact.kind == "semantic.if_goto"
            and len(fact.subject) == 2
            and any(
                start <= fact.subject[0] and fact.subject[1] <= end
                for start, end in inline_subjects
            )
            and not any(
                start <= fact.subject[0] and fact.subject[1] <= end
                for start, end in inline_bodies
            )
        ):
            continue
        if (
            fact.kind == "semantic.if_inline"
            and len(fact.subject) == 2
            and isinstance(fact.value[0], tuple)
            and fact.value[0][:1] == ("OR",)
            and any(
                other.kind == "semantic.if_inline"
                and other.subject == fact.subject
                and isinstance(other.value[0], tuple)
                and other.value[0][:1] == ("AND",)
                for other in by_kind.get(fact.kind, ())
            )
        ):
            continue
        if (
            fact.kind == "semantic.if_inline"
            and len(fact.subject) == 2
            and all(isinstance(value, int) for value in fact.subject)
            and any(
                start == fact.subject[0] and fact.subject[1] <= end
                for start, end in block_if_subjects
            )
        ):
            continue
        if (
            fact.kind == "semantic.goto"
            and len(fact.subject) == 2
            and len(fact.value) == 1
            and (fact.subject[0], fact.value[0]) in block_if_exits
        ):
            continue
        if (
            fact.kind == "semantic.goto"
            and len(fact.subject) == 2
            and any(
                start <= fact.subject[0] and fact.subject[1] <= end
                for start, end in resume_subjects
            )
        ):
            continue
        if fact.kind == "semantic.goto" and fact.subject in exit_sub_subjects:
            continue
        if fact.kind == "semantic.goto" and fact.subject in segment_subjects:
            continue
        if fact.kind == "semantic.goto" and fact.subject in exit_def_subjects:
            continue
        if fact.kind == "semantic.goto" and fact.subject in exit_loop_subjects:
            continue
        if (
            fact.kind == "semantic.goto"
            and len(fact.value) == 1
            and isinstance(fact.value[0], int)
            and any(
                instruction.kind == "instruction"
                and instruction.subject == (fact.value[0],)
                and instruction.value[:2] == ("x86.xor", 2)
                # Cleanup starts with `xor dx,dx` (31 d2) ahead of the xchg
                # scaffold, or is runtime-library code encoded `33`.  The
                # compiler's own clears -- `31 c0` for `IF X% = 0`, `31 f6` for
                # an element address -- begin statements, and a jump there is
                # a GOTO in the program that dropping would change.
                and _cleanup_clear(instruction.value[2:])
                for instruction in by_kind.get("instruction", ())
            )
        ):
            continue
        if (
            fact.kind == "semantic.goto"
            and len(fact.subject) == 2
            and len(fact.value) == 1
            and fact.value[0] == fact.subject[1]
            and any(
                resume.subject[1] == fact.subject[0]
                for resume in facts
                if resume.kind == "semantic.resume" and len(resume.subject) == 2
            )
        ):
            continue
        if (
            fact.kind == "semantic.if_goto"
            and fact.subject
            and fact.subject[0] in dispatch_if_starts
            and any(start <= fact.subject[0] < end for start, end in if_block_spans)
        ):
            continue
        if fact.kind == "semantic.write" and (
            (fact.subject, fact.value) in print_spans
            or (len(fact.value) >= 2 and (fact.subject, fact.value[1]) in print_items)
        ):
            continue
        if (
            fact.kind == "semantic.goto"
            and len(fact.subject) == 2
            and any(
                start <= fact.subject[0] and fact.subject[1] <= end
                for start, end in loop_subjects
            )
        ):
            continue
        if (
            fact.kind == "semantic.if_goto"
            and fact.subject in richer_if_gotos
            and len(fact.value) >= 3
            and fact.value[2] == ("const", 0)
        ):
            continue
        if (
            fact.kind == "semantic.if_inline"
            and (fact.subject, fact.value[1:]) in grouped_inline_duplicates
            and "group" in repr(fact.value[0])
        ):
            continue
        if (
            fact.kind == "semantic.if_goto"
            and len(fact.subject) == 2
            and any(
                start < fact.subject[0] and fact.subject[1] <= end
                for start, end in compound_if_goto_spans
            )
        ):
            continue
        if (
            fact.kind == "semantic.if_goto"
            and len(fact.value) >= 5
            and (fact.value[3], fact.value[4]) in preferred_len_if_gotos
            and not (
                isinstance(fact.value[1], tuple)
                and fact.value[1][:2] == ("call", "LEN")
                and fact.value[2] == ("const", 4)
            )
        ):
            continue
        if (
            fact.kind == "semantic.if_goto"
            and fact.value[0] == "OR"
            and any(
                other.kind == "semantic.if_goto"
                and other.value[0] == "OR"
                and other.subject[0] < fact.subject[0]
                and other.subject[1] == fact.subject[1]
                and repr(fact.value[1]) in repr(other.value[1:3])
                and repr(fact.value[2]) in repr(other.value[1:3])
                for other in by_kind.get(fact.kind, ())
            )
        ):
            continue
        if (
            fact.kind == "semantic.if_goto"
            and "group" in repr(fact.value[:3])
            and any(
                other.kind == "semantic.if_goto"
                and other.subject == fact.subject
                and other.value[3:] == fact.value[3:]
                and "group" not in repr(other.value[:3])
                for other in by_kind.get(fact.kind, ())
            )
        ):
            continue
        if (
            fact.kind == "semantic.if_goto"
            and len(fact.value) >= 5
            and any(
                other.kind == "semantic.if_goto"
                and len(other.value) >= 5
                and other.subject[0] <= fact.subject[0]
                and other.subject[1] >= fact.subject[1]
                and all(
                    atom in repr(other.value[:3])
                    for atom in _condition_atoms(
                        (fact.value[0], fact.value[1], fact.value[2])
                    )
                )
                and other.value[0] != fact.value[0]
                for other in by_kind.get(fact.kind, ())
            )
        ):
            continue
        if (
            fact.kind == "semantic.if_goto"
            and len(fact.value) >= 5
            and fact.value[2] == ("const", 0)
            and any(
                other.kind == "semantic.if_goto"
                and len(other.value) >= 5
                and other.value[3:] == fact.value[3:]
                and other.subject[0] < fact.subject[0]
                and isinstance(other.value[2], tuple)
                and other.value[2][:1] == ("string",)
                for other in by_kind.get(fact.kind, ())
            )
        ):
            continue
        if (
            fact.kind.startswith("semantic.")
            and fact.kind != "semantic.assign"
            and not (fact.kind == "semantic.loop" and fact.value[:2] != (None, None))
            and not (
                fact.kind == "semantic.print"
                and len(fact.value) >= 2
                and isinstance(fact.value[1], tuple)
                and len(fact.value[1]) == 1
                and isinstance(fact.value[1][0], tuple)
                and fact.value[1][0][:2] == ("call", "ASC")
            )
            and len(fact.subject) == 2
            and any(
                kind == fact.kind
                and start < fact.subject[0]
                and fact.subject[1] <= end
                # A block IF inside another's arm is a nested statement, not
                # a shorter reading of the same one.
                and not (
                    kind == "semantic.if_block"
                    and any(
                        body_start <= fact.subject[0] and fact.subject[1] <= body_end
                        for body_start, body_end in block_bodies.get((start, end), ())
                    )
                )
                for kind, start, end in semantic_spans
            )
        ):
            continue
        if (
            fact.kind == "semantic.sub_def"
            and len(fact.value) == 2
            and fact.value[0] in resolved_procedures
            and _unresolved_procedure_values(fact.value[1])
        ):
            continue
        if (
            fact.kind == "semantic.call"
            and len(fact.subject) == 2
            and len(fact.value) == 2
            and (fact.value[0], fact.subject[1]) in resolved_calls
            and _unresolved_procedure_values(fact.value[1])
        ):
            continue
        if (
            fact.kind == "semantic.statement"
            and fact.confidence == "signature"
            and len(fact.subject) == 2
            and len(fact.value) >= 2
            and any(
                candidate.subject[0] <= fact.subject[0]
                and candidate.subject[1] >= fact.subject[1]
                and candidate.value[:2] == fact.value[:2]
                and len(candidate.value) > len(fact.value)
                for candidate in anchored_statements
            )
        ):
            continue
        if (
            fact.kind == "semantic.assign"
            and len(fact.subject) == 2
            and any(
                other.kind == "semantic.assign"
                and other.subject == fact.subject
                and len(other.value) == len(fact.value)
                and other.value[0] == fact.value[0]
                and repr(other.value[1]) < repr(fact.value[1])
                for other in by_kind.get("semantic.assign", ())
            )
        ):
            continue
        if (
            fact.kind == "semantic.assign"
            and len(fact.subject) == 2
            and not (
                isinstance(fact.value[1], tuple)
                and fact.value[1][:2] == ("call", "RND")
            )
            and any(
                other.kind == "semantic.assign"
                and len(other.subject) == 2
                and other.subject[0] < fact.subject[0]
                and other.subject[1] > fact.subject[0]
                and other.value == fact.value
                for other in by_kind.get("semantic.assign", ())
            )
        ):
            continue
        kind = _OPERATION_KINDS.get(fact.kind)
        identity = fact.kind, fact.subject, fact.value
        if kind is None or identity in materialized:
            continue
        if (fact.kind, fact.subject) in block_gotos:
            continue
        if (
            fact.kind in {"semantic.do", "semantic.do_codeless"}
            and fact.subject
            and fact.subject[0] in block_goto_targets
        ):
            continue
        if (
            fact.kind == "semantic.do_codeless"
            and fact.subject
            and fact.subject[0] in (end_statement_starts | for_starts)
        ):
            continue
        if (
            fact.kind == "semantic.loop"
            and fact.value[:2] == (None, None)
            and fact.subject
            and fact.subject[0] in (inline_starts | for_starts)
        ):
            continue
        if (
            fact.kind == "semantic.loop"
            and fact.value[:2] == (None, None)
            and len(fact.subject) == 2
            and any(
                other.kind == "semantic.loop"
                and other.value[:2] != (None, None)
                and len(other.subject) == 2
                and other.subject[1] == fact.subject[1]
                for other in by_kind.get(fact.kind, ())
            )
        ):
            continue
        if (
            fact.kind == "semantic.loop"
            and fact.value[:2] != (None, None)
            and any(
                other.kind == "semantic.loop"
                and other.subject == fact.subject
                and other.value != fact.value
                and len(other.evidence) > len(fact.evidence)
                for other in by_kind.get(fact.kind, ())
            )
        ):
            continue
        if (
            fact.kind == "semantic.print"
            and len(fact.value) >= 2
            and any(
                other.kind == "semantic.print"
                and len(other.subject) == 2
                and len(fact.subject) == 2
                and other.subject[0] == fact.subject[0]
                and len(other.value) >= 2
                and len(other.value[1]) > len(fact.value[1])
                and other.value[1][: len(fact.value[1])] == fact.value[1]
                and other.value[2:3] == fact.value[2:3]
                for other in by_kind.get(fact.kind, ())
            )
        ):
            continue
        if (
            fact.kind == "semantic.print"
            and len(fact.subject) == 2
            and any(
                other.kind == "semantic.print"
                and other.subject == fact.subject
                and len(fact.value) >= 2
                and len(other.value) >= 2
                and "memory" in repr(fact.value[1])
                and "memory" not in repr(other.value[1])
                for other in by_kind.get(fact.kind, ())
            )
        ):
            continue
        if fact.subject in split_print_spans:
            continue
        if (
            fact.kind == "semantic.print"
            and len(fact.subject) == 2
            and "ASC" in repr(fact.value)
            and any(
                other.kind == "semantic.print"
                and other.subject == fact.subject
                and other.value[2:3] == fact.value[2:3]
                and "ASC" not in repr(other.value)
                for other in by_kind.get(fact.kind, ())
            )
        ):
            continue
        if (
            fact.kind == "semantic.do"
            and fact.value[:1] == ("UNTIL",)
            and any(
                other.kind == "semantic.do"
                and other.subject == fact.subject
                and other.value[:1] == ("WHILE",)
                for other in by_kind.get(fact.kind, ())
            )
        ):
            continue
        if (
            fact.kind == "semantic.print"
            and len(fact.value) >= 3
            and fact.value[2] is False
            and len(fact.subject) == 2
            and any(
                other.kind == "semantic.print"
                and len(other.value) >= 3
                and other.value[2] is True
                and other.subject[0] == fact.subject[0]
                and other.value[1] == fact.value[1]
                for other in by_kind.get(fact.kind, ())
            )
        ):
            continue
        if (
            fact.kind == "semantic.data"
            and any(other.kind == "layout.line_table" for other in facts)
            and any(
                other.kind == "semantic.data"
                and other.subject[:1] != fact.subject[:1]
                and other.subject[0] > fact.subject[0]
                and len(fact.value) == 1
                and len(other.value) == 1
                and len(fact.value[0]) > len(other.value[0])
                for other in by_kind.get(fact.kind, ())
            )
        ):
            continue
        if fact.kind == "semantic.def_type" and any(
            other.kind == "semantic.data" and other.subject == fact.subject
            for other in facts
        ):
            continue
        if (
            fact.kind == "semantic.print"
            and len(fact.value) >= 3
            and fact.value[2] is False
            and isinstance(fact.value[1], tuple)
            and len(fact.value[1]) > 1
            and any(
                other.kind == "semantic.print"
                and len(other.value) >= 2
                and other.subject[:1] == fact.subject[:1]
                and other.value[1] == (fact.value[1][0],)
                for other in by_kind.get(fact.kind, ())
            )
            and any(
                other.kind == "semantic.print"
                and len(other.value) >= 2
                and other.subject[:1] != fact.subject[:1]
                and other.value[1] == (fact.value[1][-1],)
                for other in by_kind.get(fact.kind, ())
            )
        ):
            continue
        if (
            fact.kind == "semantic.print"
            and len(fact.value) >= 2
            and isinstance(fact.value[1], tuple)
            and len(fact.value[1]) == 1
            and isinstance(fact.value[1][0], tuple)
            and fact.value[1][0][:1] == ("call",)
            and any(
                other.kind == "semantic.print"
                and other.subject[1] == fact.subject[1]
                and len(other.value) >= 2
                and isinstance(other.value[1], tuple)
                and len(other.value[1]) == 1
                and isinstance(other.value[1][0], tuple)
                and other.value[1][0][:1] == ("array",)
                for other in by_kind.get(fact.kind, ())
            )
        ):
            continue
        if (
            fact.kind == "semantic.print"
            and len(fact.subject) == 2
            and len(fact.value) >= 2
            and isinstance(fact.value[1], tuple)
            and len(fact.value[1]) == 1
            and isinstance(fact.value[1][0], tuple)
            and fact.value[1][0][:2] == ("call", "ASC")
            and any(
                other.kind == "semantic.print"
                and len(other.subject) == 2
                and other.subject[1] == fact.subject[1]
                and other.subject[0] > fact.subject[0]
                for other in by_kind.get(fact.kind, ())
            )
        ):
            continue
        materialized.add(identity)
        if kind in {"ir.dim", "ir.common", "ir.option_base"}:
            operation = _static_dim_operation(evidence, fact)
            if operation is not None:
                operations.append(operation)
            continue
        if fact.kind in {
            "semantic.data",
            "semantic.def_type",
            "semantic.do_codeless",
        }:
            operation = _codeless_operation(fact)
            if operation is not None:
                operations.append(operation)
            continue
        span = _span(fact, len(evidence.image))
        if span is None:
            continue
        value = fact.value
        # An arm's closing jump skips the rest of its block, so a jump to it
        # leaves the block.
        if fact.kind == "semantic.goto" and len(value) == 1 and value[0] in arm_closes:
            value = (arm_closes[value[0]],)
        if (
            fact.kind == "semantic.if_goto"
            and len(value) >= 4
            and value[3] in arm_closes
        ):
            value = (*value[:3], arm_closes[value[3]], *value[4:])
        if fact.kind == "semantic.assign" and len(value) == 2:
            resolved = resolve_expression(value[1], snapshot)
            if resolved is not None:
                value = value[0], resolved.value
        start, end = span
        if fact.kind == "semantic.if_goto" and len(value) >= 4:
            # IF c THEN EXIT SUB: the IF's closing jump leaves the SUB, so the
            # statement is an inline IF whose body is that EXIT SUB.
            tail = next(
                (
                    subject
                    for subject, target in exit_sub_targets.items()
                    if subject[1] == end and target == value[3]
                ),
                None,
            )
            if tail is not None:
                kind = "ir.if_inline"
                value = (tuple(value[:3]), tail[0], tail[1], None)
        raw = evidence.image[start:end].hex(" ")
        operations.append(
            Operation(start, end - start, kind, value, raw, fact.confidence)
        )
    return tuple(sorted(operations, key=_operation_key))


def _cleanup_clear(raw: tuple[object, ...]) -> bool:
    """Return whether a two-byte ``xor`` begins compiler or library cleanup."""
    text = raw[0] if raw and isinstance(raw[0], str) else ""
    return text == "31 d2" or text.startswith("33")


def _unresolved_procedure_values(value: object) -> bool:
    return (
        isinstance(value, tuple)
        and bool(value)
        and value[0] in {"unresolved-frame", "unresolved-call-arguments"}
    )


_FRAME_KINDS = {"tb.proc_enter", "tb.proc_return", "tb.fn_return"}
"""A procedure's frame setup and return, which its definition accounts for."""


def build_program_operations(
    evidence: Evidence, semantic: tuple[Operation, ...]
) -> tuple[Operation, ...]:
    """Build the final IR operation stream from recovered facts."""

    # A procedure's definition spans its body, but claims only its header:
    # its statements claim themselves, and code between them is unknown.
    claimed = tuple(
        (
            (operation.offset, operation.operands[0])
            if operation.kind in {"ir.sub_def", "ir.def_fn"}
            and operation.operands
            and isinstance(operation.operands[0], int)
            and operation.offset <= operation.operands[0] < operation.end
            else (operation.offset, operation.end)
        )
        for operation in semantic
        if operation.size > 0
    )
    # Semantic operations are numerous in large programs.  Scanning every
    # claimed span for every instruction is quadratic (and made some wild
    # binaries take minutes).  Prefix maxima preserve enclosing spans when
    # a later-starting span is nested inside an earlier one.
    claimed = tuple(sorted(set(claimed)))
    claimed_starts = tuple(start for start, _ in claimed)
    claimed_ends = tuple(accumulate((end for _, end in claimed), max))

    def is_claimed(instruction: Operation) -> bool:
        index = bisect_right(claimed_starts, instruction.offset) - 1
        return index >= 0 and instruction.end <= claimed_ends[index]

    boundaries = {block.start for block in evidence.blocks}
    structural: list[Operation] = []
    unknown: list[Operation] = []
    for instruction in evidence.instructions:
        if is_claimed(instruction) or instruction.kind in _FRAME_KINDS:
            continue
        if instruction.kind in {
            "tb.prologue",
            "tb.statement",
            "tb.epilogue",
            "tb.commit",
        }:
            _flush_unknown(unknown, structural)
            structural.append(instruction)
            continue
        if unknown and (
            unknown[-1].end != instruction.offset or instruction.offset in boundaries
        ):
            _flush_unknown(unknown, structural)
        unknown.append(instruction)
    _flush_unknown(unknown, structural)
    return tuple(sorted((*semantic, *structural), key=_operation_key))


def _flush_unknown(pending: list[Operation], result: list[Operation]) -> None:
    if not pending:
        return
    kinds = tuple(dict.fromkeys(instruction.kind for instruction in pending))
    result.append(
        Operation(
            pending[0].offset,
            pending[-1].end - pending[0].offset,
            "unknown.region",
            (len(pending), kinds),
            " ".join(instruction.raw for instruction in pending),
            "opaque",
        )
    )
    pending.clear()


def _static_dim_operation(evidence: Evidence, fact: Fact) -> Operation | None:
    if len(fact.subject) != 2:
        return None
    start, order = fact.subject
    if not isinstance(start, int) or not isinstance(order, int):
        return None
    raw = " ".join(
        evidence.image[address : address + 1].hex()
        for address in fact.evidence
        if 0 <= address < len(evidence.image)
    )
    operands = (order, *fact.value)
    return Operation(
        start,
        0,
        _OPERATION_KINDS[fact.kind],
        operands,
        raw,
        fact.confidence,
    )


def _codeless_operation(fact: Fact) -> Operation | None:
    if not fact.subject or not isinstance(fact.subject[0], int):
        return None
    if fact.kind == "semantic.data":
        operands = (*fact.subject[1:], *fact.value)
    elif fact.kind == "semantic.def_type":
        operands = (*fact.subject[1:], *fact.value)
    else:
        operands = fact.value
    return Operation(
        fact.subject[0],
        0,
        _OPERATION_KINDS[fact.kind],
        operands,
        "",
        fact.confidence,
    )


def _span(fact: Fact, image_size: int) -> tuple[int, int] | None:
    if len(fact.subject) != 2:
        return None
    start, end = fact.subject
    if not isinstance(start, int) or not isinstance(end, int):
        return None
    return (start, end) if 0 <= start < end <= image_size else None


def _operation_key(operation: Operation) -> tuple[int, int, int, str]:
    if (
        operation.kind == "ir.print"
        and len(operation.operands) >= 2
        and isinstance(operation.operands[1], tuple)
        and len(operation.operands[1]) == 1
        and isinstance(operation.operands[1][0], tuple)
        and operation.operands[1][0][:1] in {("call",), ("array",)}
    ):
        return operation.end, operation.offset, 1000, operation.kind
    if operation.kind == "ir.assign":
        if (
            isinstance(operation.operands, tuple)
            and operation.operands
            and isinstance(operation.operands[0], tuple)
            and operation.operands[0][:1] == ("array",)
            and len(operation.operands[0]) >= 3
            and isinstance(operation.operands[0][2], tuple)
            and (
                len(operation.operands[0][2]) >= 4
                or (
                    len(operation.operands[0][2]) == 1
                    and isinstance(operation.operands[0][1], str)
                    and operation.operands[0][1].endswith("%")
                )
            )
        ):
            return operation.offset, operation.end, 1000, operation.kind
        # Nested compiler templates execute their inner store before the
        # enclosing expression is complete (for example DIMM's array copy).
        # End-order preserves that source order while leaving non-assignments
        # address-ordered.
        return operation.end, operation.offset, 1000, operation.kind
    if operation.kind == "ir.dim":
        return operation.offset, 1_000_000, operation.operands[0], ""
    if operation.kind in {"ir.common", "ir.option_base"}:
        return operation.offset, operation.end, operation.operands[0], ""
    toggles = {"ir.tron": 0, "ir.troff": 1}
    if operation.kind in {"ir.data", "ir.def_type"}:
        return operation.offset, operation.end, operation.operands[0], operation.kind
    if operation.kind == "ir.do":
        return operation.offset, operation.end, -1, operation.kind
    if operation.kind == "ir.loop":
        # A loop marker closes the body it spans.  Ordering it by its end
        # keeps anchored codeless loops after the final body operation.
        return operation.end, operation.end, 1001, operation.kind
    return (
        operation.offset,
        operation.end,
        toggles.get(operation.kind, 1000),
        operation.kind,
    )
