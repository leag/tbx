"""Pure operation-template matchers.

A matcher inspects an operation window and returns facts about it. It never
mutates decode state, advances a cursor, or infers a missing layout fact from
position -- the applier owns all of that. Separating them makes the accepted
byte vocabulary visible: a matcher's ``None`` says "not this template", and
the applier turns that into the same fail-loud `ValueError` as before.

Every result carries the calibrated template's name and the operation range it
covers, so a caller can report what was recognized and how much of the stream
that claim rests on. The range is the *template's* extent, not necessarily what
the applier consumes: a boolean header is six operations wide even when folding
the whole expression runs much further.

Matchers accept either ``(ops, index)`` or an :class:`OpCursor` positioned at
the candidate. The cursor form is read-only -- matching never moves it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tbx import ir
from tbx.decode0.cursor import OpCursor
from tbx.decode0.const import _JCC_RELOP_TRUE


@dataclass(frozen=True)
class TemplateMatch:
    """What a matcher recognized, and the operations it rests on."""

    template: str
    start: int
    stop: int

    @property
    def consumed(self) -> int:
        """Operation count the recognized template covers."""
        return self.stop - self.start


@dataclass(frozen=True)
class DelayMatch(TemplateMatch):
    """``delay_init [trap_hook]* delay_poll jcc loop_back``."""

    hooks: tuple[tuple[Any, ...], ...] = ()
    loop_back: int = 0


@dataclass(frozen=True)
class BoolTermMatch(TemplateMatch):
    """A compound-boolean first term and the combinator it joins with."""

    operator: str = ""
    #: The jcc condition code that gates the term's own short circuit.
    polarity: int = 0
    #: Where that short circuit lands -- the evidence tying this term to its
    #: partner, since the two can sit many operations apart.
    short_circuit: int = 0
    #: True when the partner is a multi-term inner group rather than the very
    #: next term, so the caller must defer folding until that group resolves.
    deferred: bool = False


@dataclass(frozen=True)
class ForHeaderMatch(TemplateMatch):
    """The x87 FOR header's three staged slots.

    A FOR header is split across committed statements (the limit/step/init
    assignments) and a byte template (the sign test). When the evidence is
    entirely in the statements the range is zero-width -- see
    :func:`match_for_header`.
    """

    #: DGROUP or bp-relative displacements of the three staged cells.
    limit: int = 0
    step: int = 0
    var: int = 0


@dataclass(frozen=True)
class ProcBodyMatch(TemplateMatch):
    """A SUB/DEF FN body's extent and the two addresses its frame needs."""

    #: Address of the ``proc_ret`` that closes the body.
    ret_address: int = 0
    #: Address an ``EXIT SUB`` jumps to -- the start of the string-descriptor
    #: epilogue when there is one, otherwise the ``proc_ret`` itself.
    exit_address: int = 0
    #: Number of ``arg_ref; str_temp_free`` pairs in that epilogue.
    freed_strings: int = 0


@dataclass(frozen=True)
class ArrayParamTypeMatch(TemplateMatch):
    """The element type of an array parameter, read off a later access."""

    #: bp-relative offset of the parameter's descriptor.
    block: int = 0
    #: BASIC type suffix witnessed by the terminal operation.
    suffix: str = ""
    #: The terminal operation that witnessed it.
    terminal: str = ""


@dataclass(frozen=True)
class UsingEmitMatch(TemplateMatch):
    """A ``PRINT USING`` emit and the output leg its item vector names."""

    #: True when the value comes off the FP stack (CB), False off the string
    #: stack (CC).
    numeric: bool = True
    #: "console", "printer", or "file" -- the leg the item vector selects.
    leg: str = ""


@dataclass(frozen=True)
class TargetMatch(TemplateMatch):
    """A control-flow template carrying one absolute code target."""

    target: int = 0


#: Item vector -> output leg, for the operation that follows a USING emit.
_USING_ITEM_LEG = {0xBE: "console", 0xC0: "file", 0xBF: "printer"}

#: Vectors that emit another value into an open USING chain.
_USING_EMIT_VECS = frozenset({0xCB, 0xCC})

#: Vectors that end one: a new USING header or a chain terminator.
_USING_CHAIN_ENDS = frozenset({0xCA, 0xB8, 0xB9})


def _same_code_offset(a: int, b: int) -> bool:
    """Compare code positions modulo the 64 KiB near-jump window.

    The scanner retains a near branch's canonical first-window target, but a
    later procedure can spell the same IP 64 KiB above it (wild electron.exe).
    """
    return (a - b) % 0x10000 == 0


def _window(ops, index):
    """Normalize the ``(ops, index)`` / cursor calling convention."""
    if isinstance(ops, OpCursor):
        if index is not None:
            raise TypeError("cursor matcher does not accept a separate index")
        return ops.ops, ops.index
    if index is None:
        raise TypeError("operation index is required")
    return ops, index


def match_return_to(ops, index: int | None = None) -> TargetMatch | None:
    """Ordinary-GOSUB ``RETURN <line>``: unwind its word, then jump.

    Event-trap returns use the scanner's dedicated ``return_to`` operation.
    A regular GOSUB frame instead compiles as ``add sp,2`` followed by either
    jump width (``t1_returngosub``; wild mdb.exe/mdb87.exe).
    """
    ops, index = _window(ops, index)
    if (
        index + 1 >= len(ops)
        or ops[index][1:] != ("add_sp", 2)
        or ops[index + 1][1] not in ("jmp", "jmps")
    ):
        return None
    return TargetMatch(
        template="return_to_gosub",
        start=index,
        stop=index + 2,
        target=ops[index + 1][2],
    )


def match_bool_term1(ops, index: int | None = None) -> BoolTermMatch | None:
    """Recognize a materialized compound-boolean first term.

    ``ops[index]`` is ``movax FFFF`` with a pending compare. The first term of
    a compound IF is the materialization header whose closing jmp
    short-circuits INTO the second term's tail: AND (jnz dispatch) jumps to the
    commit after ``and ax,bx``; OR (jz) jumps to the tail's ``or ax,ax`` with
    ax still 0FFFFh.

    ``operator`` is the combinator that folds this term with whatever comes
    next. ``deferred`` is True when the matched partner is not the next term to
    materialize but a multi-term inner GROUP further ahead -- a
    differently-precedenced sub-expression, e.g. ``A OR B AND C`` = ``A OR (B
    AND C)``, where A's short circuit lands on the group's own convergence
    point rather than on B (wild wb.exe/grdscn.exe/mcmurphy.exe, probes
    q_mixedbool5/q_mixedbool6). It is detected by another ``movax 0FFFFh``
    materialization sitting strictly between here and the match: register
    shuffles before a direct combine never include one, since only a genuine
    extra TERM's own self-test does (t1_and3 and wild number.exe's shuffle
    dance around cmpax_m prove the shuffle alone is not a signal).

    Returns None when ``ops[index]`` is not a compound-IF first term at all --
    then it is a WHILE header, which the address equality disambiguates
    exactly.
    """
    ops, index = _window(ops, index)
    if [o[1] for o in ops[index : index + 6]] != [
        "movax",
        "jcc",
        "incax",
        "orax",
        "jcc",
        "jmp",
    ]:
        return None
    if (
        ops[index + 1][3] != ops[index + 3][0]
        or ops[index + 1][2] not in _JCC_RELOP_TRUE
        or ops[index + 4][3] != ops[index + 5][0] + 3
    ):
        return None
    polarity, short_circuit = ops[index + 4][2], ops[index + 5][2]
    combination = {0x75: ("andaxbx", "AND"), 0x74: ("orax", "OR")}.get(polarity)
    if combination is None:
        return None
    other = ("orax", "OR") if combination[0] == "andaxbx" else ("andaxbx", "AND")
    seen_materialize = False
    for j in range(index + 6, min(index + 36, len(ops) - 3)):
        if ops[j][1] != "movax" or ops[j][2] != 0xFFFF:
            continue
        next_kinds = [o[1] for o in ops[j + 1 : j + 4]]
        for candidate in (combination, other):
            if next_kinds == ["jcc", "incax", candidate[0]]:
                delta = 2 if candidate[1] == "AND" else 0
                if _same_code_offset(short_circuit, ops[j + 3][0] + delta):
                    # term1's OWN polarity is always how it joins whatever was
                    # found -- `candidate` only describes the SHAPE of that
                    # thing (a same-op cascade continuation, or a
                    # differently-precedenced inner group), never the join
                    # operator itself.
                    return BoolTermMatch(
                        template="bool_term1",
                        start=index,
                        stop=index + 6,
                        operator=combination[1],
                        polarity=polarity,
                        short_circuit=short_circuit,
                        deferred=seen_materialize,
                    )
        seen_materialize = True
    return None


def match_string_logical_value_group(
    ops, index: int | None = None
) -> BoolTermMatch | None:
    """Explicit string-led relational ``AND|OR`` value group.

    Unlike an unparenthesized compound IF, this form has no short-circuit
    dispatch after its first term. Both relations materialize independently,
    fold through AX/BX, and only the completed value feeds a jcc/jmp decision
    (t1_stringorvalueif; wild kinder.exe, whose right relation is numeric).
    Requiring the immediately preceding ``strcmp`` distinguishes this from
    the numeric-led parenthesized group in t1_orofands.
    """
    ops, index = _window(ops, index)
    if (
        index == 0
        or ops[index - 1][1] != "strcmp"
        or index + 3 >= len(ops)
        or ops[index][1:] != ("movax", 0xFFFF)
        or ops[index + 1][1] != "jcc"
        or ops[index + 1][2] not in _JCC_RELOP_TRUE
        or ops[index + 2][1] != "incax"
        or ops[index + 1][3] != ops[index + 3][0]
    ):
        return None
    for j in range(index + 3, min(index + 14, len(ops) - 7)):
        if any(
            op[1] in ("jcc", "jmp", "jmpf", "jmps")
            for op in ops[index + 3 : j]
        ):
            # An intervening dispatch closes the first term as an ordinary
            # short-circuit chain; do not reach across it into a later
            # materialization (t1_mixedbool).
            continue
        tail = [o[1] for o in ops[j : j + 8]]
        if (
            tail[0] not in ("strcmp", "fstsw")
            or tail[1:5] != ["movbxax", "movax", "jcc", "incax"]
        ):
            continue
        combination = {"andaxbx": "AND", "oraxbx": "OR"}.get(tail[5])
        if (
            combination is None
            or ops[j + 2][2] != 0xFFFF
            or ops[j + 3][2] not in _JCC_RELOP_TRUE
            or ops[j + 3][3] != ops[j + 5][0]
            or tail[6:] != ["jcc", "jmp"]
            or ops[j + 6][2] not in (0x74, 0x75)
            or ops[j + 6][3] != ops[j + 7][0] + 3
        ):
            continue
        return BoolTermMatch(
            template="string_logical_value_group",
            start=index,
            stop=j + 8,
            operator=combination,
            polarity=ops[j + 6][2],
            short_circuit=ops[j + 7][2],
        )
    if any(
        ops[j][1] == "oraxbx"
        for j in range(index + 3, min(index + 36, len(ops)))
    ):
        return BoolTermMatch(
            template="string_logical_value_group_split",
            start=index,
            stop=index + 3,
            operator="OR",
        )
    if any(
        ops[j][1] == "andaxbx"
        and j + 3 < len(ops)
        and ops[j + 1][1] == "notax"
        and ops[j + 2][1] == "orax"
        for j in range(index + 3, min(index + 36, len(ops)))
    ):
        return BoolTermMatch(
            template="string_logical_value_group_not",
            start=index,
            stop=index + 3,
            operator="AND",
        )
    return None


def match_numeric_logical_value_group(
    ops, index: int | None = None
) -> BoolTermMatch | None:
    """Mirror of :func:`match_string_logical_value_group`: a NUMERIC-led
    relational ``AND|OR`` value group whose second term is a string relation.

    Same non-short-circuiting shape (both relations always materialize, only
    the completed value feeds the final jcc/jmp), just with the leading
    relation numeric instead of string -- ``ops[index]`` is the numeric
    term's own ``movax FFFF`` materialization (no ``orax`` tail, unlike an
    ordinary short-circuit chain's first term), and the tail's own second
    term is a raw ``strcmp`` rather than the numeric ``fstsw`` the string-led
    matcher's tail also accepts. Wild kinder.exe: `IF A# = B# OR C$ = D$
    THEN <line>` (probe q_numstrvaluegroup).

    A 3rd (or later) term chains flat off the same tail shape with no
    closing ``jcc;jmp`` of its own -- just more term-staging leading into
    the NEXT ``strcmp``/fold (wild kinder.exe's real witness is a 3-term
    `A# = B# OR C$ = D$ OR C$ = E$`, probe q_numstr3chain) -- so only the
    fold through ``oraxbx`` is required here; whether that closes the whole
    expression or continues is for the caller's downstream fold (the
    ``direct_bool_gate``/``reg_logical_results`` chain machinery) to decide,
    not this recognizer.

    OR only: the combine-time fold this feeds (``arith.py``'s ``oraxbx and
    e.direct_bool_group is not None`` branch) has no AND counterpart -- the
    sibling ``andaxbx`` branch belongs to a DIFFERENT feature
    (``match_bool_outer_and_group``) that happens to share the
    ``direct_bool_gate`` flag but not the register orientation this shape
    needs, so accepting AND here would silently fold with the wrong operand
    order (checked: probed `A# = B# AND C$ = D$` this way emits a misplaced
    Group and does not recompile byte-identical).
    """
    ops, index = _window(ops, index)
    if (
        index + 3 >= len(ops)
        or ops[index][1:] != ("movax", 0xFFFF)
        or ops[index + 1][1] != "jcc"
        or ops[index + 1][2] not in _JCC_RELOP_TRUE
        or ops[index + 2][1] != "incax"
        or ops[index + 1][3] != ops[index + 3][0]
    ):
        return None
    for j in range(index + 3, min(index + 14, len(ops) - 6)):
        if any(
            op[1] in ("jcc", "jmp", "jmpf", "jmps")
            for op in ops[index + 3 : j]
        ):
            # An intervening dispatch closes the first term as an ordinary
            # short-circuit chain; do not reach across it into a later
            # materialization.
            continue
        tail = [o[1] for o in ops[j : j + 6]]
        if (
            tail != ["strcmp", "movbxax", "movax", "jcc", "incax", "oraxbx"]
            or ops[j + 2][2] != 0xFFFF
            or ops[j + 3][2] not in _JCC_RELOP_TRUE
            or ops[j + 3][3] != ops[j + 5][0]
        ):
            continue
        return BoolTermMatch(
            template="numeric_logical_value_group",
            start=index,
            stop=j + 6,
            operator="OR",
        )
    # Numeric-led groups in older compiler revisions place the second
    # materialization before the second strcmp's argument setup (kinder.exe),
    # so the OR fold is not adjacent to the first strcmp tail.  The same
    # materialization/jcc/incax evidence plus a nearby oraxbx is sufficient to
    # stage the first term; the later fold is consumed by the regular handler.
    if any(
        ops[j][1] == "oraxbx"
        for j in range(index + 3, min(index + 32, len(ops)))
    ):
        return BoolTermMatch(
            template="numeric_logical_value_group_split",
            start=index,
            stop=index + 3,
            operator="OR",
        )
    return None


def match_bool_bare_term1(ops, index: int | None = None) -> BoolTermMatch | None:
    """Sibling of :func:`match_bool_term1` for a bare-value compound term.

    ``ops[index]`` is an ``orax`` self-testing a just-computed value (e.g. a
    function call's raw result), immediately followed by the same jcc+jmp
    short-circuit-skip idiom (jcc target == jmp addr + 3). TB's AND/OR operate
    on the raw integer value, not a coerced 0/-1 boolean, so a bare-value term
    is never materialized via ``movax FFFF`` the way a comparison is (wild
    rsltest.exe: ``PEEK(&H410) AND &H40 = 48`` -- PEEK's raw byte combined via
    bitwise AND with a materialized comparison; TEST.BAS line 159, where
    BASIC's own relational-over-AND precedence makes this parse as
    ``PEEK(&H410) AND (&H40=48)``, confirmed byte-exact via a dedicated oracle
    probe).

    OR uses JZ and lands directly on the trailing ``orax``; this is calibrated
    by ``t1_bareor`` and witnessed by wild cal.exe/cal87.exe.
    """
    ops, index = _window(ops, index)
    if (
        ops[index][1] != "orax"
        or index + 2 >= len(ops)
        or ops[index + 1][1] != "jcc"
        or ops[index + 1][2] not in (0x74, 0x75)
        or ops[index + 2][1] != "jmp"
        or ops[index + 1][3] != ops[index + 2][0] + 3
    ):
        return None
    polarity = ops[index + 1][2]
    combinator, operator, delta = {
        0x75: ("andaxbx", "AND", 2),
        0x74: ("orax", "OR", 0),
    }[polarity]
    short_circuit = ops[index + 2][2]
    for j in range(index + 3, min(index + 36, len(ops) - 3)):
        if ops[j][1] != "movax" or ops[j][2] != 0xFFFF:
            continue
        if (
            ops[j + 1][1] == "jcc"
            and ops[j + 2][1] == "incax"
            and ops[j + 3][1] == combinator
            and _same_code_offset(short_circuit, ops[j + 3][0] + delta)
        ):
            return BoolTermMatch(
                template="bool_bare_term1",
                start=index,
                stop=index + 3,
                operator=operator,
                polarity=polarity,
                short_circuit=short_circuit,
            )
        # The first materialization decides: a later one belongs to a
        # different term, not to this one.
        return None
    return None


def match_bool_outer_and_group(ops, index: int | None = None) -> BoolTermMatch | None:
    """Outer ``A AND (B OR C)`` header, whose skip lands at the final AND.

    The right group owns the register-spill protocol rather than starting with
    a directly-combined materialization (probe_string_nested_and_or_block;
    wild grdscn.exe).
    """
    ops, index = _window(ops, index)
    if [o[1] for o in ops[index : index + 6]] != [
        "movax",
        "jcc",
        "incax",
        "orax",
        "jcc",
        "jmp",
    ]:
        return None
    materialize, gate, jmp = ops[index + 1], ops[index + 4], ops[index + 5]
    if not (
        materialize[3] == ops[index + 3][0]
        and materialize[2] in _JCC_RELOP_TRUE
        and gate[2] == 0x75
        and gate[3] == jmp[0] + 3
        and any(
            o[1] == "andaxbx" and _same_code_offset(jmp[2], o[0] + 2)
            for o in ops[index + 6 : index + 36]
        )
        # The parenthesized right group parks the outer value in CX while
        # its own BX fold runs, then restores it for the final AND. A flat
        # `A AND B` has the same header and convergence address but no CX
        # spill, so accepting it here would steal ordinary compound chains.
        and ("movrr", "cx", "bx") in [
            o[1:] for o in ops[index + 6 : index + 36]
        ]
        and ("movrr", "bx", "cx") in [
            o[1:] for o in ops[index + 6 : index + 36]
        ]
    ):
        return None
    return BoolTermMatch(
        template="bool_outer_and_group",
        start=index,
        stop=index + 6,
        operator="AND",
        polarity=gate[2],
        short_circuit=jmp[2],
    )


_ARR_PARAM_SUFFIX_BY_TERMINAL = {
    "far_spush": "$",
    "far_strassign": "$",
    "far_fild_si": "%",
    "far_fstp_si": "%",
    "far_fild_si32": "&",
    "far_fstp_si32": "&",
}


def _staged_for_slots(stmts):
    """The three trailing assignments a FOR header stages, or None.

    A FOR variable is never a string, and consecutive string slots are ALSO 4
    bytes apart, so the displacement probe could false-positive on three
    trailing string assigns before a GOTO (witnessed t1_strgoto, wild
    inv87.exe -- vdisp cannot even parse the "$" placeholder).
    """
    if len(stmts) < 3 or not all(isinstance(s, ir.Assign) for s in stmts[-3:]):
        return None
    staged = stmts[-3:]
    if not all(isinstance(s.target, ir.Var) for s in staged):
        return None
    if any(s.target.name.endswith("$") for s in staged):
        return None
    return staged


def match_for_header(stmts, vdisp) -> ForHeaderMatch | None:
    """The canonical FOR header: limit at ``v-4``, step at ``v-8``, init at ``v``.

    This one reads only committed statements -- the compiler's slot layout is
    the whole evidence -- so the match is zero-width in the operation stream.
    """
    staged = _staged_for_slots(stmts)
    if staged is None:
        return None
    lim_s, stp_s, init_s = staged
    var = vdisp(init_s.target)
    if vdisp(lim_s.target) != var - 4 or vdisp(stp_s.target) != var - 8:
        return None
    return ForHeaderMatch(
        template="for_header",
        start=0,
        stop=0,
        limit=var - 4,
        step=var - 8,
        var=var,
    )


def match_loose_for_header(ops, index, stmts, vdisp) -> ForHeaderMatch | None:
    """The x87 FOR header when its temp slots are non-adjacent.

    The normal compiler layout puts limit and step at ``v-4``/``v-8``. Some
    wild programs retain earlier user variables between those slots, but the
    sign test at the target still names the three slots explicitly. Match only
    the complete, distinctive test prefix; otherwise an arbitrary ``testw``
    could become a FOR.
    """
    staged = _staged_for_slots(stmts)
    if staged is None:
        return None
    lim_s, stp_s, init_s = staged
    ops, index = _window(ops, index)
    if index >= len(ops) or ops[index][1] not in ("testw", "testw_bp"):
        return None
    if index + 3 > len(ops):
        # Too little stream left to BE this template. Not a guess: a match
        # needs the full distinctive prefix, and a truncated one has none.
        return None
    test, jcc, skip = ops[index : index + 3]
    if jcc[1] != "jcc" or jcc[2] != 0x74 or skip[1] != "jmp":
        return None
    if index + 6 >= len(ops):
        return None
    first_fld, first_cmp, first_sw = ops[index + 3 : index + 6]
    pair = (first_fld[1], first_cmp[1])
    single_pairs = {
        ("fld", "fcomp"),
        ("fld", "fcomp_bp"),
        ("fld_bp", "fcomp"),
        ("fld_bp", "fcomp_bp"),
    }
    if pair not in single_pairs | {("fld64", "fcomp64")} or first_sw[1] != "fstsw":
        return None
    # TEST names the step cell, independently of where the limit and loop
    # variable live. Mixed DEF FN frames keep limit/step BP-relative while the
    # loop variable remains in DGROUP (wild cleanup.exe/reformat.exe).
    if (test[1] == "testw_bp") != (pair[0] == "fld_bp"):
        return None
    if jcc[3] != first_fld[0]:
        return None

    # Positive-path body branch: direct JAE BODY, or its long-distance form
    # JB +3; JMP BODY. It is followed by the unconditional EXIT jump.
    i = index + 6
    if ops[i][1] == "jcc" and ops[i][2] == 0x73:
        body = ops[i][3]
        i += 1
    elif (
        i + 1 < len(ops)
        and ops[i][1] == "jcc"
        and ops[i][2] == 0x72
        and ops[i][3] == ops[i][0] + 5
        and ops[i + 1][1] == "jmp"
    ):
        body = ops[i + 1][2]
        i += 2
    else:
        return None
    if i >= len(ops) or ops[i][1] != "jmp":
        return None
    i += 1
    if i + 2 >= len(ops):
        return None
    second_fld, second_cmp, second_sw = ops[i : i + 3]
    if (second_fld[1], second_cmp[1]) != pair or second_sw[1] != "fstsw":
        return None
    i += 3
    if i < len(ops) and ops[i][1] == "jcc" and ops[i][2] == 0x76:
        if not _same_code_offset(ops[i][3], body):
            return None
    elif (
        i + 1 < len(ops)
        and ops[i][1] == "jcc"
        and ops[i][2] == 0x77
        and ops[i][3] == ops[i][0] + 5
        and ops[i + 1][1] == "jmp"
        # The scanner canonicalizes near targets to the branch's first
        # 64-KiB window.  A long FOR body can therefore be named by the
        # equivalent offset in the current window (wild mcmurphy.exe).
        and _same_code_offset(ops[i + 1][2], body)
    ):
        # Keep the branch's own canonical target for downstream FOR-frame
        # bookkeeping; it is the address later operations will use.
        body = ops[i + 1][2]
        i += 2
    else:
        return None
    if not _same_code_offset(skip[2], second_fld[0]):
        return None
    limit, var = first_fld[2], first_cmp[2]
    # The sign bit lives in the high word of the step cell: +2 for SINGLE,
    # +6 for DOUBLE (wild electron/elec87).
    step = test[2] - (6 if pair[0] == "fld64" else 2)
    if (second_fld[2], second_cmp[2]) != (limit, var):
        return None
    if (vdisp(lim_s.target), vdisp(stp_s.target), vdisp(init_s.target)) != (
        limit,
        step,
        var,
    ):
        return None
    return ForHeaderMatch(
        template="loose_for_header",
        start=index,
        stop=i,
        limit=limit,
        step=step,
        var=var,
    )


#: Register-shuttle operations that may sit between a ``fn_call`` and the
#: read-back of its result -- they bank an operand, they do not compute one.
_REGISTER_SHUTTLE = frozenset({"movbxax", "movrr"})


def epilogue_entry(ops, closer: int, floor: int = 0) -> tuple[int, int]:
    """(index an EXIT lands on, count of strings freed) for the body closing at
    ``closer``.

    A body's epilogue is the run immediately before its return: one
    ``arg_ref <disp>; str_temp_free`` pair per LOCAL/parameter string, one
    ``movsi <disp>; local_arr_free`` pair per LOCAL dynamic array, plus the
    ``trap_hook`` poll stamps a trapping build leaves there. All of it is a
    no-op to the lift, so it produces no statement -- but it IS where an EXIT
    SUB / EXIT DEF jumps, and the address it jumps to is the FIRST op of the
    run, not the return.

    Shared by ``match_proc_body`` and the block DEF FN frame, which has no
    ``proc_enter`` to be matched and so has to walk its own epilogue back.
    """
    i, freed = closer, 0
    while i > floor:
        if ops[i - 1][1] == "trap_hook":
            i -= 1
            continue
        if (
            i - 2 >= floor
            and ops[i - 1][1] == "str_temp_free"
            and ops[i - 2][1] == "arg_ref"
        ):
            i -= 2
            freed += 1
            continue
        if (
            i - 2 >= floor
            and ops[i - 1][1] == "local_arr_free"
            and ops[i - 2][1] == "movsi"
        ):  # a LOCAL dynamic array's heap block, released the same way and in
            # the same place (wild cleanup.exe, reformat.exe, whose three EXIT
            # SUBs each aim at the stamp ahead of this pair). Counted apart
            # from the strings: `freed_strings` is what the retf pop
            # arithmetic reads, and an array block is not a string descriptor.
            i -= 2
            continue
        break
    return i, freed


def match_proc_body(ops, index: int | None = None) -> ProcBodyMatch | None:
    """Extent of the SUB/DEF FN body opened by ``proc_enter`` at ``index``.

    A SUB with LOCAL string variables frees their descriptors in the epilogue,
    as a run of ``arg_ref <disp>; str_temp_free`` pairs ahead of the
    ``proc_ret`` (t1_localstr/t1_locstrafterfor). Both are no-ops to the lift,
    so the run produces no statement -- but it IS where an ``EXIT SUB`` jumps,
    so the frame's exit address has to name the FIRST pair, not the
    ``proc_ret``.

    Under event trapping the epilogue also carries ``trap_hook`` stamps, which
    are no-ops to the lift in the same way, and the EXIT SUB jumps to the first
    of those (wild help.exe, resume.exe, rsltest.exe -- ``jump target 0x8b06 /
    0xa3d7 / 0xae3a is not a statement start``). Fixture t1_exitsubtrap.

    Recognizing only the ``proc_ret`` left the EXIT SUB decoded as a plain Goto
    to an address no statement owns (wild tbd73.exe, TBW73.INC:452: ``EXIT
    SUB`` inside ``IF curntpos > itemcount THEN ... END IF`` in ``SUB
    Makevmenu``, whose two LOCAL strings ``ans$, ans1$`` make the epilogue
    start six bytes early -- ``jump target 0xc2cc is not a statement start``).
    Fixture t1_exitsublocstr.

    Returns None when no ``proc_ret`` closes the body; the applier reports that
    fail-loud.
    """
    ops, index = _window(ops, index)
    ret = next(
        (j for j, o in enumerate(ops[index:], index) if o[1] == "proc_ret"), None
    )
    if ret is None:
        return None
    epilogue, freed = epilogue_entry(ops, ret, index)
    return ProcBodyMatch(
        template="proc_body",
        start=index,
        stop=ret + 1,
        ret_address=ops[ret][0],
        exit_address=ops[epilogue][0],
        freed_strings=freed,
    )


def match_fn_result_readback(ops, index: int | None = None) -> TemplateMatch | None:
    """A ``mov ax,[bp+0]`` at ``index`` reading a just-called FN's result.

    ``mov_bp_sp`` has repointed BP at the staging frame by then, so the
    enclosing SUB's own LOCAL frame is NOT what bp+0 means here: keying on the
    preceding ``fn_call`` rather than on "no frame is open" is what lets an
    integer FN be called from inside a SUB body at all (probe t1_fnintcall;
    wild tbd73.exe, whose TBWINDOW SUBs call FNAttr(), integer-typed under its
    DEFINT a-z).

    The ``fn_call`` need not be the IMMEDIATELY preceding operation: when the
    result is about to be compared, the comparison's other operand was
    evaluated BEFORE the call and is shuttled into bx right after it (``IF
    FNCurvideo <> 7 THEN`` -- wild tbd73.exe, TBW73.INC:339 -- puts the 7 in
    ax, calls, then ``movbxax`` banks it before ``mov ax,[bp+0]`` reads the
    result). This skips that register-shuttle boilerplate.

    Recognition alone is not sufficient to fold: the caller must also see an
    integer FnCall result actually waiting on the stack, which is what makes
    the skip safe rather than a guess.
    """
    ops, index = _window(ops, index)
    if index >= len(ops) or ops[index][1] != "movax_bp" or ops[index][2] != 0:
        return None
    j = index - 1
    while j >= 0 and ops[j][1] in _REGISTER_SHUTTLE:
        j -= 1
    if j < 0 or ops[j][1] != "fn_call":
        return None
    return TemplateMatch(template="fn_result_readback", start=j, stop=index + 1)


def match_array_param_type(
    ops, index: int | None = None, *, block: int | None = None
) -> ArrayParamTypeMatch | None:
    """Element type of the array PARAMETER whose descriptor sits at bp+``block``.

    ``arg_push_arr`` (passing a computed element by reference) is a bare ES:SI
    pointer push -- byte-identical for every element type, so it witnesses
    nothing about the type. When it is the FIRST access to a descriptor there
    is no recorded type to fall back on, and defaulting to SINGLE collides with
    whatever the real type turns out to be. The evidence does exist, just later
    in the body, so this scans forward within the same procedure for another
    ``moves_bp`` on the SAME offset whose terminal is type-bearing.

    Returns None when no such access exists, leaving the caller's default
    intact rather than inventing a type. Bounded by ``proc_ret``: a different
    procedure's bp+``block`` is an unrelated frame slot.
    """
    ops, index = _window(ops, index)
    if block is None:
        raise TypeError("array parameter block offset is required")
    for j in range(index, len(ops)):
        if ops[j][1] == "proc_ret":
            return None
        if ops[j][1] != "moves_bp" or ops[j][2] != block or j + 1 >= len(ops):
            continue
        terminal = ops[j + 1][1]
        suffix = _ARR_PARAM_SUFFIX_BY_TERMINAL.get(terminal)
        if suffix is not None:
            return ArrayParamTypeMatch(
                template="array_param_type",
                start=j,
                stop=j + 2,
                block=block,
                suffix=suffix,
                terminal=terminal,
            )
    return None


def array_param_suffix(ops, index: int, block: int) -> str:
    """:func:`match_array_param_type`'s suffix, or ``""`` when unwitnessed.

    The empty string is the caller's existing unsuffixed spelling, not a
    guessed type.
    """
    matched = match_array_param_type(ops, index, block=block)
    return "" if matched is None else matched.suffix


def match_using_emit(ops, index: int | None = None) -> UsingEmitMatch | None:
    """Match a ``PRINT USING`` emit and its item vector.

    ``rt CB`` formats a numeric off the FP stack and ``rt CC`` a string off
    the sstack (t1_using); the operation that follows names the leg -- BE
    console, C0 file, BF printer (LPRINT USING, witnessed t1_lpusing and wild
    vhfprop.exe). The pair is the template: an emit without its item vector is
    a stray emit, which the applier reports fail-loud.
    """
    ops, index = _window(ops, index)
    if index >= len(ops) or ops[index][1] != "rt":
        return None
    vec = ops[index][2]
    if vec not in _USING_EMIT_VECS:
        return None
    if index + 1 >= len(ops) or ops[index + 1][1] != "rt":
        return None
    leg = _USING_ITEM_LEG.get(ops[index + 1][2])
    if leg is None:
        return None
    return UsingEmitMatch(
        template="using_emit",
        start=index,
        stop=index + 2,
        numeric=vec == 0xCB,
        leg=leg,
    )


#: How far ahead a TAB/SPC item may sit from the emit that claims it.
_USING_CHAIN_LOOKAHEAD = 18


def match_second_using_before_flush(ops, index: int | None = None):
    """Another `USING` begin before this statement's flush, if there is one.

    Turbo Basic accepts more than one USING in a single print statement
    (`LPRINT TAB(5); USING f1$; A#; TAB(37); USING f2$; B$`), and that form is
    not interchangeable with any split spelling -- only the one-statement
    source reproduces the bytes, the four candidate splits coming back 15-20
    bytes off (t1_usingtwice). Two `rt CA` before one flush vector is what says
    so. A SINGLE USING after items is byte-identical split off, so this fires
    only on the second.

    The match points at the second `rt CA`, which the caller needs: two USING
    begins are necessary but not sufficient, and the span between them is where
    the deciding evidence sits.
    """
    ops, index = _window(ops, index)
    for j in range(index + 1, min(index + _USING_CHAIN_LOOKAHEAD * 2, len(ops))):
        if ops[j][1] != "rt":
            continue
        if ops[j][2] == 0xCA:
            return TemplateMatch(template="second_using", start=j, stop=j + 1)
        if ops[j][2] in (0xB8, 0xB9, 0xBA):  # statement flush: chain is over
            return None
    return None


def match_using_chain_continues(
    ops, index: int | None = None
) -> TemplateMatch | None:
    """Whether an open USING chain emits again after ``index``.

    A TAB/SPC is an item inside a ``PRINT USING`` chain only when another
    USING emit follows it; a trailing TAB starts the next statement instead.
    The scan is bounded and stops at the first chain terminator, so a later
    unrelated chain cannot claim the item.

    The returned range points at the emit that claims it, which is the whole
    evidence for folding the item into the open chain.
    """
    ops, index = _window(ops, index)
    for j in range(index + 1, min(index + _USING_CHAIN_LOOKAHEAD, len(ops))):
        if ops[j][1] != "rt":
            continue
        if ops[j][2] in _USING_EMIT_VECS:
            return TemplateMatch(template="using_chain_item", start=j, stop=j + 1)
        if ops[j][2] in _USING_CHAIN_ENDS:
            return None
    return None


def match_delay(ops, index: int | None = None) -> DelayMatch | None:
    """Match ``delay_init [trap_hook]* delay_poll jcc loop_back``.

    ``None`` means the operation at ``index`` is not this template. A malformed
    template that starts with ``delay_init`` is returned as no match here; the
    applier turns that into the existing fail-loud `ValueError` so the public
    behavior remains unchanged.
    """
    ops, index = _window(ops, index)
    if index < 0 or index >= len(ops) or ops[index][1] != "delay_init":
        return None
    j = index + 1
    hooks = []
    while j < len(ops) and ops[j][1] == "trap_hook":
        hooks.append(ops[j])
        j += 1
    if j >= len(ops) or ops[j][1] != "delay_poll":
        return None
    poll = ops[j]
    j += 1
    if j >= len(ops):
        return None
    branch = ops[j]
    loop_back = hooks[0][0] if hooks else poll[0]
    if branch[1] != "jcc" or branch[3] != loop_back:
        return None
    return DelayMatch(
        template="delay",
        start=index,
        stop=j + 1,
        hooks=tuple(hooks),
        loop_back=loop_back,
    )


def match_definition_bracket(ops, index: int | None = None) -> TargetMatch | None:
    """A ``jmp`` at ``index`` that brackets the framed definition right after it.

    The compiler brackets every SUB/DEF FN with a jmp over its body, and the
    decoder normally recognizes that jmp by what PRECEDES it: the entry jmp at
    op 0, a jmp landed on by the previous bracket, or a jmp sitting where a
    definition just closed. None of those hold when a definition is interleaved
    into main code behind an ordinary subroutine, where the op before the
    bracket is a user ``RETURN`` -- and the decoder then lifts the bracket as a
    user ``GOTO`` and never opens the body's frame (wild cleanup.exe,
    reformat.exe: ``LOCAL zero-fill outside a fresh SUB/DEF FN body at 0xd0ca /
    0xd455``).

    So this recognizes the bracket by what it DOES instead, which needs no
    context at all: the next op begins a framed body -- ``proc_enter``, or the
    ``mov [bp+0],0`` result-slot zero-fill that opens a block DEF FN -- and the
    jmp's target is the op right after that body's own closer, modulo the
    ``trap_hook`` stamps event trapping puts there. A jmp that lands exactly
    past the closer of the body it opens is skipping that body and nothing
    else. Fixture t1_gosubthendef.

    The unframed forms (``inline_sub``, ``opaque_helper``) are deliberately not
    here: they have no closer to measure a bracket against.
    """
    index = 0 if index is None else index
    if index + 1 >= len(ops) or ops[index][1] != "jmp":
        return None
    head = ops[index + 1]
    if head[1] == "proc_enter":
        closer = "proc_ret"
    elif head[1] == "mov_bp_imm" and head[2] == 0 and head[3] == 0:
        closer = "fn_ret"
    else:
        return None
    target = ops[index][2]
    if target <= ops[index][0]:  # a bracket always jumps forward
        return None
    for j in range(index + 1, len(ops)):
        if ops[j][1] != closer:
            continue
        j += 1
        while j < len(ops) and ops[j][1] == "trap_hook" and ops[j][0] < target:
            j += 1
        if j < len(ops) and ops[j][0] == target:
            return TargetMatch(
                template="definition_bracket",
                start=index,
                stop=index + 1,
                target=target,
            )
        return None
    return None
