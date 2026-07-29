"""Typed records for the frames the dispatch loop keeps open.

An open construct -- a FOR, a loop, an inline IF, a procedure body -- is
bookkeeping the walk carries until something closes it. These were plain dicts
built at the recognition site and read somewhere else entirely, which made two
things hard that should not be.

*What is in one.* `c.fors` held five different key sets across six recognition
sites, so a reader could not know what was present without finding all six.
The absences were then papered over at the read sites: `f.get("lim", v - 4)`,
`f.get("stp", v - 8)`, `f.get("step", 1)`. Three defaults, none of them stated
where the frame is defined, each repeated wherever someone remembered.

*Who may change one.* A dict says nothing about that, and `addm_i8` does patch
a FOR's step after the fact.

A dataclass answers both. The fields are the frame, the defaults live once at
the definition, and the docstring is where the compiler's layout convention is
written down rather than inferred from an arithmetic default at a call site.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ForFrame:
    """One open FOR, from its header until `_lift_next` consumes its NEXT.

    Six templates produce one of these -- a literal step, a computed step, the
    "loose" form, and their 8087 variants -- and they differ only in which of
    the optional fields they can fill in at recognition time.
    """

    #: DGROUP or bp displacement of the loop variable. The compiler lays the
    #: loop's three cells out contiguously and descending, so the limit and
    #: step cells follow from it (see `lim`/`stp`).
    v: int
    #: Address of the NEXT test template that closes this loop.
    test: int
    #: Address the loop body starts at: the operation after the header, or
    #: None when the header is the last operation in the image.
    body: int | None = None
    #: Position of the emitted `ir.For` in the statement list, for the
    #: templates that patch their header once NEXT-side evidence arrives (a
    #: real limit, or a negative step). None for the templates that never do.
    idx: int | None = None
    #: Displacement of the limit cell. Defaults to `v - 4`, the compiler's
    #: layout, which is why most recognition sites do not pass it.
    lim: int | None = None
    #: Displacement of the step cell. Defaults to `v - 8`, likewise.
    stp: int | None = None
    #: Sign of a literal step, patched to -1 by `addm_i8` when the increment
    #: turns out to be a subtraction. Chooses the NEXT template's comparison.
    step: int = 1
    #: A computed (variable) STEP: the sign is not known until run time, so
    #: the compiler emits both comparisons and picks between them.
    var_step: bool = False

    def __post_init__(self) -> None:
        if self.lim is None:
            self.lim = self.v - 4
        if self.stp is None:
            self.stp = self.v - 8


@dataclass
class SelectFrame:
    """One open SELECT CASE, from its header until END SELECT.

    The recognizer is a state machine and this is its state. Reading the
    fields in the order the machine moves through them is the fastest way to
    understand it:

    *At the header* the selector expression and the compiler's scratch cell
    holding it are known, and nothing else is. `end_select` is 0 because where
    the construct ends genuinely is not known yet -- it is learned from the
    first arm's trailing jmp.

    *While matching an arm's guards*, each recognised `CASE` value, range or
    `IS` comparison is appended to `cur_guards`. A range arrives as two
    compares, so `pending_range_lo` holds the low bound between them.

    *When the body starts*, `_begin_body` fills in where it begins and the jmp
    that closes it, and records the region -- `body_seq` -- so the snapshot can
    read its own extent back out of the log rather than off this frame.

    *When the arm closes*, its statements are folded into a `CaseArm`, appended
    to `arms`, and `cur_guards`/`body_jmp` are cleared for the next one.

    *At END SELECT* the arms become one `ir.SelectCase` standing at `start`.

    So most fields are empty for most of the frame's life. As a dict that was
    invisible: `body_seq` did not exist at all until `_begin_body` created it,
    and nothing said which of the twelve keys were meaningful when.
    """

    #: The expression being switched on, popped from the numeric or string
    #: stack at the header.
    selector: object
    #: Displacement of the compiler's scratch cell holding the selector, which
    #: every arm header compares against.
    temp: int
    #: Whether this is the string form. The two differ in which stack the
    #: selector came from and which arm-header templates match.
    is_string: bool
    #: Address of the SELECT header, which the finished statement stands at.
    start: int | None = None
    #: Address of END SELECT. 0 until an arm's trailing jmp reveals it -- the
    #: header itself carries no forward reference to it.
    end_select: int = 0
    #: Arms closed so far.
    arms: list = field(default_factory=list)
    #: Guards matched for the arm currently being recognised, cleared as each
    #: arm closes.
    cur_guards: list = field(default_factory=list)
    #: Low bound of a `CASE lo TO hi`, held between its two compares.
    pending_range_lo: object = None
    #: Where the current arm's body begins in the statement list.
    body_idx: int = 0
    #: `seq` of the `case_arm` or `case_else` region event for the current
    #: body. Absent until the body starts, which is the first moment the
    #: extent is knowable.
    body_seq: int | None = None
    #: Address of the jmp that closes the current arm; None between arms, and
    #: therefore also the flag for "a body is open".
    body_jmp: int | None = None
    #: Address of the next arm's header test.
    next_test: int = 0
    #: Whether the body currently open is the CASE ELSE.
    in_else: bool = False


@dataclass
class BodyFrame:
    """What an open SUB and an open DEF FN body have in common.

    `local_init` handles the two interchangeably -- a LOCAL declaration reads
    and fills the same fields whichever body it is in -- so the shared part is
    a base rather than a coincidence of two dicts having similar keys.

    Everything below `exit` is filled in as the body is decoded, not at
    `proc_enter`. As dicts these keys did not exist until something created
    them, and their absence was then read as a value: `.get("has_local_for")`
    meaning False, `.get("hidden_locals") or ()` meaning empty. Worse,
    `frame_words` was read with *two different defaults* in two places -- 0 in
    one, `len(locs)` in the other -- so what "not set" meant depended on who
    was asking. Here it is None, and each caller says what it wants.
    """

    #: Address of the body's entry (`proc_enter`, or the DEF FN header).
    entry: int
    #: `seq` of the `proc`/`fn` region event, recorded before any statement of
    #: the body is committed, so the fold at the return reads its start
    #: position out of the log rather than off this frame.
    seq: int
    #: Statement-list position the body begins at.
    idx: int
    #: Address of the return.
    exit: int
    #: The body's LOCAL declaration: bp offset -> name. None until a
    #: `local_init` is seen, and None means "no LOCAL statement", not "empty".
    locals: dict | None = None
    #: `(disp, count)` of the LOCAL zero-fill, which is how the frame tail --
    #: where a LOCAL FOR's temp words live -- is found.
    local_span: tuple | None = None
    #: bp offsets that are compiler temporaries rather than declared LOCALs.
    hidden_locals: set = field(default_factory=set)
    #: bp offsets read or written as ordinary variables, which is the evidence
    #: that a hidden offset is *not* a temp after all.
    touched: set = field(default_factory=set)
    #: Whether a FOR inside this body uses LOCAL loop cells.
    has_local_for: bool = False
    #: Entry of the LOCAL-string teardown, when the body has one. An EXIT
    #: jumps here rather than to `exit`; see `teardown_entry`.
    exit_entry: int | None = None

    @property
    def teardown_entry(self) -> int:
        """Where an EXIT SUB / EXIT DEF lands.

        The LOCAL-string teardown when the body has one, the plain return
        otherwise. Two call sites spelled this `.get("exit_entry", f["exit"])`;
        it is one question and belongs in one place.
        """
        return self.exit if self.exit_entry is None else self.exit_entry


@dataclass
class ProcFrame(BodyFrame):
    """An open SUB body."""

    #: Array parameters, by descriptor block: shape facts recovered from how
    #: the body indexes them.
    array_params: dict = field(default_factory=dict)
    #: Words the LOCAL zero-fill reserved, which the `retf` pop arithmetic
    #: needs. None means no LOCAL statement was seen -- callers differ on what
    #: to assume then, so none of them may assume it here.
    frame_words: int | None = None


@dataclass
class FnFrame(BodyFrame):
    """An open DEF FN body."""

    #: A multi-statement DEF FN (`DEF FN... : ... : END DEF`) rather than the
    #: single-expression form.
    block: bool = False
    #: A string-valued FN, whose result is stored via INT A2.
    str_result: bool = False
    #: An INTEGER-valued FN, whose result goes through the ax path. An
    #: unsuffixed FN name is SINGLE to Turbo Basic, so the `%` has to be
    #: recovered or the recompile widens the result and every reference to it
    #: (probe t1_fnintcall: 32 bytes larger without it).
    int_result: bool = False
    #: bp offsets of string parameters (INT 9E).
    str_offs: set = field(default_factory=set)
    #: bp offsets of INTEGER parameters, read through the ax path. The source
    #: needs the explicit `%` suffix to recompile byte-exact, mirroring SUB's
    #: `proc_int_offs`.
    int_offs: set = field(default_factory=set)
    #: The result expression, once the body stores one.
    result: object = None
    #: bp offsets touched as a parameter read, fold or result. The actual set
    #: *is* the parameter list: not every parameter uses the same byte stride,
    #: so the offsets are what identifies them.
    param_offs: set = field(default_factory=set)
