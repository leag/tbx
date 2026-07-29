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
