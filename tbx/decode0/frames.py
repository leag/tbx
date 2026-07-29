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

from dataclasses import dataclass


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
