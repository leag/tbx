"""Ownership views for the incremental decoder-state migration.

The first migration stage keeps the legacy storage in ``DecodeState`` so old
handlers remain source-compatible. These views are the single named access
surface for migrated code; their values are aliases, not copies, so a mixed
legacy/new dispatch loop cannot observe stale state.

Ownership is a *total, disjoint partition* of the persistent decode-loop
fields -- ``tests/tbx/test_state_parts.py`` fails if a field is claimed twice
or by nobody. A partition is what makes the ownership claim testable; a field
in two views would let a handler read a value whose producer it cannot name.

Ownership was assigned from observed reads and writes, not from field names.
The three calls worth recording, because the names suggest otherwise:

``ax``/``bx``/``cx``/``dx``/``di``/``si``
    They hold IR nodes, not machine words, so they read like expression state.
    They stay in :class:`MachineState` because their *lifetime* is the emulated
    register's: a runtime-call template leaves a value in AX and the next
    handler consumes it from AX. :class:`ExprState` owns operands whose
    lifetime is the expression being folded.

``ds``/``ss_base``
    Segment-shaped names, but both are resolved once from ``lay`` during setup
    and never written by the dispatch loop. They are DGROUP facts, so
    :class:`LayoutState` owns them.

``pend_es``/``cint_round``/``fp64_bridge``
    The ``pend_``/``fp`` prefixes suggest expression state, but each is a
    latched machine element -- the ES array-descriptor selector, the x87
    rounding-mode round trip, and the x87 f64 store/reload bridge -- so
    :class:`MachineState` owns them.
"""

from __future__ import annotations

from typing import Any, ClassVar


class StateView:
    """A small typed-by-contract view over one ``DecodeState`` owner."""

    fields: ClassVar[frozenset[str]] = frozenset()

    def __init__(self, owner: Any) -> None:
        object.__setattr__(self, "_owner", owner)

    def __getattr__(self, name: str) -> Any:
        if name in self.fields:
            return getattr(self._owner, name)
        raise AttributeError(
            f"{type(self).__name__} does not own {name!r}"
        )

    def __setattr__(self, name: str, value: Any) -> None:
        # Fail loud rather than shadowing the shared state with a view-local
        # attribute: a silently absorbed write is a decode that reads a stale
        # value many operations later, which is the exact failure class this
        # migration exists to remove.
        if name not in self.fields:
            raise AttributeError(
                f"{type(self).__name__} does not own {name!r}"
            )
        setattr(self._owner, name, value)


class ImageState(StateView):
    """The decoded input: EXE bytes, prologue anchors, and the op stream.

    Written once during setup and read-only for the rest of the decode. It is
    not one of the plan's five mutable owners; it exists so the partition can
    be total without pretending the input image is mutable decoder state.
    """

    fields = frozenset({"exe", "start", "dia", "main_start", "ops"})


class MachineState(StateView):
    """The emulated register file and latched x87/segment machine elements."""

    fields = frozenset(
        {
            "ax",
            "bx",
            "cx",
            "dx",
            "di",
            "si",
            "pend_es",
            "cint_round",
            "fp64_bridge",
            "reg_spills",
        }
    )


class ExprState(StateView):
    """Expression stacks, staged operand cells, and pending expression folds."""

    fields = frozenset(
        {
            "bchk_bp",
            "bchk_subs",
            "color_cells",
            "direct_bool_gate",
            "direct_bool_group",
            "direct_bool_logical",
            "stack",
            "sstack",
            "pend_cmp",
            "pend_cmp_str",
            "pend_icmp",
            "pend_bool",
            "pend_bool_outer",
            "pend_dataread",
            "pend_field",
            "pend_filein",
            "pend_fnum",
            "pend_getstr",
            "pend_input",
            "pend_line_input",
            "pend_mode_lit",
            "pend_print",
            "pend_shortstr",
            "pend_swap",
            "pend_swap_rev",
            "pend_using",
            "reg_logical_results",
        }
    )


class LayoutState(StateView):
    """DGROUP layout, slot registries, array facts, and data/string pools."""

    fields = frozenset(
        {
            "lay",
            "ds",
            "dsd",
            "ss_base",
            "arrs",
            "r_arrs",
            "slot_info",
            "option_base",
            "dim_frame",
            "local_dim_frame",
            "prev_dim_end",
            "n_local_arrs",
            "data_items",
            "desc_disps",
            "discard_strs",
            "have_fre",
        }
    )


class ControlState(StateView):
    """Statement cursor and open structured-control/procedure frames."""

    fields = frozenset(
        {
            "cur",
            "k",
            "ifs",
            "pending_ifs",
            "fold_plan",
            "fors",
            "whiles",
            "dos",
            "cases",
            "exit_folds",
            "block_if_addrs",
            "has_procs",
            "proc_frame",
            "fn_frame",
            "fn_args",
            "fn_args_stack",
            "fwd_inline_offs",
            "inline_procs",
            "nfn",
            "nsub",
            "pend_arg",
            "pend_args",
            "proc_dbl_offs",
            "sp_save_cell",
            "sp_save_stack",
            "proc_int_offs",
            "proc_long_offs",
            "proc_names",
            "proc_params",
            "proc_str_offs",
        }
    )


class OutputState(StateView):
    """Emitted statements, physical addresses, and output metadata."""

    fields = frozenset(
        {
            "stmts",
            "addrs",
            "stmt_addr",
            "metas",
            "seg_metas",
            "toggles",
            "trace_tbl",
            "hook_seq",
            "cc_hooks",
            "commits",
            "event_log",
        }
    )


#: Attribute name on ``DecodeState`` -> the view class that owns its fields.
#: The dispatch loop instantiates exactly these; the partition test walks the
#: same registry so a new view cannot be added without an ownership claim.
STATE_VIEWS: dict[str, type[StateView]] = {
    "image": ImageState,
    "machine": MachineState,
    "expr": ExprState,
    "layout_state": LayoutState,
    "control": ControlState,
    "output": OutputState,
}

#: Fields that hold the migration scaffolding itself rather than decode state.
#: They are excluded from the partition because they are not decoded facts.
INFRASTRUCTURE_FIELDS: frozenset[str] = frozenset(
    {"cursor", "diagnostics", *STATE_VIEWS}
)
