# Decoder architecture

Where to look, and who owns what. Written for the moment a wild EXE fails and
you have one line of error text to start from.

`tbx` decompiles Turbo Basic 1.0/1.1 DOS EXEs to source that recompiles
byte-for-byte. It is fail-loud by construction: an unrecognised byte pattern
raises `ValueError` rather than being guessed at. Everything below exists to
make the raise say where you are.

## The pipeline

    EXE bytes
      -> scan.py          the INT/ESC stream becomes an operation list
      -> layout.py        DGROUP, the line table, the constant pools
      -> core.py          the dispatch loop: operations become statements
         handlers/*       one family each: arith, control, dos_io, fileio, graphics
         lift.py          FOR/DO/WHILE/IF folding, jump-target resolution
         select_case.py   SELECT CASE, as a state machine over open frames
      -> rename.py        canonical variable names, string-literal recovery
      -> emit0.py         canonical Turbo Basic source

`decode0.decode_user_code(exe)` runs all of it. `tbx.ir` is the shared
immutable representation the middle three stages speak.

## Reading a failure

Every decode error carries a `DecodeDiagnostics` report (`cursor.py`):

    unhandled jmp short at 0xa4bb [phase=lift, offset=0xa4bb, op=2230,
      statement=0xa4a5, recent=[(42126, 'movax', 11), ...]]

| field | what it tells you |
| --- | --- |
| `phase` | which stage: `scan`, `layout`, `lift` |
| `offset` | the file offset the decoder was at |
| `op` | index into the operation list -- feed it to `dump_ops` |
| `statement` | the address of the statement being built |
| `component` | the owning state view, when the raise names one |
| `recent` | the last operations consumed, newest last |
| `expected` / `rejected` | for a template mismatch, what was looked for |

`recent` is usually the fastest read: it is the byte vocabulary immediately
before the failure, and a template mismatch is nearly always visible in it.

## State ownership

`DecodeState` holds 98 persistent fields. They are partitioned across six
views -- **total and disjoint**, enforced by `tests/tbx/test_state_parts.py`,
which fails if a field gains a second owner or none. A view is an alias, not a
copy, and writing an unowned name through one raises rather than shadowing it.

The partition is the answer to "who set this?": a field has exactly one owner,
and `tests/tbx/test_state_audit.py` additionally proves every one of them is
read somewhere, so nothing in the list is decoration.

**`state.image`** (ImageState, 5 fields)
: The decoded input: EXE bytes, prologue anchors, and the op stream.

    `dia`, `exe`, `main_start`, `ops`, `start`

**`state.machine`** (MachineState, 10 fields)
: The emulated register file and latched x87/segment machine elements.

    `ax`, `bx`, `cint_round`, `cx`, `di`, `dx`, `fp64_bridge`, `pend_es`, `reg_spills`, `si`

**`state.expr`** (ExprState, 26 fields)
: Expression stacks, staged operand cells, and pending expression folds.

    `bchk_bp`, `bchk_subs`, `color_cells`, `direct_bool_gate`, `direct_bool_logical`, `pend_bool`, `pend_bool_outer`, `pend_cmp`, `pend_cmp_str`, `pend_dataread`, `pend_field`, `pend_filein`, `pend_fnum`, `pend_getstr`, `pend_icmp`, `pend_input`, `pend_line_input`, `pend_mode_lit`, `pend_print`, `pend_shortstr`, `pend_swap`, `pend_swap_rev`, `pend_using`, `reg_logical_results`, `sstack`, `stack`

**`state.layout_state`** (LayoutState, 16 fields)
: DGROUP layout, slot registries, array facts, and data/string pools.

    `arrs`, `data_items`, `desc_disps`, `dim_frame`, `discard_strs`, `ds`, `dsd`, `have_fre`, `lay`, `local_dim_frame`, `n_local_arrs`, `option_base`, `prev_dim_end`, `r_arrs`, `slot_info`, `ss_base`

**`state.control`** (ControlState, 30 fields)
: Statement cursor and open structured-control/procedure frames.

    `block_if_addrs`, `cases`, `cur`, `dos`, `exit_folds`, `fn_args`, `fn_args_stack`, `fn_frame`, `fold_plan`, `fors`, `fwd_inline_offs`, `has_procs`, `ifs`, `inline_procs`, `k`, `nfn`, `nsub`, `pend_arg`, `pend_args`, `pending_ifs`, `proc_dbl_offs`, `proc_frame`, `proc_int_offs`, `proc_long_offs`, `proc_names`, `proc_params`, `proc_str_offs`, `sp_save_cell`, `sp_save_stack`, `whiles`

**`state.output`** (OutputState, 11 fields)
: Emitted statements, physical addresses, and output metadata.

    `addrs`, `cc_hooks`, `commits`, `event_log`, `hook_seq`, `metas`, `seg_metas`, `stmt_addr`, `stmts`, `toggles`, `trace_tbl`

Ownership was assigned from observed reads and writes, not from names --
`state_parts.py` records the three calls where the name misleads.

## Frames: what the walk is in the middle of

`DecodeState` holds the fields above for the whole decode. Alongside them the
dispatch loop keeps a *frame* for every construct it has recognised but not
yet closed, and those are in `tbx/decode0/frames.py` -- one dataclass each,
which is the complete inventory of transient decoder state.

| frame | fields | what it is |
| --- | --- | --- |
| `BodyFrame` | 10 | What an open SUB and an open DEF FN body have in common |
| `BoolTerm` | 4 | One open term of a compound condition, waiting for its second half |
| `DimFrame` | 3 | An array declaration being assembled from its descriptor writes |
| `FieldChain` | 3 | An open `FIELD #n`, collecting its `width AS var$` entries |
| `FnFrame` | 17 | An open DEF FN body |
| `ForFrame` | 8 | One open FOR, from its header until `_lift_next` consumes its NEXT |
| `IfFrame` | 2 | One inline IF, recognised and waiting for decoding to reach its target |
| `InputChain` | 5 | An open `INPUT`, collecting its targets |
| `LineInputChain` | 4 | An open `LINE INPUT` or `LINE INPUT #n`, waiting for its target |
| `LoopFrame` | 2 | One open head-tested loop -- `DO ... LOOP`, or a legacy `WHILE ... WEND` |
| `PendingFold` | 4 | An inline-IF region whose extent is known, queued until it can fold |
| `PrintChain` | 5 | An open PRINT / LPRINT / PRINT# / WRITE#, collecting its items |
| `ProcFrame` | 12 | An open SUB body |
| `ReadChain` | 3 | An open `READ` or `INPUT #n`, waiting for the stores that name targets |
| `SelectFrame` | 13 | One open SELECT CASE, from its header until END SELECT |
| `UsingChain` | 5 | An open `PRINT USING` / `LPRINT USING`, collecting its values |

They were dicts until recently, and the reason they are not is worth knowing
when reading old commits: a dict cannot say what is in it. `c.fors` held five
different key sets across six recognition sites; a SELECT frame gained
`body_seq` partway through its life and no construction site mentioned it;
`frame_words` was read with two different defaults, so what "not set" meant
depended on the caller; and one key's *existence* was conditional
(`**({"mode": "lprint"} if want_lprint else {})`). All of that read as
ordinary code and none of it was visible from the definition.

`tests/tbx/test_frames.py` keeps them that way: no frame may be a dict
literal, no frame field may be reached by subscript, and every field carries a
comment where the compiler convention behind it can be written down.

## The record

Two logs run alongside the statement list, and between them they answer
"what did the decoder actually do?" without re-running it.

**The event stream** (`events.py`, `Program.events`). An event per decoder
decision: `statement` for a commit, `branch` for a recognised skip or loop
edge, `region` for a construct's extent, `arrive` for reaching an address some
branch is waiting on, `patch` for revising a commit, `reconstruct` for a
statement derived at finalization from pool or layout facts. Every statement in
a finished program traces to one.

**The statement edit log** (`statement_log.py`, `Program.statement_edits`).
Every append, insert, replace, delete and splice, each naming the pass that
made it (`origin`), the enclosing passes (`scope`) and the event it followed
(`at_event`). `replay(edits) == list(stmts)` is checked at decode time.

The shared `at_event` clock is what lets the two be read together: it is how a
fold region recorded as "the list length when this branch was recognised"
becomes a position. `control_graph.py` reads both; `fold_pass.py` rebuilds
constructs from them alone.

## Tools

| command | use |
| --- | --- |
| `tbx PROGRAM.EXE` | decompile to stdout |
| `tbx PROGRAM.EXE --ops` | the operation stream |
| `python -m tbx.tools.dump_ops` | operations with file offsets |
| `python -m tbx.tools.dump_events` | events, edits and branch classification |
| `python -m tbx.tools.scan_wild DIR` | decode a corpus, report every failure |
| `python -m tbx.tools.verify_fixture STEM` | oracle round-trip, one fixture |
| `python -m tbx.tools.verify_wild` | oracle round-trip, the comparable wild subset |

`pip install '.[debug]'` adds the iced-x86 CFG tools (`tbx.tools.cfg`).

## Gates

- `uv run pytest` and `uv run ruff check`.
- `git status tests/fixtures/` **must be empty**. `ops`, `ir_snapshot.txt` and
  `usercode` are contracts; a structural change that moves one has changed
  behaviour.
- `python -m tbx.tools.scan_wild wild/hits`, diffed against the previous run.
  Not the tally -- the full report. A refactor can move which programs fail
  while keeping the count.

**The fixture corpus does not cover everything, and knowing what it misses is
part of using it.** It is 1030 small programs, and it is blind to anything that
only appears at scale: shift arithmetic across many folds, line-table recovery,
pooled-list reconstruction. Every bug of that kind found so far was byte-clean
across all 1030 goldens and visible only in `wild/hits`. When a change touches
positions or reconstruction, the wild report is the gate that matters.

A new byte mapping needs a compiled fixture in `tests/fixtures/corpus/` and
oracle verification. See `docs/release-checklist.md` and
`vendor/turbo_basic_oracle/README.tbx.md`.
