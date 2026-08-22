import json
from pathlib import Path

from tbx import decode0, ir as tbx_ir
from tbd import cli, decode
from tbd.canonical import canonicalize, normalize_expression
from tbd.facts import Evidence, analyze as analyze_facts
from tbd.for_facts import integer_for_facts
from tbd.for_variable_facts import integer_variable_step_for_facts
from tbd.ir import Fact, Operation, Slot, Statement
from tbd.pool import infer_layout, resolve as resolve_pool
from tbd.x86 import decode_instruction

_CORPUS = Path(__file__).parents[1] / "fixtures" / "corpus"
_TBX_STRING_STATEMENT_FIELDS = {
    tbx_ir.Chdir: "path",
    tbx_ir.Draw: "cmd",
    tbx_ir.Environ: "s",
    tbx_ir.Kill: "file",
    tbx_ir.Mkdir: "path",
    tbx_ir.Play: "music",
    tbx_ir.Rmdir: "path",
    tbx_ir.Shell: "cmd",
}


def test_known_program_has_standalone_lifted_ir_and_cfg():
    program = decode((_CORPUS / "t1_delay.exe").read_bytes())

    names = [operation.operands[0] for operation in program.operations
             if operation.kind == "tb.statement"]
    assert program.dialect == "1.1"
    assert {"DELAY_INIT", "DELAY_POLL", "END"} <= set(names)
    assert program.instructions
    assert len(program.blocks) == 3
    assert any(xref.kind == "branch" for xref in program.xrefs)
    assert any(report.name == "control-flow" for report in program.passes)


def test_unknown_input_becomes_ir_instead_of_an_exception():
    program = decode(b"\xcc\xcd\xec\xfe\x60")

    assert program.format == "raw"
    assert program.instructions[0].kind == "x86.int3"
    assert program.instructions[1].kind == "tb.statement"
    assert program.instructions[1].operands == ("WRITE_FILE_SEPARATOR", 0xFE)
    assert program.instructions[2].kind == "opaque.byte"
    assert [operation.kind for operation in program.operations] == [
        "unknown.region", "tb.statement", "unknown.region"
    ]


def test_recursive_discovery_skips_unreachable_bytes():
    program = decode(bytes.fromhex("eb 02 cc cc cd ec e8"))

    assert [item.offset for item in program.instructions] == [0, 4]
    assert len(program.blocks) == 2
    assert program.xrefs[0].target == 4


def test_wrapped_near_branches_discover_compiled_orphan_source_regions():
    expected = {
        "": (0x12B31, 0x12B25, 0x8709),
        "v10_": (0x114E1, 0x114D5, 0x70B9),
    }
    for prefix, (call_target, jump_target, orphan) in expected.items():
        program = decode((_CORPUS / f"{prefix}t1_bigjmp.exe").read_bytes())

        assert program.instructions[1].operands == (call_target,)
        assert program.instructions[2].operands == (jump_target,)
        assert any(
            xref.kind == "orphan" and xref.target == orphan
            for xref in program.xrefs
        )
        assert len(program.canonical_statements) == 2807
        assert sum(
            statement.kind == "Assign"
            for statement in program.canonical_statements
        ) == 2800


def test_fact_engine_preserves_instruction_signature_and_xref_evidence():
    program = decode((_CORPUS / "t1_delay.exe").read_bytes())

    assert len([fact for fact in program.facts if fact.kind == "instruction"]) == len(
        program.instructions
    )
    assert any(
        fact.kind == "signature"
        and fact.subject == (program.code_start,)
        and fact.evidence == (program.code_start,)
        for fact in program.facts
    )
    assert any(
        fact.kind == "xref"
        and fact.value[0] == "branch"
        and fact.evidence == fact.subject
        for fact in program.facts
    )
    assert program.fact_passes[-1].additions == 0
    first_round = [
        report.facts for report in program.fact_passes if report.round == 1
    ]
    assert first_round == sorted(first_round)
    final_round = max(report.round for report in program.fact_passes)
    assert all(
        report.facts == len(program.facts) and report.additions == 0
        for report in program.fact_passes
        if report.round == final_round
    )


def test_fact_engine_is_monotonic_and_pass_order_independent():
    seed = Fact("seed", (0,), (), (0,), "structural")
    derived = Fact("derived", (0,), (), (0,), "anchored")
    evidence = Evidence(b"", (), (), ())

    def add_seed(_evidence, _facts):
        return (seed,)

    def add_derived(_evidence, facts):
        return (derived,) if seed in facts else ()

    forward = analyze_facts(
        evidence,
        rounds=4,
        passes=(("derived", add_derived), ("seed", add_seed)),
    )
    reverse = analyze_facts(
        evidence,
        rounds=4,
        passes=(("seed", add_seed), ("derived", add_derived)),
    )

    assert forward[0] == reverse[0] == (derived, seed)
    assert forward[2] and reverse[2]


def test_repeated_passes_reveal_arguments_until_stable():
    binary = bytes.fromhex("b8 01 00 bb 02 00 cd ec 22 00 ea 00 00 00 00")
    program = decode(binary)

    statement = program.operations[0]
    assert statement.kind == "tb.statement"
    assert statement.operands == (
        "COLOR", 0x22, 0, ("register", "bx", 2), ("register", "ax", 1)
    )
    changed_rounds = {
        report.round
        for report in program.passes
        if report.name == "register-arguments" and report.changes
    }
    assert changed_rounds == {1, 2}


def test_symbolic_pass_evaluates_fp_stack_and_direct_memory_effects():
    delay = decode((_CORPUS / "t1_delay.exe").read_bytes())
    arithmetic = decode((_CORPUS / "t1_addimm.exe").read_bytes())

    assert any(
        operation.kind == "expr.value" and operation.operands == (("const", 1),)
        for operation in delay.operations
    )
    assert any(
        report.name == "symbols" and report.changes >= 2
        for report in arithmetic.passes
    )


def test_symbolic_facts_recover_values_stores_updates_and_provenance():
    delay = decode((_CORPUS / "t1_delay.exe").read_bytes())
    arithmetic = decode((_CORPUS / "t1_addimm.exe").read_bytes())
    conditional = decode((_CORPUS / "t1_if.exe").read_bytes())

    assert _fact_values(delay, "expression.value") == [("const", 1)]
    assert _fact_effects(arithmetic, "machine.store") == {
        0x120: (("const", 5),)
    }
    assert _fact_effects(arithmetic, "machine.update") == {
        0x120: ("+", ("const", 3))
    }
    update = next(fact for fact in arithmetic.facts if fact.kind == "machine.update")
    assert update.evidence == (0x8709, 0x870C)
    stores = [fact for fact in conditional.facts if fact.kind == "machine.store"]
    assert any(
        fact.subject == (0x128,)
        and fact.value == (("const", 1),)
        and fact.evidence == (0x8703, 0x8706)
        for fact in stores
    )
    assert any(
        fact.subject == (0x124,)
        and fact.value == (("memory", 0x136, "integer"),)
        and fact.evidence == (0x870D, 0x8712)
        for fact in stores
    )
    assert len([fact for fact in conditional.facts if fact.kind == "expression.compare"]) == 2


def test_string_store_facts_require_a_complete_direct_stack_pair():
    complete = decode(bytes.fromhex("be 40 01 cd 9c be 20 01 cd a0"))
    incomplete = decode(bytes.fromhex("be 40 01 cd 9c be 20 01"))

    stores = [fact for fact in complete.facts if fact.kind == "machine.store"]
    assert [fact.subject for fact in stores] == [(0x120,)]
    assert stores[0].value == (("memory", 0x140, "string"),)
    assert stores[0].evidence == (0, 3, 5, 8)
    assert stores[0].confidence == "signature"
    assert not any(fact.kind == "machine.store" for fact in incomplete.facts)


def test_string_store_facts_require_both_concat_operands():
    complete = decode(
        bytes.fromhex("be 40 01 cd 9c be 44 01 cd 9c cd 9b be 20 01 cd a0")
    )
    incomplete = decode(
        bytes.fromhex("be 40 01 cd 9c cd 9b be 20 01 cd a0")
    )

    store = next(fact for fact in complete.facts if fact.kind == "machine.store")
    assert store.value == (
        (
            "binary",
            "+",
            ("memory", 0x140, "string"),
            ("memory", 0x144, "string"),
        ),
    )
    assert store.evidence == (0, 3, 5, 8, 10, 12, 15)
    assert not any(fact.kind == "machine.store" for fact in incomplete.facts)


def _fact_values(program, kind):
    return [fact.value[0] for fact in program.facts if fact.kind == kind]


def _fact_effects(program, kind):
    return {
        fact.subject[0]: fact.value for fact in program.facts if fact.kind == kind
    }


def test_dgroup_pass_names_slots_without_touching_runtime_cells():
    program = decode((_CORPUS / "t1_if.exe").read_bytes())

    assert [slot.name for slot in program.slots[:3]] == ["V0001", "V0002", "V0003"]
    assert [slot.offset for slot in program.slots[:3]] == [0x120, 0x124, 0x128]
    assert all(slot.offset < 0x134 for slot in program.slots)
    assert any(report.name == "dgroup-slots" and report.changes for report in program.passes)


def test_slot_facts_match_legacy_identities_and_retain_types():
    arithmetic = decode((_CORPUS / "t1_addimm.exe").read_bytes())
    conditional = decode((_CORPUS / "t1_if.exe").read_bytes())

    arithmetic_slots = [fact for fact in arithmetic.facts if fact.kind == "slot"]
    conditional_slots = [fact for fact in conditional.facts if fact.kind == "slot"]
    assert [(fact.subject[0], fact.value[0]) for fact in arithmetic_slots] == [
        (slot.offset, slot.name) for slot in arithmetic.slots
    ]
    assert [(fact.subject[0], fact.value[0]) for fact in conditional_slots] == [
        (slot.offset, slot.name) for slot in conditional.slots
    ]
    assert arithmetic_slots[0].value[1] == ("integer",)
    assert {fact.subject[0]: fact.value[1] for fact in conditional_slots} == {
        0x120: ("float",),
        0x124: ("float",),
        0x128: ("float",),
    }
    assert all(fact.subject[0] < 0x134 for fact in conditional_slots)


def test_constant_pool_pass_resolves_numeric_and_string_literals():
    printed = decode((_CORPUS / "t1_print.exe").read_bytes())
    conditional = decode((_CORPUS / "t1_if.exe").read_bytes())

    assert printed.statements[0].operands[1] == ("const", 5)
    assert printed.statements[1].operands[1] == (("string", "HELLO"),)
    assert conditional.statements[1].operands[1] == ("const", 2)
    assert conditional.statements[3].operands[1] == ("const", 5)
    assert any(
        report.name == "constant-pool" and report.changes
        for report in printed.passes
    )


def test_constant_pool_facts_match_legacy_literal_view():
    printed = decode((_CORPUS / "t1_print.exe").read_bytes())
    conditional = decode((_CORPUS / "t1_if.exe").read_bytes())

    layouts = [fact for fact in printed.facts if fact.kind == "layout.pool"]
    assert len(layouts) == 1
    assert layouts[0].value[1] == 0x134
    printed_constants = {
        fact.subject: fact.value
        for fact in printed.facts
        if fact.kind == "constant"
    }
    conditional_constants = {
        fact.subject: fact.value
        for fact in conditional.facts
        if fact.kind == "constant"
    }
    assert printed_constants == {
        ("memory", 0x13A): ("const", 5),
        ("string", 0x134): ("string", "HELLO"),
    }
    assert conditional_constants == {
        ("memory", 0x134): ("const", 5),
        ("memory", 0x136): ("const", 2),
    }


def test_pool_base_minus_four_is_the_canonical_empty_string_descriptor():
    image = (_CORPUS / "t1_poolrun.exe").read_bytes()
    program = decode(image)
    layout = next(fact for fact in program.facts if fact.kind == "layout.pool")
    empty_address = layout.value[1] - 4

    assert any(
        fact.kind == "constant"
        and fact.subject == ("string", empty_address)
        and fact.value == ("string", "")
        for fact in program.facts
    )
    assert not any(
        fact.kind == "slot" and fact.subject == (empty_address,)
        for fact in program.facts
    )
    assert [
        (node.kind, node.operands) for node in program.canonical_statements
    ] == [
        _tbx_statement(node) for node in decode0.decode_user_code(image)
    ]


def test_wide_fp_facts_recover_double_literals_and_direct_stores():
    for prefix in ("", "v10_"):
        image = (_CORPUS / f"{prefix}t1_convf.exe").read_bytes()
        program = decode(image)
        exact = [_tbx_statement(node) for node in decode0.decode_user_code(image)]
        migrated = [
            (node.kind, node.operands) for node in program.canonical_statements
        ]

        constants = {
            fact.subject: fact.value
            for fact in program.facts
            if fact.kind == "constant"
        }
        layout = next(fact for fact in program.facts if fact.kind == "layout.pool")
        slots = {
            fact.subject[0]: fact.value[1]
            for fact in program.facts
            if fact.kind == "slot"
        }
        assert layout.value[2] == image.rfind(bytes.fromhex("00 80 16 00"))
        assert constants == {
            ("memory", 0x134): ("const", 2.7),
            ("memory", 0x13C): ("const", 2.5),
            ("memory", 0x144): ("const", 1.5),
        }
        assert slots[0x128] == ("double",)
        assert migrated[:2] == exact[:2]
        assert migrated[-1] == exact[-1] == ("End", ())


def test_wide_fp_direct_array_reads_keep_array_identity():
    image = (_CORPUS / "t1_dblarr.exe").read_bytes()
    program = decode(image)
    exact = [_tbx_statement(node) for node in decode0.decode_user_code(image)]
    migrated = [
        (node.kind, node.operands) for node in program.canonical_statements
    ]

    assert exact[3] in migrated
    assert exact[6] in migrated
    assert any(
        fact.kind == "memory.read"
        and fact.subject == (0x190,)
        and fact.value == ("double",)
        for fact in program.facts
    )
    assert not any(
        fact.kind == "constant" and fact.subject == ("memory", 0x190)
        for fact in program.facts
    )


def test_scalar_slot_facts_do_not_alias_static_array_storage():
    program = decode((_CORPUS / "t1_cmpsival.exe").read_bytes())
    array = next(fact for fact in program.facts if fact.kind == "layout.array")
    array_base = array.value[4]

    assert not any(
        fact.kind == "slot" and fact.subject == (array_base,)
        for fact in program.facts
    )
    first_assignments = [
        fact
        for fact in program.facts
        if fact.kind == "semantic.assign" and fact.subject[0] == 0x8703
    ]
    assert len(first_assignments) == 1
    assert first_assignments[0].value[0][0] == "array"


def test_long_fp_facts_recover_literals_arithmetic_and_arrays():
    for stem in ("zz_vm_ladd", "zz_vm_lsub", "zz_vm_lmul", "zz_vm_lmix"):
        image = (_CORPUS / f"{stem}.exe").read_bytes()
        exact = [_tbx_statement(node) for node in decode0.decode_user_code(image)]
        program = decode(image)
        migrated = [
            (node.kind, node.operands) for node in program.canonical_statements
        ]

        assert migrated == exact
        assert any(
            fact.kind == "memory.read" and fact.value == ("long",)
            for fact in program.facts
        )

    mixed = decode((_CORPUS / "zz_vm_lmix.exe").read_bytes())
    array = next(fact for fact in mixed.facts if fact.kind == "layout.array")
    prints = [fact for fact in mixed.facts if fact.kind == "semantic.print"]
    assert array.value[3] == "long"
    assert len(prints) == 1
    assert len(prints[0].value[1]) == 3


def test_constant_pool_candidates_follow_evidenced_slot_extent():
    image = bytearray(0x200)
    marker = len(image) - 0x30
    image[marker : marker + 4] = b"\x00\x80\x16\x00"
    ds = marker - 0x140
    image[ds + 0x146 : ds + 0x148] = b"\x2a\x00"
    node = Operation(
        0,
        1,
        "machine.store",
        (0x130, ("memory", 0x146, "integer")),
    )

    resolved, changes = resolve_pool([node], set(), bytes(image))

    assert changes == 1
    assert resolved[0].operands == (0x130, ("const", 42))


def test_constant_pool_requires_a_unique_compiler_marker():
    image = bytearray(0x200)
    image[0x20:0x24] = bytes.fromhex("00 80 16 00")
    image[-0x30:-0x2C] = bytes.fromhex("00 80 16 00")

    assert infer_layout(bytes(image), {0x120}, ((0x140, "integer"),)) is None


def test_static_array_layout_facts_anchor_codeless_dim_statements():
    for prefix in ("", "v10_"):
        image = (_CORPUS / f"{prefix}t1_arr1.exe").read_bytes()
        program = decode(image)
        layout = next(fact for fact in program.facts if fact.kind == "layout.pool")
        array = next(fact for fact in program.facts if fact.kind == "layout.array")
        exact_dim = next(
            node for node in decode0.decode_user_code(image)
            if isinstance(node, tbx_ir.Dim)
        )

        assert layout.value[:2] == (34416 if not prefix else 28704, 0x164)
        assert array.subject == ("static", 0x120)
        assert array.value == (0, "V0", ((0, 10),), "float", 0x170, 4, 11)
        assert array.confidence == "anchored"
        assert program.canonical_statements[0] == Statement(
            0, program.code_start, "Dim", ("V0", (10,), (), False)
        )
        assert program.canonical_statements[0].operands == _tbx_statement(exact_dim)[1]


def test_static_array_record_order_restores_source_dim_order():
    program = decode((_CORPUS / "t1_arr_two.exe").read_bytes())

    dims = [
        statement for statement in program.canonical_statements
        if statement.kind == "Dim"
    ]
    assert [statement.operands for statement in dims] == [
        ("V0", (10,), (), False),
        ("V1", (5,), (), False),
    ]
    assert not any(
        fact.kind == "constant" and fact.subject[1] in {0x1A0, 0x1C0}
        for fact in program.facts
    )


def test_runtime_dim_templates_match_tbx_bounds_names_and_comma_chains():
    stems = (
        "t1_dim3v",
        "t1_dimv",
        "v10_t1_dimv",
        "t1_dimv2",
        "v10_t1_dimv2",
        "t1_dimm",
        "v10_t1_dimm",
        "t1_mix",
        "v10_t1_mix3",
    )
    for stem in stems:
        image = (_CORPUS / f"{stem}.exe").read_bytes()
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, tbx_ir.Dim)
        ]
        actual = [
            (node.kind, node.operands)
            for node in decode(image).canonical_statements
            if node.kind == "Dim"
        ]

        assert actual == exact


def test_runtime_dim_region_hides_descriptor_writes_from_source_slots():
    program = decode((_CORPUS / "t1_dim3v.exe").read_bytes())

    assert [
        (node.kind, node.operands)
        for node in program.canonical_statements[:5]
    ] == [
        ("Assign", (("var", "A"), ("const", 4))),
        (
            "Dim",
            ("V0", (("const", 2), ("var", "A"), ("const", 3)), (), False),
        ),
        (
            "For",
            (("var", "B"), ("const", 0), ("const", 2), ("const", 1)),
        ),
        (
            "For",
            (("var", "C"), ("const", 0), ("const", 4), ("const", 1)),
        ),
        (
            "For",
            (("var", "D"), ("const", 0), ("const", 3), ("const", 1)),
        ),
    ]


def test_assignment_pass_lifts_store_and_update_expressions():
    program = decode((_CORPUS / "t1_addimm.exe").read_bytes())
    assignments = [node.operands for node in program.operations if node.kind == "ir.assign"]
    target = ("slot", "V0001", 0x120)

    assert assignments[:2] == [
        (target, ("const", 5)),
        (target, ("binary", "+", target, ("const", 3))),
    ]


def test_assignment_facts_match_legacy_assignments_when_fully_resolved():
    for stem in ("t1_addimm", "t1_print", "t1_if"):
        program = decode((_CORPUS / f"{stem}.exe").read_bytes())
        legacy = [
            operation.operands
            for operation in program.operations
            if operation.kind == "ir.assign"
        ]
        migrated = [
            fact.value for fact in program.facts if fact.kind == "semantic.assign"
        ]
        assert migrated == legacy
        assert all(fact.confidence == "anchored" for fact in program.facts if fact.kind == "semantic.assign")


def test_string_assignments_anchor_slots_and_match_tbx_trees():
    for prefix in ("", "v10_"):
        image = (_CORPUS / f"{prefix}t1_str.exe").read_bytes()
        program = decode(image)
        exact = [_tbx_statement(node) for node in decode0.decode_user_code(image)]
        migrated = [
            (node.kind, node.operands) for node in program.canonical_statements
        ]

        slots = [fact for fact in program.facts if fact.kind == "slot"]
        assert [fact.value[1] for fact in slots] == [("string",), ("string",)]
        assert migrated == exact


def test_string_concat_assignment_matches_tbx_tree():
    image = (_CORPUS / "zz_op_concat.exe").read_bytes()
    exact = [_tbx_statement(node) for node in decode0.decode_user_code(image)]
    migrated = [
        (node.kind, node.operands) for node in decode(image).canonical_statements
    ]

    assert migrated == exact


def test_assignment_facts_wait_for_unique_memory_identity():
    program = decode(bytes.fromhex("c7 06 20 01 05 00"))

    assert any(fact.kind == "machine.store" for fact in program.facts)
    assert not any(fact.kind == "semantic.assign" for fact in program.facts)


def test_runtime_pass_lifts_numeric_and_string_print_chains():
    program = decode((_CORPUS / "t1_print.exe").read_bytes())
    prints = [node.operands for node in program.operations if node.kind == "ir.print"]

    assert prints == [
        ("console", (("string", "HELLO"),), True),
        ("console", (("slot", "V0001", 0x120, "float"),), True),
        (
            "console",
            (("binary", "+", ("slot", "V0001", 0x120), ("const", 1)),),
            True,
        ),
    ]
    assert any(node.kind == "tb.commit" for node in program.operations)


def test_runtime_facts_match_legacy_prints_with_complete_provenance():
    for stem in ("t1_addimm", "t1_print"):
        program = decode((_CORPUS / f"{stem}.exe").read_bytes())
        legacy = [
            operation.operands
            for operation in program.operations
            if operation.kind == "ir.print"
        ]
        migrated = [
            fact.value for fact in program.facts if fact.kind == "semantic.print"
        ]
        assert migrated == legacy

    printed = decode((_CORPUS / "t1_print.exe").read_bytes())
    first = next(fact for fact in printed.facts if fact.kind == "semantic.print")
    assert first.subject == (0x870F, 0x8718)
    assert {0x870F, 0x8712, 0x8714, 0x8716} <= set(first.evidence)


def test_runtime_facts_combine_adjacent_items_and_ignore_incomplete_chains():
    complete = decode(bytes.fromhex("cd35e8 cdbb cd35e8 cdbb cdb8"))
    incomplete = decode(bytes.fromhex("cd35e8 cdbb"))

    prints = [fact for fact in complete.facts if fact.kind == "semantic.print"]
    assert [fact.value for fact in prints] == [
        ("console", (("const", 1), ("const", 1)), True)
    ]
    assert not any(fact.kind == "semantic.print" for fact in incomplete.facts)


def test_runtime_facts_preserve_items_across_print_separators():
    for prefix in ("", "v10_"):
        image = (_CORPUS / f"{prefix}t1_pcomma2.exe").read_bytes()
        program = decode(image)
        exact = [_tbx_statement(node) for node in decode0.decode_user_code(image)]
        migrated = [
            (node.kind, node.operands) for node in program.canonical_statements
        ]

        assert migrated == exact
        separated = [
            fact for fact in program.facts
            if fact.kind == "semantic.print" and len(fact.value[1]) == 2
        ]
        assert len(separated) == 2
        assert all(len(fact.evidence) >= 8 for fact in separated)


def test_file_print_facts_preserve_channel_items_and_blank_statements():
    stems = (
        "t1_close",
        "t1_fpcomma",
        "t1_fprintblank",
        "t1_open2",
        "t1_openfor",
        "t1_tab",
    )
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in stems
        if (_CORPUS / f"{prefix}{stem}.exe").exists()
    ]
    for path in paths:
        image = path.read_bytes()
        program = decode(image)
        actual = [
            (node.kind, node.operands)
            for node in program.canonical_statements
            if node.kind == "Print" and node.operands[0] != "console"
        ]
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, tbx_ir.Print) and node.file is not None
        ]
        assert actual == exact


def test_file_print_requires_its_adjacent_channel_store():
    program = decode(bytes.fromhex("cd ba"))

    assert not any(fact.kind == "semantic.print" for fact in program.facts)


def test_runtime_facts_classify_resolved_printer_chains_as_lprint():
    for stem, expected_count in {
        "t1_lprint": 1,
        "v10_t1_lprint": 1,
        "t1_lpstr": 3,
    }.items():
        image = (_CORPUS / f"{stem}.exe").read_bytes()
        program = decode(image)
        recovered = [
            fact for fact in program.facts if fact.kind == "semantic.lprint"
        ]

        assert len(recovered) == expected_count
        assert all(fact.value[0] == "printer" for fact in recovered)
        assert not any(
            fact.kind == "semantic.print" and fact.value[0] == "printer"
            for fact in program.facts
        )

    for prefix in ("", "v10_"):
        image = (_CORPUS / f"{prefix}t1_lprint.exe").read_bytes()
        program = decode(image)
        actual = [
            (statement.kind, statement.operands)
            for statement in program.canonical_statements
        ]
        exact = [
            _tbx_statement(statement)
            for statement in decode0.decode_user_code(image)
        ]
        assert actual == exact

    blank_image = (_CORPUS / "t1_lpstr.exe").read_bytes()
    blank = decode(blank_image)
    assert [
        (statement.kind, statement.operands)
        for statement in blank.canonical_statements
    ] == [
        _tbx_statement(statement)
        for statement in decode0.decode_user_code(blank_image)
    ]
    single_flush = decode(bytes.fromhex("cd b9"))
    double_flush = decode(bytes.fromhex("cd b9 cd b9"))
    assert not any(
        fact.kind == "semantic.lprint" for fact in single_flush.facts
    )
    assert [
        fact.value for fact in double_flush.facts if fact.kind == "semantic.lprint"
    ] == [("printer", (), True)]


def test_runtime_facts_keep_tab_spc_items_in_their_chains():
    printer_image = (_CORPUS / "t1_ltab.exe").read_bytes()
    printer = decode(printer_image)
    assert [
        (statement.kind, statement.operands)
        for statement in printer.canonical_statements
    ] == [
        _tbx_statement(statement)
        for statement in decode0.decode_user_code(printer_image)
    ]

    for prefix in ("", "v10_"):
        console_image = (_CORPUS / f"{prefix}t1_tab.exe").read_bytes()
        console = decode(console_image)
        actual_prints = [
            statement.operands
            for statement in console.canonical_statements
            if statement.kind == "Print"
        ]
        exact_prints = [
            _tbx_statement(statement)[1]
            for statement in decode0.decode_user_code(console_image)
            if isinstance(statement, tbx_ir.Print)
        ]
        assert actual_prints[:3] == exact_prints[:3]
        assert actual_prints[3] == exact_prints[3]
        assert actual_prints[2][1][0] == (
            "call", "TAB", (("var", "A"),)
        )

    complete = decode(bytes.fromhex("b8 05 00 cd c8 cd 35 e8 cd bc cd b9"))
    unresolved = decode(bytes.fromhex("b9 05 00 cd c8 cd 35 e8 cd bc cd b9"))
    complete_lprint = next(
        fact for fact in complete.facts if fact.kind == "semantic.lprint"
    )
    assert complete_lprint.value == (
        "printer",
        (("call", "TAB", (("const", 5),)), ("const", 1)),
        True,
    )
    assert not any(
        fact.kind == "semantic.lprint" for fact in unresolved.facts
    )


def test_runtime_facts_translate_printer_using_clauses_and_commit_boundaries():
    for stem in ("t1_lpusing", "v10_t1_lpusing"):
        image = (_CORPUS / f"{stem}.exe").read_bytes()
        program = decode(image)

        assert [
            (statement.kind, statement.operands)
            for statement in program.canonical_statements
        ] == [
            _tbx_statement(statement)
            for statement in decode0.decode_user_code(image)
        ]
        assert sum(
            fact.kind == "reference.print_using" for fact in program.facts
        ) == 1
        assert sum(
            fact.kind == "semantic.print_using" for fact in program.facts
        ) == 1
        assert sum(fact.kind == "semantic.lprint" for fact in program.facts) == 2

        clause = next(
            fact
            for fact in program.facts
            if fact.kind == "reference.print_using"
        )
        altered = bytearray(image)
        altered[clause.subject[1] - 1] = 0xB7
        assert not any(
            fact.kind in {"reference.print_using", "semantic.print_using"}
            for fact in decode(bytes(altered)).facts
        )

    nested_image = (_CORPUS / "t1_usingtwice.exe").read_bytes()
    nested = decode(nested_image)
    assert [
        (statement.kind, statement.operands)
        for statement in nested.canonical_statements
    ] == [
        _tbx_statement(statement)
        for statement in decode0.decode_user_code(nested_image)
    ]
    assert sum(
        fact.kind == "reference.print_using" for fact in nested.facts
    ) == 2
    assert not any(
        fact.kind == "semantic.print_using" for fact in nested.facts
    )
    outer = next(
        fact for fact in nested.facts if fact.kind == "semantic.lprint"
    )
    assert sum(
        isinstance(item, tuple) and item[:1] == ("print_using",)
        for item in outer.value[1]
    ) == 2

    for stem, expected in (
        ("t1_using", 3),
        ("t1_pr2", 3),
        ("v10_t1_pr2", 3),
        ("t1_usingtab", 1),
        ("v10_t1_usingtab", 1),
    ):
        image = (_CORPUS / f"{stem}.exe").read_bytes()
        program = decode(image)
        assert [
            (statement.kind, statement.operands)
            for statement in program.canonical_statements
        ] == [
            _tbx_statement(statement)
            for statement in decode0.decode_user_code(image)
        ]
        assert sum(
            fact.kind == "semantic.print_using" for fact in program.facts
        ) == expected

    file_using = [
        statement
        for statement in decode(
            (_CORPUS / "t1_pr2.exe").read_bytes()
        ).canonical_statements
        if statement.kind == "PrintUsing" and statement.operands[0] != "console"
    ]
    assert [statement.operands[0] for statement in file_using] == [1]


def test_runtime_facts_recover_complete_console_and_file_write_chains():
    for prefix in ("", "v10_"):
        for stem in ("t1_write", "t1_writefile"):
            image = (_CORPUS / f"{prefix}{stem}.exe").read_bytes()
            program = decode(image)
            actual = [node for node in program.canonical_statements if node.kind == "Write"]
            exact = [
                _tbx_statement(node)
                for node in decode0.decode_user_code(image)
                if isinstance(node, tbx_ir.Write)
            ]
            assert [(node.kind, node.operands) for node in actual] == exact
            fact = next(item for item in program.facts if item.kind == "semantic.write")
            assert fact.confidence == "anchored"

    incomplete = decode(bytes.fromhex("cd 35 e8 cd ec f4"))
    unresolved_prefix = decode(
        bytes.fromhex("cd ec f4 cd ec f8 cd 35 e8 cd ec f4 cd b8")
    )
    assert not any(fact.kind == "semantic.write" for fact in incomplete.facts)
    assert not any(
        fact.kind == "semantic.write" for fact in unresolved_prefix.facts
    )


def test_runtime_facts_recover_complete_lset_and_rset_scaffolds():
    for prefix in ("", "v10_"):
        for stem, kind in (("t1_lset", "Lset"), ("t1_rset", "Rset")):
            image = (_CORPUS / f"{prefix}{stem}.exe").read_bytes()
            program = decode(image)
            actual = [
                (node.kind, node.operands)
                for node in program.canonical_statements
            ]
            exact = [
                _tbx_statement(node) for node in decode0.decode_user_code(image)
            ]
            assert actual == exact
            fact = next(
                item for item in program.facts if item.kind == f"semantic.{kind.lower()}"
            )
            assert fact.confidence == "anchored"


def test_runtime_facts_recover_scalar_mid_assignments():
    for prefix in ("", "v10_"):
        for stem in ("t1_midas", "t1_midvarstart", "t1_mid3"):
            image = (_CORPUS / f"{prefix}{stem}.exe").read_bytes()
            program = decode(image)
            actual = [
                (node.kind, node.operands)
                for node in program.canonical_statements
            ]
            exact = [
                _tbx_statement(node) for node in decode0.decode_user_code(image)
            ]
            assert actual == exact
            fact = next(
                item
                for item in program.facts
                if item.kind == "semantic.mid_assign"
            )
            assert fact.confidence == "anchored"


def test_runtime_facts_leave_incomplete_mid_assign_scaffolds_structural():
    complete = bytes.fromhex(
        "b8 02 00 be 40 01 cd 9c be 20 01 ba 96 00 8e c2 cd ae"
    )
    truncated = decode(complete[:-2])
    altered = decode(complete[:14] + b"\x8e\xc0" + complete[16:])

    assert not any(
        fact.kind == "memory.write"
        and fact.subject == (0x120,)
        and fact.value == ("string",)
        for fact in truncated.facts
    )
    assert not any(
        fact.kind == "memory.write"
        and fact.subject == (0x120,)
        for fact in altered.facts
    )
    assert not any(
        fact.kind == "semantic.mid_assign" for fact in altered.facts
    )


def test_array_mid_assign_consumes_a_shared_static_address_fact():
    image = (_CORPUS / "v10_t1_midarrelem.exe").read_bytes()
    program = decode(image)
    actual = [
        (node.kind, node.operands)
        for node in program.canonical_statements
        if node.kind == "MidAssign"
    ]
    exact = [
        _tbx_statement(node)
        for node in decode0.decode_user_code(image)
        if isinstance(node, tbx_ir.MidAssign)
    ]

    assert actual == exact
    statement = next(
        fact for fact in program.facts if fact.kind == "semantic.mid_assign"
    )
    target = next(
        fact
        for fact in program.facts
        if fact.kind == "reference.array_address"
        and statement.subject[0] < fact.subject[0] < statement.subject[1]
    )
    assert target.value[1:] == ("string", 4, False)

    altered = bytearray(image)
    altered[statement.subject[1] - 1] = 0xAE
    assert not any(
        fact.kind == "semantic.mid_assign"
        for fact in decode(bytes(altered)).facts
    )


def test_scalar_swap_signature_recovers_slots_without_component_aliases():
    for prefix in ("", "v10_"):
        image = (_CORPUS / f"{prefix}t1_swap.exe").read_bytes()
        program = decode(image)
        actual = [
            (node.kind, node.operands) for node in program.canonical_statements
        ]
        exact = [
            _tbx_statement(node) for node in decode0.decode_user_code(image)
        ]

        assert actual == exact
        swap = next(
            fact for fact in program.facts if fact.kind == "semantic.swap"
        )
        assert swap.confidence == "anchored"
        assert not any(
            fact.kind in {"memory.read", "memory.write"}
            and fact.subject in {(0x124,), (0x126,)}
            and fact.value == ("integer",)
            for fact in program.facts
        )


def test_scalar_swap_requires_the_complete_inline_template():
    complete = bytes.fromhex(
        "8b 06 24 01 87 06 20 01 89 06 24 01 "
        "8b 06 26 01 87 06 22 01 89 06 26 01"
    )
    truncated = decode(complete[:-4])
    altered = decode(complete[:18] + b"\x24\x01" + complete[20:])

    assert not any(fact.kind == "semantic.swap" for fact in truncated.facts)
    assert not any(fact.kind == "semantic.swap" for fact in altered.facts)


def test_static_array_swap_consumes_shared_element_address_facts():
    for prefix in ("", "v10_"):
        for stem, width in (("t1_arrswap", 2), ("t1_arrswapf", 4)):
            image = (_CORPUS / f"{prefix}{stem}.exe").read_bytes()
            program = decode(image)
            actual = [
                (node.kind, node.operands)
                for node in program.canonical_statements
                if node.kind == "Swap"
            ]
            exact = [
                _tbx_statement(node)
                for node in decode0.decode_user_code(image)
                if isinstance(node, tbx_ir.Swap)
            ]

            assert actual == exact
            swap = next(
                fact for fact in program.facts if fact.kind == "semantic.swap"
            )
            addresses = sorted(
                (
                    fact
                    for fact in program.facts
                    if fact.kind == "reference.array_address"
                    and swap.subject[0] <= fact.subject[0] < swap.subject[1]
                ),
                key=lambda fact: fact.subject,
            )
            assert [fact.value[2:] for fact in addresses] == [
                (width, False),
                (width, True),
            ]
            assert swap.confidence == "anchored"


def test_mixed_string_array_swap_claims_descriptor_exchange_components():
    for prefix in ("", "v10_"):
        image = (_CORPUS / f"{prefix}t1_swapstrelem.exe").read_bytes()
        program = decode(image)
        actual = [
            (node.kind, node.operands)
            for node in program.canonical_statements
            if node.kind == "Swap"
        ]
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, tbx_ir.Swap)
        ]

        assert actual == exact
        swap = next(
            fact for fact in program.facts if fact.kind == "semantic.swap"
        )
        address = next(
            fact
            for fact in program.facts
            if fact.kind == "reference.array_address"
            and fact.subject[0] == swap.subject[0]
        )
        assert address.value[1:] == ("string", 4, False)
        assert not any(
            fact.kind in {"memory.read", "memory.write"}
            and fact.subject in {(344,), (346,)}
            and fact.value == ("integer",)
            for fact in program.facts
        )


def test_dynamic_array_swap_consumes_runtime_element_address_facts():
    for prefix in ("t1_", "v10_"):
        for suffix, kind, width in (
            ("swap_dynstr", "string", 4),
            ("swap_dyndbl", "double", 8),
        ):
            image = (_CORPUS / f"{prefix}{suffix}.exe").read_bytes()
            program = decode(image)
            actual = [
                (node.kind, node.operands)
                for node in program.canonical_statements
                if node.kind == "Swap"
            ]
            exact = [
                _tbx_statement(node)
                for node in decode0.decode_user_code(image)
                if isinstance(node, tbx_ir.Swap)
            ]

            assert actual == exact
            swap = next(
                fact for fact in program.facts if fact.kind == "semantic.swap"
            )
            addresses = sorted(
                (
                    fact
                    for fact in program.facts
                    if fact.kind == "reference.array_address"
                    and swap.subject[0] <= fact.subject[0] < swap.subject[1]
                ),
                key=lambda fact: fact.subject,
            )
            assert [fact.value[1:] for fact in addresses] == [
                (kind, width, False),
                (kind, width, True),
            ]

            altered = bytearray(image)
            altered[swap.subject[1] - 2 : swap.subject[1]] = b"\x8e\xc2"
            assert not any(
                fact.kind == "semantic.swap"
                for fact in decode(bytes(altered)).facts
            )


def test_computed_array_values_feed_print_items_without_redecoding_indices():
    for stem in (
        "t1_arrswapf",
        "v10_t1_arrswapf",
        "t1_swap_dyndbl",
        "v10_swap_dyndbl",
        "t1_swap_dynstr",
        "v10_swap_dynstr",
    ):
        image = (_CORPUS / f"{stem}.exe").read_bytes()
        program = decode(image)
        actual = [
            (node.kind, node.operands)
            for node in program.canonical_statements
            if node.kind == "Print"
        ]
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, tbx_ir.Print)
        ]

        assert actual == exact
        assert [
            (node.kind, node.operands) for node in program.canonical_statements
        ] == [
            _tbx_statement(node) for node in decode0.decode_user_code(image)
        ]
        values = [
            fact for fact in program.facts if fact.kind == "reference.array_value"
        ]
        assert len(values) == 2
        assert all(fact.confidence == "anchored" for fact in values)
        if "swap_dyn" in stem:
            stores = [
                fact
                for fact in program.facts
                if fact.kind == "reference.array_store"
            ]
            assignments = [
                fact
                for fact in program.facts
                if fact.kind == "semantic.assign"
                and isinstance(fact.value[0], tuple)
                and fact.value[0][:1] == ("array",)
            ]
            assert len(stores) == len(assignments) == 2


def test_staged_integer_array_store_and_print_reuse_reference_facts():
    for prefix in ("", "v10_"):
        image = (_CORPUS / f"{prefix}t1_arrwrite.exe").read_bytes()
        program = decode(image)

        assert [
            (node.kind, node.operands) for node in program.canonical_statements
        ] == [
            _tbx_statement(node) for node in decode0.decode_user_code(image)
        ]
        stores = [
            fact for fact in program.facts
            if fact.kind == "reference.array_store"
        ]
        values = [
            fact for fact in program.facts
            if fact.kind == "reference.array_value"
        ]
        assert len(stores) == len(values) == 1
        assert stores[0].value[1] == values[0].value[1] == "integer"
        assert stores[0].confidence == values[0].confidence == "anchored"


def test_integer_array_folds_feed_assignments_and_if_goto_facts():
    for prefix in ("", "v10_"):
        read_image = (_CORPUS / f"{prefix}t1_arrread.exe").read_bytes()
        read = decode(read_image)
        assert [
            (node.kind, node.operands) for node in read.canonical_statements
        ] == [
            _tbx_statement(node) for node in decode0.decode_user_code(read_image)
        ]
        value = next(
            fact for fact in read.facts
            if fact.kind == "reference.array_value"
        )
        assert value.value[0][:2] == ("binary", "+")

        compare_image = (_CORPUS / f"{prefix}t1_arrcmp.exe").read_bytes()
        compared = decode(compare_image)
        actual = [
            (node.kind, node.operands)
            for node in compared.canonical_statements
            if node.kind == "IfGoto"
        ]
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(compare_image)
            if isinstance(node, tbx_ir.IfGoto)
        ]
        assert len(actual) == len(exact) == 1
        assert actual[0][0] == exact[0][0]
        assert actual[0][1][:3] == exact[0][1][:3]
        conditional = next(
            fact for fact in compared.facts
            if fact.kind == "semantic.if_goto"
            and isinstance(fact.value[1], tuple)
            and fact.value[1][:1] == ("array",)
        )
        assert conditional.confidence == "anchored"

        commit = next(
            instruction for instruction in compared.instructions
            if instruction.offset in conditional.evidence
            and instruction.kind == "tb.runtime"
            and instruction.operands == (0x87,)
        )
        altered = bytearray(compare_image)
        altered[commit.offset + 1] = 0x88
        assert not any(
            fact.kind == "semantic.if_goto"
            and isinstance(fact.value[1], tuple)
            and fact.value[1][:1] == ("array",)
            for fact in decode(bytes(altered)).facts
        )


def test_grouped_locate_runtime_legs_recover_complete_constant_forms():
    stems = (
        "t1_locateomit",
        "t1_locate5",
        "t1_loccurs",
        "v10_t1_loccurs",
        "t1_scr2",
        "v10_t1_scr2",
        "t1_addpool",
        "v10_t1_addpool",
        "t1_locarr",
        "v10_t1_locarr",
        "t1_locarrcom",
        "v10_t1_locarrcom",
    )
    for stem in stems:
        image = (_CORPUS / f"{stem}.exe").read_bytes()
        program = decode(image)
        actual = [
            (node.kind, node.operands)
            for node in program.canonical_statements
            if node.kind == "Locate"
        ]
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, tbx_ir.Locate)
        ]

        assert actual == exact
        confidence = "anchored" if "locarr" in stem else "signature"
        assert {
            fact.confidence
            for fact in program.facts
            if fact.kind == "semantic.locate"
        } == {confidence}
        if "locarr" in stem:
            reads = [
                fact
                for fact in program.facts
                if fact.kind == "reference.array_read"
            ]
            assert len(reads) == 2
            assert reads[1].value[2] is True


def test_locate_does_not_emit_a_partial_cursor_extension():
    truncated = decode(
        bytes.fromhex("b8 03 00 89 c3 b8 05 00 cd cf b8 01 00")
    )

    assert not any(fact.kind == "semantic.locate" for fact in truncated.facts)


def test_color_cell_scaffolds_recover_exact_optional_operands():
    for prefix in ("", "v10_"):
        for stem in ("t1_scr", "t1_scr2", "t1_color3", "t1_colorfp"):
            image = (_CORPUS / f"{prefix}{stem}.exe").read_bytes()
            program = decode(image)
            actual = [
                (node.kind, node.operands)
                for node in program.canonical_statements
                if node.kind == "Color"
            ]
            exact = [
                _tbx_statement(node)
                for node in decode0.decode_user_code(image)
                if isinstance(node, tbx_ir.Color)
            ]

            assert actual == exact
            assert all(
                fact.confidence == "anchored"
                for fact in program.facts
                if fact.kind == "semantic.color"
            )


def test_color_requires_matching_cells_for_every_present_mask_bit():
    missing = decode(bytes.fromhex("cd ec 22 04"))
    wrong_cell = decode(bytes.fromhex("c7 06 94 00 01 00 cd ec 22 04"))
    truncated = decode(bytes.fromhex("c7 06 88 00 01 00 cd ec 22"))

    for program in (missing, wrong_cell, truncated):
        assert not any(fact.kind == "semantic.color" for fact in program.facts)
        assert program.canonical_statements == ()


def test_screen_immediate_cell_scaffolds_recover_exact_optional_operands():
    names = (
        "t1_blitline.exe",
        "t1_paintt.exe",
        "t1_screen.exe",
        "t1_screena.exe",
        "t1_screenb.exe",
        "t1_screenp.exe",
        "t1_viewbare.exe",
        "v10_t1_blitline.exe",
        "v10_t1_screen.exe",
        "v10_t1_viewbare.exe",
    )
    for name in names:
        image = (_CORPUS / name).read_bytes()
        program = decode(image)
        actual = [
            (node.kind, node.operands)
            for node in program.canonical_statements
            if node.kind == "Screen"
        ]
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, tbx_ir.Screen)
        ]

        assert actual == exact
        assert all(
            fact.confidence == "anchored"
            for fact in program.facts
            if fact.kind == "semantic.screen"
        )


def test_screen_requires_matching_immediate_cells_for_every_present_mask_bit():
    missing = decode(bytes.fromhex("cd ec c6 08"))
    wrong_cell = decode(bytes.fromhex("c7 06 94 00 01 00 cd ec c6 08"))
    dynamic = decode(bytes.fromhex("89 06 88 00 cd ec c6 08"))
    truncated = decode(bytes.fromhex("c7 06 88 00 01 00 cd ec c6"))

    for program in (missing, wrong_cell, dynamic, truncated):
        assert not any(fact.kind == "semantic.screen" for fact in program.facts)
        assert program.canonical_statements == ()


def test_files_requires_bare_dispatch_or_complete_resolved_string_scaffold():
    for prefix in ("", "v10_"):
        for stem in ("t1_files", "t1_files0"):
            image = (_CORPUS / f"{prefix}{stem}.exe").read_bytes()
            program = decode(image)
            actual = [
                (node.kind, node.operands)
                for node in program.canonical_statements
                if node.kind == "Files"
            ]
            exact = [
                _tbx_statement(node)
                for node in decode0.decode_user_code(image)
                if isinstance(node, tbx_ir.Files)
            ]

            assert actual == exact
            assert all(
                fact.confidence in {"anchored", "signature"}
                for fact in program.facts
                if fact.kind == "semantic.files"
            )

    incomplete = decode(bytes.fromhex("cd ec 44"))
    wrong_runtime = decode(bytes.fromhex("be 20 01 cd 9a cd ec 44"))
    unresolved = decode(bytes.fromhex("be 20 01 cd 9c cd ec 44"))
    for program in (incomplete, wrong_runtime, unresolved):
        assert not any(fact.kind == "semantic.files" for fact in program.facts)
        assert program.canonical_statements == ()


def test_single_string_statements_require_complete_resolved_scaffolds():
    stems = (
        "t1_chdir",
        "t1_dates",
        "t1_draw",
        "t1_environ",
        "t1_kill",
        "t1_mkdir",
        "t1_play",
        "t1_rmdir",
        "t1_shell",
        "t1_times",
    )
    statement_types = (
        tbx_ir.Chdir,
        tbx_ir.DateTimeSet,
        tbx_ir.Draw,
        tbx_ir.Environ,
        tbx_ir.Kill,
        tbx_ir.Mkdir,
        tbx_ir.Play,
        tbx_ir.Rmdir,
        tbx_ir.Shell,
    )
    for prefix in ("", "v10_"):
        for stem in stems:
            image = (_CORPUS / f"{prefix}{stem}.exe").read_bytes()
            program = decode(image)
            actual = [
                (node.kind, node.operands)
                for node in program.canonical_statements
                if node.kind in {item.__name__ for item in statement_types}
            ]
            exact = [
                _tbx_statement(node)
                for node in decode0.decode_user_code(image)
                if isinstance(node, statement_types)
            ]

            assert actual == exact

    for prefix in ("", "v10_"):
        program = decode((_CORPUS / f"{prefix}t1_shellvar.exe").read_bytes())
        assert not any(node.kind == "Shell" for node in program.canonical_statements)

    missing = decode(bytes.fromhex("cd ec 10"))
    wrong_runtime = decode(bytes.fromhex("be 20 01 cd 9a cd ec 10"))
    unresolved = decode(bytes.fromhex("be 20 01 cd 9c cd ec 10"))
    for program in (missing, wrong_runtime, unresolved):
        assert not any(
            fact.kind == "semantic.statement" and fact.value[0] == "CHDIR"
            for fact in program.facts
        )
        assert program.canonical_statements == ()


def test_direct_integer_for_facts_require_one_consistent_complete_region():
    operations = (
        Operation(6, 3, "x86.jmp", (13,), "e9 04 00", "structural"),
        Operation(9, 4, "x86.op_ff", (), "ff 06 20 01", "structural"),
        Operation(13, 5, "x86.op_83", (), "83 3e 20 01 05", "structural"),
        Operation(18, 2, "x86.jle", (9,), "7e f5", "structural"),
    )
    evidence = Evidence(bytes(20), operations, (), ())
    assignment = Fact(
        "semantic.assign",
        (0, 6),
        (("slot", "V0", 0x120), ("const", 1)),
        (0,),
        "anchored",
    )
    goto = Fact("flow.goto", (6, 9), (13,), (6,), "structural")
    branch = Fact("flow.branch", (18, 20), ("<=", 9), (18,), "structural")
    slot = Fact("slot", (0x120,), ("V0", ("integer",)), (0,), "anchored")
    base = frozenset((assignment, goto, branch, slot))

    result = tuple(integer_for_facts(evidence, base))

    assert [(fact.kind, fact.value) for fact in result] == [
        (
            "semantic.for",
            (("slot", "V0", 0x120), ("const", 1), ("const", 5), ("const", 1)),
        ),
        ("semantic.next", (("slot", "V0", 0x120),)),
    ]

    wrong_branch = frozenset(
        (
            assignment,
            goto,
            slot,
            Fact("flow.branch", (18, 20), (">=", 9), (18,), "structural"),
        )
    )
    competing = frozenset(
        (
            *base,
            Fact(
                "semantic.assign",
                (1, 6),
                (("slot", "OTHER", 0x120), ("const", 2)),
                (1,),
                "anchored",
            ),
        )
    )
    assert tuple(integer_for_facts(evidence, wrong_branch)) == ()
    assert tuple(integer_for_facts(evidence, competing)) == ()


def test_direct_integer_for_accepts_only_a_complete_long_branch_trampoline():
    operations = (
        Operation(6, 3, "x86.jmp", (13,), "e9 04 00", "structural"),
        Operation(9, 4, "x86.op_ff", (), "ff 06 20 01", "structural"),
        Operation(13, 5, "x86.op_83", (), "83 3e 20 01 05", "structural"),
        Operation(18, 2, "x86.jg", (23,), "7f 03", "structural"),
        Operation(20, 3, "x86.jmp", (9,), "e9 f2 ff", "structural"),
    )
    evidence = Evidence(bytes(23), operations, (), ())
    assignment = Fact(
        "semantic.assign",
        (0, 6),
        (("slot", "V0", 0x120), ("const", 1)),
        (0,),
        "anchored",
    )
    goto = Fact("flow.goto", (6, 9), (13,), (6,), "structural")
    branch = Fact("flow.branch", (18, 20), (">", 23), (18,), "structural")
    slot = Fact("slot", (0x120,), ("V0", ("integer",)), (0,), "anchored")
    complete = frozenset((assignment, goto, branch, slot))

    result = tuple(integer_for_facts(evidence, complete))

    assert [fact.subject for fact in result] == [(0, 9), (9, 23)]
    malformed = Evidence(
        bytes(23),
        (*operations[:-1], Operation(20, 3, "x86.jmp", (10,), "e9 f3 ff", "structural")),
        (),
        (),
    )
    assert tuple(integer_for_facts(malformed, complete)) == ()


def test_integer_for_variable_limit_snapshot_recovers_source_operand():
    for name in (
        "t1_fori.exe",
        "t1_forvarlimneg.exe",
        "v10_t1_forvarlimneg.exe",
        "t1_forlong.exe",
        "v10_t1_forlong.exe",
        "t1_forvarlimfar.exe",
        "v10_t1_forvarlimfar.exe",
    ):
        image = (_CORPUS / name).read_bytes()
        actual = [
            (node.kind, node.operands)
            for node in decode(image).canonical_statements
            if node.kind in {"For", "NextStmt"}
        ]
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, (tbx_ir.For, tbx_ir.NextStmt))
        ]

        assert actual == exact


def test_integer_variable_step_recovers_only_complete_two_arm_regions():
    for name in (
        "t1_forvarstep.exe",
        "v10_t1_forvarstep.exe",
        "t1_forvarstep2.exe",
        "v10_t1_forvarstep2.exe",
        "v10_t1_forvarstepinit.exe",
    ):
        image = (_CORPUS / name).read_bytes()
        program = decode(image)
        actual = [
            (node.kind, node.operands)
            for node in program.canonical_statements
            if node.kind in {"For", "NextStmt"}
        ]
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, (tbx_ir.For, tbx_ir.NextStmt))
        ]

        assert actual == exact

    program = decode((_CORPUS / "t1_forvarstep.exe").read_bytes())
    evidence = Evidence(
        program.image_size * b"\0",
        program.instructions,
        program.blocks,
        program.xrefs,
    )
    inputs = frozenset(
        fact
        for fact in program.facts
        if fact.kind not in {"semantic.for", "semantic.next"}
    )
    complete = tuple(integer_variable_step_for_facts(evidence, inputs))
    truncated = Evidence(
        evidence.image,
        tuple(
            operation
            for operation in evidence.instructions
            if operation.offset != 34631
        ),
        evidence.blocks,
        evidence.xrefs,
    )

    assert [fact.kind for fact in complete] == ["semantic.for", "semantic.next"]
    assert tuple(integer_variable_step_for_facts(truncated, inputs)) == ()


def test_fp_for_templates_recover_short_long_single_and_double_loops():
    names = (
        "t1_for.exe",
        "v10_t1_for.exe",
        "t1_for2.exe",
        "v10_t1_for2.exe",
        "t1_forlongfp.exe",
        "v10_t1_forlongfp.exe",
    )
    for name in names:
        image = (_CORPUS / name).read_bytes()
        actual = [
            (node.kind, node.operands)
            for node in decode(image).canonical_statements
            if node.kind in {"For", "NextStmt"}
        ]
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, (tbx_ir.For, tbx_ir.NextStmt))
        ]

        assert actual == exact


def test_far_fp_escape_keeps_following_for_tail_aligned():
    image = bytes.fromhex("cd 3c d9 1c cd 87 cd 35 06 20 01")

    far = decode_instruction(image, 0, len(image), 0, "1.1")
    commit = decode_instruction(image, far.end, len(image), 0, "1.1")
    load = decode_instruction(image, commit.end, len(image), 0, "1.1")

    assert (far.kind, far.size, far.operands) == ("tb.fp_far", 4, (0xD9, 0x1C))
    assert (commit.kind, commit.offset) == ("tb.runtime", 4)
    assert (load.kind, load.offset) == ("tb.fp", 6)


def test_transcendental_dispatch_owns_its_selector_byte():
    names = {0x00: "SIN", 0x08: "LOG", 0x0E: "EXP"}
    for selector, name in names.items():
        image = bytes((0xCD, 0x3E, selector, 0xCD, 0xEC, 0x32))
        operation = decode_instruction(image, 0, len(image), 0, "1.1")

        assert (operation.size, operation.kind, operation.operands) == (
            3,
            "tb.fp_function",
            (name,),
        )


def test_profiled_backward_loop_keeps_physical_source_fallthrough():
    program = decode((_CORPUS / "zz_ginf.exe").read_bytes())

    assert program.canonical_statements[-1].kind == "End"
    assert any(
        xref.kind == "orphan" and xref.target == 0x871E
        for xref in program.xrefs
    )


def test_bounds_vectors_own_descriptor_payloads_without_source_semantics():
    for vector, role in {0x91: "base", 0x92: "span", 0x93: "index"}.items():
        image = bytes((0xCD, vector, 0x34, 0x12, 0xCD, 0xEC, 0x32))
        operation = decode_instruction(image, 0, len(image), 0, "1.1")

        assert (operation.size, operation.kind, operation.operands) == (
            4,
            "tb.bounds",
            (role, 0x1234),
        )


def test_numeric_read_facts_recover_complete_committed_chains():
    for prefix in ("", "v10_"):
        for stem in ("t1_readnum", "t1_readfp", "t1_readalt"):
            image = (_CORPUS / f"{prefix}{stem}.exe").read_bytes()
            program = decode(image)
            actual = [
                (node.kind, node.operands)
                for node in program.canonical_statements
                if node.kind == "Read"
            ]
            exact = [
                _tbx_statement(node)
                for node in decode0.decode_user_code(image)
                if isinstance(node, tbx_ir.Read)
            ]
            assert actual == exact


def test_read_facts_reuse_string_integer_and_array_targets():
    stems = (
        "t1_databig",
        "t1_datasharedlit",
        "t1_readsarr",
        "t1_readstr",
        "v10_t1_readiarr",
        "v10_t1_readsarr",
        "v10_t1_readstr",
    )
    for stem in stems:
        image = (_CORPUS / f"{stem}.exe").read_bytes()
        program = decode(image)
        actual = [
            (node.kind, node.operands)
            for node in program.canonical_statements
            if node.kind == "Read"
        ]
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, tbx_ir.Read)
        ]

        assert actual == exact


def test_read_does_not_lift_incomplete_or_unresolved_mixed_suffixes():
    incomplete = decode(bytes.fromhex("cd ec b2 cd 35 1e 20 01"))
    mixed = decode(
        bytes.fromhex(
            "cd ec b4 be 24 01 cd a0 cd ec b2 cd 35 1e 20 01 cd 87"
        )
    )

    assert not any(fact.kind == "semantic.read" for fact in incomplete.facts)
    assert not any(fact.kind == "semantic.read" for fact in mixed.facts)


def test_input_file_facts_recover_complete_scalar_chains():
    stems = (
        "t1_file",
        "v10_t1_file",
        "t1_file2",
        "v10_t1_file2",
        "t1_open2",
    )
    for stem in stems:
        image = (_CORPUS / f"{stem}.exe").read_bytes()
        program = decode(image)
        actual = [
            (node.kind, node.operands)
            for node in program.canonical_statements
            if node.kind == "InputFile"
        ]
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, tbx_ir.InputFile)
        ]
        if stem.endswith("t1_file2"):
            input_fact = next(
                fact
                for fact in program.facts
                if fact.kind == "semantic.input_file"
            )
            assert input_fact.value[0] == 2
            assert [target[2] for target in input_fact.value[1]] == [0x124, 0x120]
            assert len(actual) == len(exact) == 1
        else:
            assert actual == exact

    for prefix in ("", "v10_"):
        image = (_CORPUS / f"{prefix}t1_fileint.exe").read_bytes()
        program = decode(image)
        actual = [
            (node.kind, node.operands)
            for node in program.canonical_statements
            if node.kind == "InputFile"
        ]
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, tbx_ir.InputFile)
        ]

        assert actual == exact
        input_fact = next(
            fact for fact in program.facts if fact.kind == "semantic.input_file"
        )
        assert len(input_fact.value[1]) == 2


def test_input_file_reuses_computed_array_store_facts():
    stems = (
        "t1_inpfilearr",
        "v10_t1_inpfilearr",
        "t1_sarr2",
        "v10_t1_sarr2",
    )
    for stem in stems:
        image = (_CORPUS / f"{stem}.exe").read_bytes()
        program = decode(image)
        actual = [
            (node.kind, node.operands)
            for node in program.canonical_statements
            if node.kind == "InputFile"
        ]
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, tbx_ir.InputFile)
        ]

        assert actual == exact
        references = [
            fact for fact in program.facts if fact.kind == "reference.array_store"
        ]
        assert len(references) == 2
        assert all(fact.confidence == "anchored" for fact in references)


def test_console_input_facts_preserve_prompts_flags_and_scalar_targets():
    stems = (
        "t1_inp",
        "t1_inp2",
        "t1_inp4",
        "t1_inpdbl",
        "t1_inpmixed",
        "t1_inpmulti",
        "t1_inpmulti3",
        "t1_inpsemi",
        "t1_inpsemis",
    )
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in stems
        if (_CORPUS / f"{prefix}{stem}.exe").exists()
    ]
    for path in paths:
        image = path.read_bytes()
        program = decode(image)
        actual = [
            (node.kind, node.operands)
            for node in program.canonical_statements
            if node.kind == "Input"
        ]
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, tbx_ir.Input)
        ]
        assert actual == exact


def test_console_input_rejects_incomplete_target_chains():
    image = bytearray((_CORPUS / "t1_inp.exe").read_bytes())
    complete = decode(bytes(image))
    header = next(
        instruction
        for instruction in complete.instructions
        if instruction.kind == "tb.statement"
        and instruction.operands[:1] == ("INPUT",)
    )
    image[header.offset + 5] |= 1
    incomplete = decode(bytes(image))
    assert not any(
        fact.kind == "semantic.input" and fact.subject[0] == header.offset
        for fact in incomplete.facts
    )



def test_console_integer_input_uses_the_calibrated_scratch_bridge():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in ("t1_dimv2", "t1_swapstrelem")
    ] + [_CORPUS / "t1_ifloopguard.exe"]
    for path in paths:
        image = path.read_bytes()
        actual = [
            (node.kind, node.operands)
            for node in decode(image).canonical_statements
            if node.kind == "Input"
        ]
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, tbx_ir.Input)
        ]
        assert actual == exact


def test_console_array_input_consumes_shared_array_store_facts():
    paths = [
        _CORPUS / name
        for name in (
            "t1_inparr.exe",
            "v10_t1_inparr.exe",
            "t1_inpdynarr.exe",
            "t1_inpdynconst.exe",
            "t1_inpsarr.exe",
            "v10_t1_inpsarr.exe",
        )
    ]
    for path in paths:
        image = path.read_bytes()
        program = decode(image)
        actual = [
            (node.kind, node.operands)
            for node in program.canonical_statements
            if node.kind == "Input"
        ]
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, tbx_ir.Input)
        ]
        assert actual == exact
        assert any(
            fact.kind == "reference.array_store" for fact in program.facts
        )


def test_input_file_rejects_an_incomplete_following_item():
    program = decode(
        bytes.fromhex(
            "b8 01 00 a3 60 00 cd ec a0 be 20 01 cd a0 cd ec 9e"
        )
    )

    assert not any(fact.kind == "semantic.input_file" for fact in program.facts)


def test_open_facts_preserve_both_source_scaffolds():
    paths = [
        _CORPUS / "t1_open2.exe",
        _CORPUS / "t1_openfor.exe",
        _CORPUS / "v10_t1_openfor.exe",
        _CORPUS / "v10_t1_openrandomlen.exe",
    ]
    for path in paths:
        image = path.read_bytes()
        program = decode(image)
        actual = [
            (node.kind, node.operands)
            for node in program.canonical_statements
            if node.kind == "Open"
        ]
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, tbx_ir.Open)
        ]
        assert actual == exact


def test_open_fact_requires_the_complete_string_push_scaffold():
    image = bytearray((_CORPUS / "t1_open2.exe").read_bytes())
    complete = decode(bytes(image))
    first_open = next(
        instruction
        for instruction in complete.instructions
        if instruction.kind == "tb.statement"
        and instruction.operands[:1] == ("OPEN",)
    )
    image[first_open.offset - 5 : first_open.offset - 3] = b"\x90\x90"
    altered = decode(bytes(image))

    assert not any(
        fact.kind == "semantic.open" and fact.subject[1] == first_open.end
        for fact in altered.facts
    )


def test_static_array_layout_resolves_read_only_open_filename():
    for prefix in ("", "v10_"):
        image = (_CORPUS / f"{prefix}t1_inpfilearr.exe").read_bytes()
        program = decode(image)
        exact = next(
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, tbx_ir.Open)
        )
        actual = next(
            (node.kind, node.operands)
            for node in program.canonical_statements
            if node.kind == "Open"
        )

        assert actual == exact


def test_close_facts_preserve_bare_immediate_and_variable_channels():
    stems = (
        "t1_close",
        "t1_file",
        "v10_t1_file",
        "t1_closevar",
        "v10_t1_closevar",
    )
    for stem in stems:
        image = (_CORPUS / f"{stem}.exe").read_bytes()
        program = decode(image)
        actual = [
            (node.kind, node.operands)
            for node in program.canonical_statements
            if node.kind == "Close"
        ]
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, tbx_ir.Close)
        ]
        assert actual == exact


def test_numbered_close_requires_a_complete_ax_source():
    program = decode(bytes.fromhex("cd ec 18"))

    assert not any(fact.kind == "semantic.close" for fact in program.facts)


def test_trap_control_facts_preserve_event_number_and_mode():
    stems = (
        "t1_oncom",
        "t1_onkey",
        "t1_onpen",
        "t1_onplay",
        "t1_ontimer",
        "t1_strigoff",
        "t1_strigon",
    )
    for prefix in ("", "v10_"):
        for stem in stems:
            image = (_CORPUS / f"{prefix}{stem}.exe").read_bytes()
            program = decode(image)
            actual = [
                (node.kind, node.operands)
                for node in program.canonical_statements
                if node.kind == "TrapCtl"
            ]
            exact = [
                _tbx_statement(node)
                for node in decode0.decode_user_code(image)
                if isinstance(node, tbx_ir.TrapCtl)
            ]
            assert actual == exact


def test_numbered_trap_control_requires_its_ax_literal():
    program = decode(bytes.fromhex("cd ec 20"))

    assert not any(fact.kind == "semantic.trap_ctl" for fact in program.facts)


def test_on_trap_facts_preserve_event_number_and_target():
    stems = ("t1_oncom", "t1_onkey", "t1_onpen", "t1_onplay", "t1_ontimer")
    for prefix in ("", "v10_"):
        for stem in stems:
            image = (_CORPUS / f"{prefix}{stem}.exe").read_bytes()
            program = decode(image)
            actual = [
                (node.kind, node.operands)
                for node in program.canonical_statements
                if node.kind == "OnTrap"
            ]
            exact = [
                _tbx_statement(node)
                for node in decode0.decode_user_code(image)
                if isinstance(node, tbx_ir.OnTrap)
            ]
            assert actual == exact


def test_numbered_on_trap_requires_its_complete_operand_source():
    com = decode(bytes.fromhex("cd ec 76 00 00 00 00"))
    timer = decode(bytes.fromhex("cd ec 80 00 00 00 00"))

    assert not any(fact.kind == "semantic.on_trap" for fact in com.facts)
    assert not any(fact.kind == "semantic.on_trap" for fact in timer.facts)


def test_runtime_facts_recover_complete_field_descriptors():
    for prefix in ("", "v10_"):
        image = (_CORPUS / f"{prefix}t1_field.exe").read_bytes()
        program = decode(image)
        actual = [
            (node.kind, node.operands) for node in program.canonical_statements
        ]
        exact = [
            _tbx_statement(node) for node in decode0.decode_user_code(image)
        ]
        assert actual == exact
        field = next(item for item in program.facts if item.kind == "semantic.field")
        assert field.confidence == "anchored"

    incomplete = decode(bytes.fromhex("c7 06 60 00 01 00 cd ec 3e b8 0a 00"))
    assert not any(fact.kind == "semantic.field" for fact in incomplete.facts)


def test_device_io_facts_recover_complete_out_scaffolds():
    expected = [
        ("Out", (("const", 888), ("const", 1))),
        ("End", ()),
    ]
    for prefix in ("", "v10_"):
        program = decode((_CORPUS / f"{prefix}t1_out.exe").read_bytes())
        actual = [
            (statement.kind, statement.operands)
            for statement in program.canonical_statements
        ]
        exact = [
            _tbx_statement(statement)
            for statement in decode0.decode_user_code(
                (_CORPUS / f"{prefix}t1_out.exe").read_bytes()
            )
        ]

        assert actual == exact == expected
        out = next(fact for fact in program.facts if fact.kind == "semantic.out")
        assert out.confidence == "signature"
        assert len(out.evidence) == 5

    for prefix in ("", "v10_"):
        image = (_CORPUS / f"{prefix}t1_out2.exe").read_bytes()
        program = decode(image)

        assert [
            (statement.kind, statement.operands)
            for statement in program.canonical_statements
        ] == [
            _tbx_statement(statement)
            for statement in decode0.decode_user_code(image)
        ]
        out = next(fact for fact in program.facts if fact.kind == "semantic.out")
        assert out.value == (
            ("const", 888),
            ("slot", "V0001", 0x120, "integer"),
        )


def test_device_io_facts_leave_incomplete_or_altered_out_structural():
    complete = bytes.fromhex("b8 78 03 89 c3 b8 01 00 8b d3 ee")
    truncated = decode(complete[:-1])
    altered = decode(complete[:3] + b"\x89\xc1" + complete[5:])

    assert not any(fact.kind == "semantic.out" for fact in truncated.facts)
    assert not any(fact.kind == "semantic.out" for fact in altered.facts)
    assert truncated.canonical_statements == altered.canonical_statements == ()


def test_device_io_facts_recover_complete_three_argument_wait():
    expected = [
        ("Wait", (("const", 986), ("const", 8), ("const", 4))),
        ("End", ()),
    ]
    for prefix in ("", "v10_"):
        image = (_CORPUS / f"{prefix}t1_wait3.exe").read_bytes()
        program = decode(image)
        actual = [
            (statement.kind, statement.operands)
            for statement in program.canonical_statements
        ]
        exact = [
            _tbx_statement(statement)
            for statement in decode0.decode_user_code(image)
        ]

        assert actual == exact == expected
        wait = next(fact for fact in program.facts if fact.kind == "semantic.wait")
        assert wait.confidence == "signature"
        assert len(wait.evidence) == 11

    for prefix in ("", "v10_"):
        image = (_CORPUS / f"{prefix}t1_wait.exe").read_bytes()
        program = decode(image)

        assert [
            (statement.kind, statement.operands)
            for statement in program.canonical_statements
        ] == [
            _tbx_statement(statement)
            for statement in decode0.decode_user_code(image)
        ]
        wait = next(fact for fact in program.facts if fact.kind == "semantic.wait")
        assert wait.value == (("const", 888), ("const", 1))
        assert len(wait.evidence) == 7


def test_device_io_facts_leave_unverified_or_incomplete_wait_structural():
    complete = bytes.fromhex(
        "b8 08 00 89 c3 b8 04 00 89 d9 89 c3 b8 da 03 8b d0 "
        "ec 30 d8 20 c8 74 f9"
    )
    truncated = decode(complete[:-1])
    altered = decode(complete[:18] + b"\x30\xc8" + complete[20:])

    assert not any(fact.kind == "semantic.wait" for fact in truncated.facts)
    assert not any(fact.kind == "semantic.wait" for fact in altered.facts)
    assert truncated.canonical_statements == altered.canonical_statements == ()


def test_fact_operation_view_matches_migrated_legacy_operations():
    for stem in ("t1_addimm", "t1_print", "t1_if"):
        program = decode((_CORPUS / f"{stem}.exe").read_bytes())
        migrated_kinds = {
            "ir.assign", "ir.print", "ir.if_goto", "ir.delay", "tb.statement"
        }
        legacy = [
            (node.offset, node.end, node.kind, node.operands)
            for node in program.operations
            if node.kind in migrated_kinds
        ]
        facts = [
            (node.offset, node.end, node.kind, node.operands)
            for node in program.fact_operations
        ]
        assert facts == legacy
        assert all(node.raw for node in program.fact_operations)


def test_branch_pair_pass_lifts_source_conditions_and_true_targets():
    program = decode((_CORPUS / "t1_if.exe").read_bytes())
    conditions = [node.operands for node in program.operations if node.kind == "ir.if_goto"]

    assert conditions == [
        (">=", ("slot", "V0003", 0x128), ("slot", "V0002", 0x124, "float"), 0x8738, 0x872C),
        ("=", ("slot", "V0003", 0x128), ("slot", "V0002", 0x124, "float"), 0x875A, 0x874B),
    ]


def test_control_facts_match_legacy_branches_and_if_gotos():
    delay = decode((_CORPUS / "t1_delay.exe").read_bytes())
    conditional = decode((_CORPUS / "t1_if.exe").read_bytes())

    legacy_branch = next(node for node in delay.operations if node.kind == "flow.branch")
    fact_branch = next(fact for fact in delay.facts if fact.kind == "flow.branch")
    assert fact_branch.subject == (legacy_branch.offset, legacy_branch.end)
    assert fact_branch.value == legacy_branch.operands

    legacy_ifs = [
        node for node in conditional.operations if node.kind == "ir.if_goto"
    ]
    fact_ifs = [
        fact for fact in conditional.facts if fact.kind == "semantic.if_goto"
    ]
    assert [fact.value for fact in fact_ifs] == [node.operands for node in legacy_ifs]
    assert [fact.subject for fact in fact_ifs] == [
        (node.offset, node.end) for node in legacy_ifs
    ]
    migrated = [node for node in conditional.fact_operations if node.kind == "ir.if_goto"]
    assert [
        (node.offset, node.end, node.operands) for node in migrated
    ] == [
        (node.offset, node.end, node.operands) for node in legacy_ifs
    ]


def test_source_subroutine_facts_match_near_gosub_and_return_trees():
    for prefix in ("", "v10_"):
        image = (_CORPUS / f"{prefix}t1_gosub.exe").read_bytes()
        exact = [_tbx_statement(node) for node in decode0.decode_user_code(image)]
        program = decode(image)
        migrated = [
            (node.kind, node.operands) for node in program.canonical_statements
        ]

        assert migrated == exact
        assert [
            fact.kind
            for fact in program.facts
            if fact.kind in {"semantic.gosub", "semantic.return"}
        ] == ["semantic.gosub", "semantic.return"]


def test_checked_gosub_and_return_are_complete_profile_instructions():
    image = (_CORPUS / "fst_t1_gosub.exe").read_bytes()
    exact = [_tbx_statement(node) for node in decode0.decode_user_code(image)]
    program = decode(image)

    assert [
        (node.kind, node.operands) for node in program.canonical_statements
    ] == exact
    checked = [
        (node.offset, node.end, node.kind, node.operands)
        for node in program.instructions
        if node.kind.startswith("tb.checked")
    ]
    assert checked == [
        (0x870D, 0x8713, "tb.checked_gosub", (0x8722,)),
        (0x872E, 0x8730, "tb.checked_return", ()),
    ]


def test_checked_call_payload_must_be_complete_and_in_user_code():
    complete = {
        "1.1": bytes.fromhex("cd 8a 00 00 00 00"),
        "1.0": bytes.fromhex("cd 84 00 00 00 00"),
    }
    for dialect, image in complete.items():
        instruction = decode_instruction(image, 0, len(image), 0, dialect)
        truncated = decode_instruction(image, 0, len(image) - 1, 0, dialect)

        assert (instruction.kind, instruction.size, instruction.operands) == (
            "tb.checked_gosub", 6, (0,)
        )
        assert (truncated.kind, truncated.size, truncated.confidence) == (
            "tb.checked_call_truncated", 2, "structural"
        )

    helper = decode_instruction(
        bytes.fromhex("cd 8a ff ff ff 7f"), 0, 6, 0, "1.1"
    )
    assert (helper.kind, helper.size, helper.confidence) == (
        "tb.checked_call_runtime", 6, "signature"
    )
    raw = decode_instruction(complete["1.1"], 0, 6, 0, None)
    assert (raw.kind, raw.size, raw.operands) == ("tb.runtime", 2, (0x8A,))


def test_profile_stack_checks_do_not_become_error_statements():
    expected = {
        "fst_t1_stsub": (0x8734, 0x8740, 0x020E),
        "v10_fst_t1_stsub": (0x70E4, 0x70F0, 0x020E),
    }
    for stem, (start, end, threshold) in expected.items():
        program = decode((_CORPUS / f"{stem}.exe").read_bytes())
        check = next(
            instruction
            for instruction in program.instructions
            if instruction.kind == "tb.stack_check"
        )

        assert (check.offset, check.end, check.operands) == (
            start, end, (threshold,)
        )
        assert not any(
            node.kind == "ErrorStmt" for node in program.canonical_statements
        )

    for stem in ("t1_errorn", "v10_t1_errorn"):
        program = decode((_CORPUS / f"{stem}.exe").read_bytes())
        assert [node.kind for node in program.canonical_statements] == [
            "ErrorStmt", "End"
        ]


def test_incomplete_or_unprofiled_stack_check_stays_structural():
    complete = bytes.fromhex("81 fc 0e 02 73 06 b8 07 00 cd ec 3c")
    profiled = decode_instruction(complete, 0, len(complete), 0, "1.1")
    truncated = decode_instruction(complete, 0, len(complete) - 1, 0, "1.1")
    raw = decode_instruction(complete, 0, len(complete), 0, None)

    assert (profiled.kind, profiled.size, profiled.operands) == (
        "tb.stack_check", 12, (0x020E,)
    )
    assert truncated.kind == raw.kind == "x86.op_81"


def test_computed_call_tables_discover_every_return_target():
    for prefix, targets in (
        ("", (0x872E, 0x872F)),
        ("v10_", (0x70DE, 0x70DF)),
    ):
        program = decode((_CORPUS / f"{prefix}t1_ongosub.exe").read_bytes())
        calls = {xref.target for xref in program.xrefs if xref.kind == "call"}

        assert calls == set(targets)
        assert [node.kind for node in program.canonical_statements] == [
            "Assign", "OnGosub", "End", "Return", "Return"
        ]
        exact = decode0.decode_user_code(
            (_CORPUS / f"{prefix}t1_ongosub.exe").read_bytes()
        )
        assert (
            program.canonical_statements[1].kind,
            program.canonical_statements[1].operands,
        ) == _tbx_statement(exact[1])


def test_computed_dispatch_and_file_run_match_tbx_in_both_dialects():
    for prefix in ("", "v10_"):
        for stem, kind in (
            ("t1_ongoto", "OnGoto"),
            ("t1_ongosub", "OnGosub"),
            ("t1_run2", "Run"),
        ):
            image = (_CORPUS / f"{prefix}{stem}.exe").read_bytes()
            exact = decode0.decode_user_code(image)
            expected = next(node for node in exact if type(node).__name__ == kind)
            actual = next(
                node for node in decode(image).canonical_statements if node.kind == kind
            )

            assert (actual.kind, actual.operands) == _tbx_statement(expected)


def test_control_operands_require_complete_compiler_scaffolds():
    missing_selector = decode(bytes.fromhex("cd ec 74 01 00 00 00 00 00"))
    missing_file = decode(bytes.fromhex("cd ec c4"))

    assert not any(
        fact.kind == "semantic.on_goto" for fact in missing_selector.facts
    )
    assert not any(fact.kind == "semantic.run" for fact in missing_file.facts)
    assert missing_selector.canonical_statements == missing_file.canonical_statements == ()


def test_profile_run_jumps_retain_the_compiled_fallthrough():
    expected = {
        "t1_run": (0x8703, 0x8705, 0x8700),
        "v10_t1_run": (0x70B3, 0x70B6, 0x70B3),
    }
    for stem, (start, end, target) in expected.items():
        image = (_CORPUS / f"{stem}.exe").read_bytes()
        exact = [type(node).__name__ for node in decode0.decode_user_code(image)]
        program = decode(image)
        run = next(node for node in program.instructions if node.kind == "tb.run")

        assert [node.kind for node in program.canonical_statements] == exact
        assert (run.offset, run.end, run.operands) == (start, end, (target,))
        assert any(
            xref.kind == "orphan" and xref.source == start and xref.target == end
            for xref in program.xrefs
        )

    far = decode((_CORPUS / "t1_runfar.exe").read_bytes())
    assert [node.kind for node in far.canonical_statements[-2:]] == ["Run", "End"]


def test_defseg_facts_recover_set_and_reset_forms_in_both_dialects():
    expected_instructions = {
        "t1_defseg": [
            (0x8706, "tb.statement", ("DEF_SEG", 0x26)),
            (0x8718, "tb.defseg_reset", ()),
        ],
        "v10_t1_defseg": [
            (0x70B3, "tb.defseg_set", (0,)),
            (0x70C6, "tb.defseg_reset", ()),
        ],
    }
    for stem, expected in expected_instructions.items():
        image = (_CORPUS / f"{stem}.exe").read_bytes()
        exact = [
            _tbx_statement(node)
            for node in decode0.decode_user_code(image)
            if isinstance(node, tbx_ir.DefSeg)
        ]
        program = decode(image)
        actual = [
            (node.kind, node.operands)
            for node in program.canonical_statements
            if node.kind == "DefSeg"
        ]
        instructions = [
            (node.offset, node.kind, node.operands)
            for node in program.instructions
            if node.kind in {"tb.statement", "tb.defseg_set", "tb.defseg_reset"}
            and (
                node.kind != "tb.statement"
                or node.operands[:2] == ("DEF_SEG", 0x26)
            )
        ]

        assert actual == exact == [("DefSeg", (("const", 0),)), ("DefSeg", ())]
        assert instructions == expected

    v10_bload = decode((_CORPUS / "v10_t1_bload0.exe").read_bytes())
    assert v10_bload.canonical_statements[0].operands == (("const", 100),)


def test_unprofiled_or_truncated_defseg_bytes_remain_structural():
    inline = bytes.fromhex("c7 06 1c 00 64 00")
    reset = bytes.fromhex("8c 1e 1c 00")

    raw_inline = decode_instruction(inline, 0, len(inline), 0, None)
    old_inline = decode_instruction(inline, 0, len(inline), 0, "1.0")
    new_inline = decode_instruction(inline, 0, len(inline), 0, "1.1")
    truncated = decode_instruction(inline, 0, len(inline) - 1, 0, "1.0")
    profiled_reset = decode_instruction(reset, 0, len(reset), 0, "1.1")

    assert raw_inline.kind == new_inline.kind == truncated.kind == "x86.mov"
    assert (old_inline.kind, old_inline.operands) == ("tb.defseg_set", (100,))
    assert (profiled_reset.kind, profiled_reset.operands) == (
        "tb.defseg_reset", ()
    )


def test_procedure_returns_do_not_become_source_returns():
    program = decode((_CORPUS / "t1_subgsb.exe").read_bytes())

    controls = [
        (instruction.offset, instruction.kind, instruction.operands)
        for instruction in program.instructions
        if instruction.kind.startswith("tb.proc")
    ]
    returns = [fact for fact in program.facts if fact.kind == "semantic.return"]
    assert controls == [
        (0x8706, "tb.proc_enter", ()),
        (0x8719, "tb.proc_return", (0,)),
    ]
    assert [fact.subject for fact in returns] == [(0x8718, 0x8719)]


def test_framed_procedure_facts_nest_bodies_and_name_calls():
    for stem in ("t1_subdef", "v10_subdef"):
        image = (_CORPUS / f"{stem}.exe").read_bytes()
        exact_kinds = [type(node).__name__ for node in decode0.decode_user_code(image)]
        program = decode(image)

        assert [node.kind for node in program.canonical_statements] == exact_kinds
        definition = program.canonical_statements[0]
        assert definition.kind == "SubDef"
        assert definition.operands[0:2] == ("SUB1", ())
        assert [node.kind for node in definition.operands[2]] == ["Assign", "Print"]
        assert [node.operands[0] for node in program.canonical_statements[2:4]] == [
            "SUB1",
            "SUB1",
        ]


def test_fallthrough_into_trailing_sub_declarations_is_discovered():
    expected = {
        "t1_declnoend": ["Assign", "SubDef", "Print"],
        "v10_t1_declnoend": ["Assign", "SubDef", "Print"],
        "t1_gotosubline": [
            "Assign", "IfGoto", "Print", "SubDef", "Print", "End"
        ],
    }
    for stem, kinds in expected.items():
        program = decode((_CORPUS / f"{stem}.exe").read_bytes())

        assert [node.kind for node in program.canonical_statements] == kinds
        definition = next(
            node for node in program.canonical_statements if node.kind == "SubDef"
        )
        declaration = next(
            instruction.offset
            for instruction in program.instructions
            if instruction.kind == "x86.jmp"
            and instruction.end
            == next(
                entered.offset
                for entered in program.instructions
                if entered.kind == "tb.proc_enter"
            )
        )
        assert definition.address == declaration
        assert any(
            xref.source == declaration
            and xref.target == declaration + 3
            and xref.kind == "orphan"
            for xref in program.xrefs
        )
        if stem == "t1_gotosubline":
            exact = next(
                _tbx_statement(node)
                for node in decode0.decode_user_code(
                    (_CORPUS / f"{stem}.exe").read_bytes()
                )
                if isinstance(node, tbx_ir.IfGoto)
            )
            actual = next(
                (node.kind, node.operands)
                for node in program.canonical_statements
                if node.kind == "IfGoto"
            )
            assert actual == exact


def test_procedure_frame_uncertainty_stays_explicit_across_nested_calls():
    program = decode((_CORPUS / "t1_argrefonly.exe").read_bytes())

    assert [node.kind for node in program.canonical_statements] == [
        "CallStmt", "End", "SubDef", "SubDef"
    ]
    first, second = program.canonical_statements[2:]
    nested_call = first.operands[2][0]
    assert nested_call.operands == (
        "SUB2",
        ("unresolved-call-arguments", 4),
    )
    assert second.operands[:2] == ("SUB2", ("unresolved-frame", 4))
    assert any(
        fact.kind == "semantic.sub_def"
        and fact.evidence == (0x870B, 0x870E, 0x871B)
        for fact in program.facts
    )


def test_incomplete_procedure_frame_does_not_invent_definition_or_call():
    program = decode(bytes.fromhex("55 8b ec 9a 00 00 00 00"))

    assert any(node.kind == "tb.proc_enter" for node in program.instructions)
    assert not any(
        fact.kind in {"semantic.sub_def", "semantic.call"}
        for fact in program.facts
    )


def test_bracketed_inline_procedures_preserve_opaque_body_bytes():
    expected = {
        "t1_inline": (
            ["SubDef", "CallStmt", "End"],
            "ba0007e46124fc3402e661b94001e2fe4a7402ebf2",
        ),
        "v10_t1_inline": (
            ["SubDef", "CallStmt", "End"],
            "ba0007e46124fc3402e661b94001e2fe4a7402ebf2",
        ),
        "t1_inlinefile": (
            ["SubDef", "Print", "CallStmt", "End"],
            "48454c4c4f0a",
        ),
    }
    for stem, (kinds, body_hex) in expected.items():
        image = (_CORPUS / f"{stem}.exe").read_bytes()
        program = decode(image)
        definition = program.canonical_statements[0]
        call = program.canonical_statements[-2]

        assert [node.kind for node in program.canonical_statements] == kinds
        assert definition.kind == "SubDef"
        assert definition.operands[:2] == ("SUB1", ())
        assert [node.kind for node in definition.operands[2]] == ["Inline"]
        assert definition.operands[2][0].operands == (body_hex,)
        assert call.kind == "CallStmt"
        assert call.operands == ("SUB1", ())
        assert not any(
            fact.kind in {"semantic.gosub", "semantic.return"}
            for fact in program.facts
        )


def test_all_authored_inline_bodies_override_frame_shaped_bytes():
    stems = (
        "t1_fwdinline", "v10_t1_fwdinline",
        "t1_inline", "v10_t1_inline",
        "t1_inlinebp", "v10_t1_inlinebp",
        "t1_inlinedata", "v10_t1_inlinedata",
        "t1_inlinefile",
        "t1_inlineport",
        "t1_inlinethendef", "v10_t1_inlinethendef",
    )
    for stem in stems:
        image = (_CORPUS / f"{stem}.exe").read_bytes()
        exact = decode0.decode_user_code(image)
        expected = [
            statement.data.hex()
            for definition in exact
            if isinstance(definition, tbx_ir.SubDef)
            for statement in definition.body
            if isinstance(statement, tbx_ir.Inline)
        ]
        program = decode(image)
        actual = [
            statement.operands[0]
            for definition in program.canonical_statements
            if definition.kind == "SubDef"
            for statement in definition.operands[2]
            if statement.kind == "Inline"
        ]

        assert actual == expected


def test_returns_with_stack_pops_do_not_become_source_return():
    raw = decode(bytes.fromhex("c2 01 b8"))
    assert not any(fact.kind == "semantic.return" for fact in raw.facts)

    for stem in ("fbd_t1_dimm", "v10_t1_mix", "v10_t1_mix2", "v10_t1_mix3"):
        program = decode((_CORPUS / f"{stem}.exe").read_bytes())
        assert not any(node.kind == "Return" for node in program.canonical_statements)


def test_far_call_to_nonprocedure_target_is_an_event_safe_gosub():
    program = decode((_CORPUS / "t1_fargosub.exe").read_bytes())
    gosub = next(fact for fact in program.facts if fact.kind == "semantic.gosub")

    assert gosub.subject == (0x8856, 0x885B)
    assert gosub.value == (0x8875,)


def test_targeted_event_returns_are_single_profiled_instructions():
    expected = {
        "": (0x885E, 0x8862, 0x8855),
        "v10_": (0x720E, 0x7212, 0x7205),
    }
    for prefix, (start, end, target) in expected.items():
        image = (_CORPUS / f"{prefix}t1_returnline.exe").read_bytes()
        exact = [_tbx_statement(node) for node in decode0.decode_user_code(image)]
        program = decode(image)
        instruction = next(
            node for node in program.instructions if node.kind == "tb.return_to"
        )
        returned = next(
            fact for fact in program.facts
            if fact.kind == "semantic.return" and fact.value
        )

        assert (instruction.offset, instruction.end, instruction.operands) == (
            start,
            end,
            (target,),
        )
        assert returned.subject == (start, end)
        assert program.canonical_statements[-1].operands == exact[-1][1]


def test_gosub_stack_unwind_pairs_recover_targeted_returns():
    program = decode((_CORPUS / "t1_returngosub.exe").read_bytes())
    returns = [
        fact for fact in program.facts
        if fact.kind == "semantic.return" and fact.value
    ]

    assert [(fact.subject, fact.value) for fact in returns] == [
        ((0x8864, 0x8869), (0x8847,)),
        ((0x8869, 0x886E), (0x8850,)),
    ]
    assert all(len(fact.evidence) == 2 for fact in returns)


def test_resume_facts_recover_all_complete_tail_forms_in_both_dialects():
    for prefix in ("", "v10_"):
        for stem in ("t1_onerr", "t1_resumen", "t1_resumel"):
            image = (_CORPUS / f"{prefix}{stem}.exe").read_bytes()
            expected = next(
                _tbx_statement(node)
                for node in decode0.decode_user_code(image)
                if isinstance(node, tbx_ir.Resume)
            )
            program = decode(image)
            actual = next(
                (node.kind, node.operands)
                for node in program.canonical_statements
                if node.kind == "Resume"
            )
            fact = next(
                fact for fact in program.facts if fact.kind == "semantic.resume"
            )

            assert actual == expected
            assert len(fact.evidence) == 2
            assert fact.subject[0] == fact.evidence[0]

    for prefix in ("", "v10_"):
        program = decode((_CORPUS / f"{prefix}t1_resumestart.exe").read_bytes())
        resumes = [
            node for node in program.canonical_statements if node.kind == "Resume"
        ]

        assert [node.operands for node in resumes] == [(0,)]
        assert not any(node.kind == "Run" for node in program.canonical_statements)


def test_targeted_resume_retains_compiled_fallthrough_source():
    image = (_CORPUS / "t1_resumefar.exe").read_bytes()
    exact = decode0.decode_user_code(image)
    program = decode(image)

    assert [node.kind for node in program.canonical_statements] == [
        type(node).__name__ for node in exact
    ]
    expected_resume = next(
        _tbx_statement(node) for node in exact if isinstance(node, tbx_ir.Resume)
    )
    actual_resume = next(
        (node.kind, node.operands)
        for node in program.canonical_statements
        if node.kind == "Resume"
    )
    assert actual_resume == expected_resume
    assert any(
        xref.kind == "orphan" and xref.source == 0x8716 and xref.target == 0x871B
        for xref in program.xrefs
    )


def test_incomplete_resume_prefix_does_not_invent_a_statement():
    for image in (
        bytes.fromhex("cd ec bc"),
        bytes.fromhex("cd ec bc cd ec 32"),
    ):
        program = decode(image)

        assert not any(fact.kind == "semantic.resume" for fact in program.facts)
        assert not any(node.kind == "Resume" for node in program.canonical_statements)


def test_incomplete_stack_unwind_does_not_invent_a_return():
    program = decode(bytes.fromhex("83 c4 02"))

    assert not any(fact.kind == "semantic.return" for fact in program.facts)


def test_profile_trace_hooks_consume_the_embedded_line_word():
    complete = {
        "1.1": bytes.fromhex("cd 97 14 00"),
        "1.0": bytes.fromhex("cd 91 14 00"),
    }
    for dialect, image in complete.items():
        instruction = decode_instruction(image, 0, len(image), 0, dialect)
        truncated = decode_instruction(image, 0, len(image) - 1, 0, dialect)

        assert (instruction.kind, instruction.size, instruction.operands) == (
            "tb.trace", 4, (20,)
        )
        assert truncated.kind == "tb.runtime"
        assert truncated.size == 2


def test_profile_dispatches_consume_complete_inline_payloads():
    cases = {
        "1.1": (bytes.fromhex("cd ec 12 08"), 0x12),
        "1.0": (bytes.fromhex("cd ec 12 08"), 0x12),
    }
    for dialect, (image, canonical_sub) in cases.items():
        instruction = decode_instruction(image, 0, len(image), 0, dialect)
        truncated = decode_instruction(image, 0, len(image) - 1, 0, dialect)

        assert (instruction.kind, instruction.size, instruction.operands) == (
            "tb.statement", 4, ("CIRCLE", canonical_sub, 8)
        )
        assert (truncated.kind, truncated.size, truncated.confidence) == (
            "tb.dispatch_truncated", 3, "structural"
        )


def test_profile_target_dispatches_require_the_complete_signature():
    cases = {
        "1.1": bytes.fromhex("cd ec 70 34 12 00 00"),
        "1.0": bytes.fromhex("cd ec 6e 34 12 00 00"),
    }
    for dialect, image in cases.items():
        instruction = decode_instruction(image, 0, len(image), 0x8000, dialect)
        truncated = decode_instruction(image, 0, len(image) - 1, 0x8000, dialect)

        assert (instruction.kind, instruction.size, instruction.operands) == (
            "tb.statement", 7, ("ON_ERROR", 0x70, 0x9234)
        )
        assert (truncated.kind, truncated.size, truncated.confidence) == (
            "tb.dispatch_truncated", 3, "structural"
        )


def test_profile_target_tables_are_one_complete_dispatch_instruction():
    cases = {
        "1.1": bytes.fromhex("cd ec 74 02 00 10 00 00 00 20 00 00 00"),
        "1.0": bytes.fromhex("cd ec 72 02 00 10 00 00 00 20 00 00 00"),
    }
    for dialect, image in cases.items():
        instruction = decode_instruction(image, 0, len(image), 0x8000, dialect)
        truncated = decode_instruction(image, 0, len(image) - 1, 0x8000, dialect)

        assert (instruction.kind, instruction.size, instruction.operands) == (
            "tb.statement", 13, ("ON_GOTO", 0x74, 0x8010, 0x8020)
        )
        assert (truncated.kind, truncated.size, truncated.confidence) == (
            "tb.dispatch_truncated", 3, "structural"
        )


def test_runtime_statement_phases_remain_signature_evidence_only():
    program = decode(bytes.fromhex("cd ec 2c cd ec 2e cd ec 9a"))

    signatures = {
        fact.value[1][0]
        for fact in program.facts
        if fact.kind == "signature" and fact.value[0] == "tb.statement"
    }
    assert {"DIM_BEGIN", "DIM_END", "READ_NUMBER"} <= signatures
    assert not any(fact.kind == "semantic.statement" for fact in program.facts)
    assert program.canonical_statements == ()


def test_trace_region_facts_recover_repeated_runs_in_both_dialects():
    expected = {
        "": (0x8793, 0x87A1, 0x87BD),
        "v10_": (0x7143, 0x7151, 0x716D),
    }
    for prefix, addresses in expected.items():
        program = decode((_CORPUS / f"{prefix}t1_tron2r2.exe").read_bytes())
        toggles = [
            fact for fact in program.facts
            if fact.kind in {"semantic.tron", "semantic.troff"}
        ]

        assert [(fact.kind, fact.subject[0]) for fact in toggles] == [
            ("semantic.troff", addresses[1]),
            ("semantic.tron", addresses[0]),
            ("semantic.tron", addresses[2]),
        ]
        assert [
            statement.kind
            for statement in program.canonical_statements
            if statement.kind in {"Tron", "Troff"}
        ] == ["Tron", "Troff", "Tron"]


def test_trace_regions_use_complete_handler_statements_without_guessing_loops():
    for prefix in ("", "v10_"):
        loop = decode((_CORPUS / f"{prefix}t1_tronfor.exe").read_bytes())
        ambiguous = decode((_CORPUS / f"{prefix}t1_tronerr.exe").read_bytes())

        assert [
            statement.kind
            for statement in loop.canonical_statements
            if statement.kind in {"Tron", "Troff"}
        ] == ["Tron"]
        assert [
            statement.kind
            for statement in ambiguous.canonical_statements
            if statement.kind in {"Tron", "Troff"}
        ] == ["Tron", "Troff"]


def test_final_trace_hook_ignores_control_inside_the_traced_region():
    for prefix in ("", "v10_"):
        program = decode((_CORPUS / f"{prefix}t1_tronerb.exe").read_bytes())
        nested = decode((_CORPUS / f"{prefix}t1_troffin.exe").read_bytes())

        assert [
            statement.kind
            for statement in program.canonical_statements
            if statement.kind in {"Tron", "Troff"}
        ] == ["Tron", "Troff"]
        troff = next(
            fact for fact in program.facts if fact.kind == "semantic.troff"
        )
        assert troff.confidence == "signature"
        assert len(troff.evidence) > 1
        assert [
            statement.kind
            for statement in nested.canonical_statements
            if statement.kind in {"Tron", "Troff"}
        ] == ["Tron"]


def test_independent_trace_support_materializes_one_toggle_statement():
    program = decode((_CORPUS / "t1_tronsplit.exe").read_bytes())

    troff_facts = [fact for fact in program.facts if fact.kind == "semantic.troff"]
    assert len(troff_facts) == 2
    assert len({fact.subject for fact in troff_facts}) == 1
    assert sum(node.kind == "ir.troff" for node in program.fact_operations) == 1
    assert sum(node.kind == "Troff" for node in program.canonical_statements) == 1


def test_if_goto_facts_require_the_complete_runtime_branch_pair():
    incomplete = decode(bytes.fromhex("cd35062001 cd341e2401 cd99 cd87 7503"))

    assert any(fact.kind == "expression.compare" for fact in incomplete.facts)
    assert not any(fact.kind == "semantic.if_goto" for fact in incomplete.facts)


def test_fact_operation_shapes_are_compared_with_tbx_ir():
    for stem in ("t1_addimm", "t1_print", "t1_if", "t1_delay"):
        image = (_CORPUS / f"{stem}.exe").read_bytes()
        exact = [type(node).__name__ for node in decode0.decode_user_code(image)]
        migrated = [node.kind for node in decode(image).fact_statements]
        assert migrated == exact


def test_canonical_fact_ir_matches_tbx_trees():
    for stem in ("t1_addimm", "t1_print", "t1_if", "t1_delay"):
        image = (_CORPUS / f"{stem}.exe").read_bytes()
        exact = [_tbx_statement(node) for node in decode0.decode_user_code(image)]
        migrated = [
            (node.kind, node.operands) for node in decode(image).canonical_statements
        ]
        assert migrated == exact


def test_canonicalization_is_a_non_destructive_final_view():
    slot = ("slot", "V0001", 0x120)
    source = (
        Statement(0, 0x10, "Assign", (slot, ("binary", "+", ("const", 1), slot))),
    )

    result = canonicalize(source, (Slot(0x120, "V0001", ("integer",)),))

    assert source[0].operands[1][2] == ("const", 1)
    assert result[0].operands == (
        ("var", "A%"),
        ("binary", "+", ("var", "A%"), ("const", 1)),
    )


def test_canonicalization_preserves_string_concat_order():
    left = ("slot", "V0002", 0x124, "string")
    right = ("slot", "V0001", 0x120, "string")
    source = (Statement(0, 0x10, "Assign", (left, ("binary", "+", left, right))),)

    result = canonicalize(
        source,
        (Slot(0x120, "V0001", ("string",)), Slot(0x124, "V0002", ("string",))),
    )

    assert result[0].operands == (
        ("var", "A$"),
        ("binary", "+", ("var", "A$"), ("var", "B$")),
    )


def test_canonicalization_uses_anchored_slot_types_without_a_typed_read():
    program = decode((_CORPUS / "t1_meta0.exe").read_bytes())

    slot = next(fact for fact in program.facts if fact.kind == "slot")
    assert slot.value == ("V0001", ("integer",))
    assert program.fact_statements[0].operands[0] == ("slot", "V0001", 0x120)
    assert program.canonical_statements[0].operands[0] == ("var", "A%")


def test_statement_facts_match_the_legacy_statement_view():
    for stem in ("t1_addimm", "t1_print", "t1_if", "t1_delay"):
        program = decode((_CORPUS / f"{stem}.exe").read_bytes())
        assert program.fact_statements == program.statements


def test_delay_fact_requires_the_complete_loop_shape():
    incomplete = decode(bytes.fromhex("cd35e8 cdec28 cdec2a cd87"))

    assert any(fact.kind == "expression.value" for fact in incomplete.facts)
    assert not any(fact.kind == "semantic.delay" for fact in incomplete.facts)
    assert incomplete.fact_statements == ()


def test_statement_pass_recovers_boundaries_and_resolves_targets():
    arithmetic = decode((_CORPUS / "t1_addimm.exe").read_bytes())
    conditional = decode((_CORPUS / "t1_if.exe").read_bytes())
    delay = decode((_CORPUS / "t1_delay.exe").read_bytes())

    assert [node.kind for node in arithmetic.statements] == [
        "Assign", "Assign", "Print", "End"
    ]
    assert [node.kind for node in conditional.statements] == [
        "Assign", "Assign", "IfGoto", "Assign", "IfGoto", "Assign", "End"
    ]
    assert conditional.statements[2].operands[-1] == 4
    assert conditional.statements[4].operands[-1] == 6
    assert [(node.kind, node.operands) for node in delay.statements] == [
        ("Delay", (("const", 1),)),
        ("End", ()),
    ]


def test_empty_truncated_and_limited_images_still_return_programs():
    empty = decode(b"")
    truncated = decode(b"MZ\x01")
    limited = decode(b"\x90" * 20, max_bytes=4)

    assert empty.instructions == ()
    assert truncated.format == "mz"
    assert len(limited.instructions) == 4
    assert any("limited" in item.message for item in limited.diagnostics)


def test_cli_hides_instructions_unless_requested(tmp_path, capsys):
    binary = tmp_path / "unknown.bin"
    binary.write_bytes(b"\xcc")

    assert cli.main([str(binary)]) == 0
    compact = json.loads(capsys.readouterr().out)
    assert "instructions" not in compact
    assert "facts" not in compact
    assert "fact_statements" not in compact
    assert "canonical_statements" not in compact

    assert cli.main([str(binary), "--instructions"]) == 0
    detailed = json.loads(capsys.readouterr().out)
    assert detailed["instructions"][0]["kind"] == "x86.int3"

    assert cli.main([str(binary), "--facts"]) == 0
    evidence = json.loads(capsys.readouterr().out)
    assert evidence["facts"][0]["evidence"] == [0]


def test_cli_text_can_be_written_to_a_file(tmp_path):
    binary = tmp_path / "unknown.bin"
    output = tmp_path / "unknown.ir"
    binary.write_bytes(b"\x90")

    assert cli.main([str(binary), "--text", "-o", str(output)]) == 0
    assert output.read_text().startswith("program format=raw")


def _tbx_statement(node):
    if isinstance(node, tbx_ir.Assign):
        operands = _tbx_expression(node.target), _tbx_expression(node.value)
    elif isinstance(node, tbx_ir.Dim):
        operands = (
            node.name,
            tuple(_tbx_bound(value) for value in node.bounds),
            tuple(
                (name, tuple(_tbx_bound(value) for value in bounds))
                for name, bounds in node.also
            ),
            node.dynamic,
        )
    elif isinstance(node, tbx_ir.Print):
        operands = (
            "console" if node.file is None else node.file,
            tuple(_tbx_expression(item) for item in node.items),
            node.newline,
        )
    elif isinstance(node, tbx_ir.Lprint):
        operands = (
            "printer",
            tuple(_tbx_expression(item) for item in node.items),
            node.newline,
        )
    elif isinstance(node, tbx_ir.PrintUsing):
        if node.lprint:
            mode = "printer"
        elif node.file is None or isinstance(node.file, int):
            mode = "console" if node.file is None else node.file
        else:
            mode = _tbx_expression(node.file)
        operands = (
            mode,
            _tbx_expression(node.fmt),
            tuple(_tbx_expression(value) for value in node.values),
            node.newline,
        )
    elif isinstance(node, tbx_ir.Write):
        if node.file is None or isinstance(node.file, int):
            file_number = node.file
        else:
            file_number = _tbx_expression(node.file)
        operands = file_number, tuple(_tbx_expression(item) for item in node.items)
    elif isinstance(node, (tbx_ir.Lset, tbx_ir.Rset)):
        operands = _tbx_expression(node.target), _tbx_expression(node.source)
    elif isinstance(node, tbx_ir.MidAssign):
        operands = (
            _tbx_expression(node.target),
            _tbx_expression(node.start),
            _tbx_expression(node.source),
            None if node.length is None else _tbx_expression(node.length),
        )
    elif isinstance(node, tbx_ir.Swap):
        operands = _tbx_expression(node.a), _tbx_expression(node.b)
    elif isinstance(node, tbx_ir.Locate):
        operands = tuple(
            None if value is None else _tbx_expression(value)
            for value in (node.row, node.col, node.cursor, node.start, node.stop)
        )
    elif isinstance(node, tbx_ir.Read):
        operands = (tuple(_tbx_expression(target) for target in node.targets),)
    elif isinstance(node, tbx_ir.InputFile):
        operands = node.num, tuple(_tbx_expression(target) for target in node.vars)
    elif isinstance(node, tbx_ir.Input):
        targets = (
            tuple(_tbx_expression(target) for target in node.var)
            if isinstance(node.var, tuple)
            else _tbx_expression(node.var)
        )
        operands = (
            None if node.prompt is None else _tbx_expression(node.prompt),
            targets,
            node.comma,
            node.semi,
        )
    elif isinstance(node, tbx_ir.Open):
        operands = (
            _tbx_expression(node.mode),
            node.num,
            _tbx_expression(node.file),
            None if node.reclen is None else _tbx_expression(node.reclen),
            node.for_as,
        )
    elif isinstance(node, tbx_ir.Close):
        if node.num is None or isinstance(node.num, int):
            value = node.num
        else:
            value = _tbx_expression(node.num)
        operands = (value,)
    elif isinstance(node, tbx_ir.Color):
        operands = tuple(
            None if value is None else _tbx_expression(value)
            for value in (node.fg, node.bg, node.border)
        )
    elif isinstance(node, tbx_ir.Screen):
        operands = tuple(
            None if value is None else _tbx_expression(value)
            for value in (node.mode, node.burst, node.apage, node.vpage)
        )
    elif isinstance(node, tbx_ir.Files):
        operands = (
            None if node.spec is None else _tbx_expression(node.spec),
        )
    elif type(node) in _TBX_STRING_STATEMENT_FIELDS:
        operands = (
            _tbx_expression(getattr(node, _TBX_STRING_STATEMENT_FIELDS[type(node)])),
        )
    elif isinstance(node, tbx_ir.DateTimeSet):
        operands = node.name, _tbx_expression(node.value)
    elif isinstance(node, tbx_ir.For):
        operands = tuple(
            _tbx_expression(value)
            for value in (node.var, node.init, node.limit, node.step)
        )
    elif isinstance(node, tbx_ir.NextStmt):
        operands = (_tbx_expression(node.var),)
    elif isinstance(node, tbx_ir.TrapCtl):
        number = None if node.n is None else _tbx_expression(node.n)
        operands = node.event, number, node.mode
    elif isinstance(node, tbx_ir.OnTrap):
        number = None if node.n is None else _tbx_expression(node.n)
        operands = node.event, number, node.target
    elif isinstance(node, tbx_ir.OnError):
        operands = (node.target,)
    elif isinstance(node, (tbx_ir.OnGoto, tbx_ir.OnGosub)):
        operands = (_tbx_expression(node.selector), *node.targets)
    elif isinstance(node, tbx_ir.Run):
        operands = () if node.file is None else (_tbx_expression(node.file),)
    elif isinstance(node, tbx_ir.Field):
        operands = node.num, tuple(
            (_tbx_expression(width), _tbx_expression(target))
            for width, target in node.fields
        )
    elif isinstance(node, tbx_ir.IfGoto):
        operands = (
            node.cond.op,
            _tbx_expression(node.cond.lhs),
            _tbx_expression(node.cond.rhs),
            node.target,
        )
    elif isinstance(node, tbx_ir.Gosub):
        operands = (node.target,)
    elif isinstance(node, tbx_ir.Return):
        operands = () if node.target is None else (node.target,)
    elif isinstance(node, tbx_ir.Resume):
        if node.next_:
            operands = ("NEXT",)
        else:
            operands = () if node.target is None else (node.target,)
    elif isinstance(node, tbx_ir.Delay):
        operands = (_tbx_expression(node.secs),)
    elif isinstance(node, tbx_ir.DefSeg):
        operands = () if node.seg is None else (_tbx_expression(node.seg),)
    elif isinstance(node, tbx_ir.Out):
        operands = _tbx_expression(node.port), _tbx_expression(node.value)
    elif isinstance(node, tbx_ir.Wait):
        operands = (_tbx_expression(node.port), _tbx_expression(node.mask))
        if node.xor is not None:
            operands += (_tbx_expression(node.xor),)
    else:
        operands = ()
    return type(node).__name__, operands


def _tbx_bound(node):
    if isinstance(node, int):
        return node
    if isinstance(node, tuple) and len(node) == 2:
        return tuple(
            item if isinstance(item, int) else _tbx_expression(item)
            for item in node
        )
    return _tbx_expression(node)


def _tbx_expression(node):
    if isinstance(node, tbx_ir.Var):
        return "var", node.name
    if isinstance(node, tbx_ir.ArrayRef):
        return (
            "array",
            node.name,
            tuple(_tbx_expression(item) for item in node.indices),
        )
    if isinstance(node, tbx_ir.Lit):
        return "const", node.value
    if isinstance(node, (tbx_ir.DblLit, tbx_ir.SingleLit)):
        return "const", node.value
    if isinstance(node, tbx_ir.StrLit):
        return "string", node.value
    if isinstance(node, tbx_ir.Call):
        return "call", node.name, tuple(_tbx_expression(item) for item in node.args)
    if isinstance(node, tbx_ir.PrintUsing):
        if node.lprint:
            mode = "printer"
        elif node.file is None or isinstance(node.file, int):
            mode = "console" if node.file is None else node.file
        else:
            mode = _tbx_expression(node.file)
        return (
            "print_using",
            mode,
            _tbx_expression(node.fmt),
            tuple(_tbx_expression(value) for value in node.values),
            node.newline,
        )
    if isinstance(node, tbx_ir.BinOp):
        return normalize_expression(
            (
                "binary",
                node.op,
                _tbx_expression(node.lhs),
                _tbx_expression(node.rhs),
            )
        )
    return "unknown", type(node).__name__
