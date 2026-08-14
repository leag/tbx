import json
from pathlib import Path

from tbx import decode0, ir as tbx_ir
from tbd import cli, decode
from tbd.canonical import canonicalize, normalize_expression
from tbd.facts import Evidence, analyze as analyze_facts
from tbd.ir import Fact, Operation, Slot, Statement
from tbd.pool import infer_layout, resolve as resolve_pool
from tbd.x86 import decode_instruction

_CORPUS = Path(__file__).parents[1] / "fixtures" / "corpus"


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
        assert actual_prints[3][0] == "file"
        assert actual_prints[3][1:] == exact_prints[3][1:]
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


def test_grouped_locate_runtime_legs_recover_complete_constant_forms():
    stems = (
        "t1_locateomit",
        "t1_locate5",
        "t1_loccurs",
        "v10_t1_loccurs",
        "t1_scr2",
        "v10_t1_scr2",
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
        assert all(
            fact.confidence == "signature"
            for fact in program.facts
            if fact.kind == "semantic.locate"
        )


def test_locate_does_not_emit_a_partial_cursor_extension():
    truncated = decode(
        bytes.fromhex("b8 03 00 89 c3 b8 05 00 cd cf b8 01 00")
    )

    assert not any(fact.kind == "semantic.locate" for fact in truncated.facts)


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


def test_numeric_read_does_not_lift_incomplete_or_mixed_suffixes():
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


def test_input_file_rejects_an_incomplete_following_item():
    program = decode(
        bytes.fromhex(
            "b8 01 00 a3 60 00 cd ec a0 be 20 01 cd a0 cd ec 9e"
        )
    )

    assert not any(fact.kind == "semantic.input_file" for fact in program.facts)


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


def test_device_io_facts_leave_incomplete_or_altered_out_structural():
    complete = bytes.fromhex("b8 78 03 89 c3 b8 01 00 8b d3 ee")
    truncated = decode(complete[:-1])
    altered = decode(complete[:3] + b"\x89\xc1" + complete[5:])
    variable = decode((_CORPUS / "t1_out2.exe").read_bytes())

    assert not any(fact.kind == "semantic.out" for fact in truncated.facts)
    assert not any(fact.kind == "semantic.out" for fact in altered.facts)
    assert not any(fact.kind == "semantic.out" for fact in variable.facts)
    assert truncated.canonical_statements == altered.canonical_statements == ()
    assert [node.kind for node in variable.canonical_statements] == ["Assign", "End"]


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


def test_device_io_facts_leave_unverified_or_incomplete_wait_structural():
    complete = bytes.fromhex(
        "b8 08 00 89 c3 b8 04 00 89 d9 89 c3 b8 da 03 8b d0 "
        "ec 30 d8 20 c8 74 f9"
    )
    truncated = decode(complete[:-1])
    altered = decode(complete[:18] + b"\x30\xc8" + complete[20:])
    two_argument = decode((_CORPUS / "t1_wait.exe").read_bytes())

    assert not any(fact.kind == "semantic.wait" for fact in truncated.facts)
    assert not any(fact.kind == "semantic.wait" for fact in altered.facts)
    assert not any(fact.kind == "semantic.wait" for fact in two_argument.facts)
    assert truncated.canonical_statements == altered.canonical_statements == ()
    assert [node.kind for node in two_argument.canonical_statements] == ["End"]


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
        assert program.canonical_statements[1].operands == (3, 4)


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
    elif isinstance(node, tbx_ir.Close):
        if node.num is None or isinstance(node.num, int):
            value = node.num
        else:
            value = _tbx_expression(node.num)
        operands = (value,)
    elif isinstance(node, tbx_ir.TrapCtl):
        number = None if node.n is None else _tbx_expression(node.n)
        operands = node.event, number, node.mode
    elif isinstance(node, tbx_ir.OnTrap):
        number = None if node.n is None else _tbx_expression(node.n)
        operands = node.event, number, node.target
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
