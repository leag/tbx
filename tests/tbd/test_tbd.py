import json
from pathlib import Path

from tbx import decode0, ir as tbx_ir
from tbd import cli, decode
from tbd.canonical import canonicalize
from tbd.facts import Evidence, analyze as analyze_facts
from tbd.ir import Fact, Operation, Slot, Statement
from tbd.pool import infer_layout, resolve as resolve_pool

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
    assert program.instructions[1].operands == ("SUB_FE", 0xFE)
    assert program.instructions[2].kind == "opaque.byte"
    assert [operation.kind for operation in program.operations] == [
        "unknown.region", "tb.statement", "unknown.region"
    ]


def test_recursive_discovery_skips_unreachable_bytes():
    program = decode(bytes.fromhex("eb 02 cc cc cd ec e8"))

    assert [item.offset for item in program.instructions] == [0, 4]
    assert len(program.blocks) == 2
    assert program.xrefs[0].target == 4


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
    binary = bytes.fromhex("b8 01 00 bb 02 00 cd ec 22 ea 00 00 00 00")
    program = decode(binary)

    statement = program.operations[0]
    assert statement.kind == "tb.statement"
    assert statement.operands == (
        "COLOR", 0x22, ("register", "bx", 2), ("register", "ax", 1)
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
    elif isinstance(node, tbx_ir.IfGoto):
        operands = (
            node.cond.op,
            _tbx_expression(node.cond.lhs),
            _tbx_expression(node.cond.rhs),
            node.target,
        )
    elif isinstance(node, tbx_ir.Delay):
        operands = (_tbx_expression(node.secs),)
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
    if isinstance(node, tbx_ir.BinOp):
        return (
            "binary",
            node.op,
            _tbx_expression(node.lhs),
            _tbx_expression(node.rhs),
        )
    return "unknown", type(node).__name__
