import json
from pathlib import Path

from tbd import cli, decode
from tbd.facts import Evidence, analyze as analyze_facts
from tbd.ir import Fact, Operation
from tbd.pool import resolve as resolve_pool

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
    assert all(
        report.facts == len(program.facts)
        for report in program.fact_passes
        if report.round == 2
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
            (("binary", "+", ("const", 1), ("slot", "V0001", 0x120)),),
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


def test_fact_operation_view_matches_migrated_legacy_operations():
    for stem in ("t1_addimm", "t1_print", "t1_if"):
        program = decode((_CORPUS / f"{stem}.exe").read_bytes())
        migrated_kinds = {"ir.assign", "ir.print"}
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
