"""Opt-in dense source keeps only source-significant line labels."""

from tbx import decode0, emit0, ir


def test_dense_source_omits_labels_from_straight_line_statements():
    program = decode0.Program(
        [
            ir.Assign(ir.Var("A"), ir.Lit(1)),
            ir.Print((ir.StrLit("X"),), newline=True),
            ir.End(),
        ]
    )

    assert emit0.emit(program, dense=True) == 'A=1\nPRINT "X"\nEND\n'


def test_dense_source_keeps_a_branch_target_label():
    program = decode0.Program(
        [
            ir.Goto(2),
            ir.Assign(ir.Var("A"), ir.Lit(1)),
            ir.End(),
        ]
    )

    assert emit0.emit(program, dense=True) == "GOTO 30\nA=1\n30 END\n"


def test_dense_source_keeps_a_restore_target_label():
    program = decode0.Program(
        [
            ir.Restore(1),
            ir.Data((ir.DataItem("1", False),)),
            ir.End(),
        ]
    )

    assert emit0.emit(program, dense=True) == "RESTORE 20\n20 DATA 1\nEND\n"


def test_dense_source_preserves_a_recovered_line_table():
    class Statements(list):
        lines = (100, 350, 900)

    program = Statements(
        [
            ir.Assign(ir.Var("A"), ir.Lit(1)),
            ir.Print((ir.Var("A"),), newline=True),
            ir.End(),
        ]
    )

    assert emit0.emit(program, dense=True) == "100 A=1\n350 PRINT A\n900 END\n"


def test_dense_source_numbers_a_block_with_an_internal_target():
    program = decode0.Program(
        [
            ir.SubDef(
                "SUB1",
                (),
                (
                    ir.Goto(ir.BodyLine(0, 2)),
                    ir.Print((ir.StrLit("SKIP"),), newline=True),
                    ir.End(),
                ),
            )
        ]
    )

    source = emit0.emit(program, dense=True)
    assert source.startswith("10 SUB SUB1\n")
    assert '12 PRINT "SKIP"\n' in source


def test_dense_source_finds_targets_nested_in_block_arm_tuples():
    condition = ir.RelOp("=", ir.Var("A"), ir.Lit(1))
    program = decode0.Program(
        [
            ir.IfBlock(((condition, (ir.Goto(2),)),)),
            ir.Assign(ir.Var("A"), ir.Lit(2)),
            ir.End(),
        ]
    )

    source = emit0.emit(program, dense=True)
    assert "GOTO 30" in source
    assert source.endswith("A=2\n30 END\n")
