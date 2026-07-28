import pytest
import json
from pathlib import Path
from tbx import ir
from tbx.decode0.core import DecodeState
from tbx.decode0.handlers import arith
from tbx.decode0.scan import _scan_direct2
from tbx.tools import batch_probe
from tbx.tools.compare_gap_reports import compare


def _handler_state(**fields):
    """A real ``DecodeState`` for exercising one handler in isolation.

    These tests used to pass a ``SimpleNamespace``, which silently accepted
    any field name. A real state carries the ownership views the handlers
    read through, so a field that moved owners fails here instead of
    quietly reading ``None``.
    """
    state = DecodeState()
    for name, value in fields.items():
        setattr(state, name, value)
    return state



ROOT = Path(__file__).resolve().parents[2]


def report(hits=(), failures=()):
    return {
        "schema_version": 1,
        "corpus_fingerprint": "same",
        "hits": [{"name": n} for n in hits],
        "failures": [{"name": n, "signature": s} for n, s in failures],
    }


def test_compare_classifies_progress_and_regression():
    old = report(hits=("regress.exe",), failures=(("done.exe", "old"), ("advance.exe", "a")))
    new = report(hits=("done.exe",), failures=(("regress.exe", "r"), ("advance.exe", "b")))
    result = compare(old, new)
    assert result["newly_decoded"] == ["done.exe"]
    assert result["regressed"] == ["regress.exe"]
    assert result["advanced"] == ["advance.exe"]


def test_compare_rejects_different_corpus():
    old = report()
    new = report()
    new["corpus_fingerprint"] = "different"
    with pytest.raises(ValueError, match="different corpus"):
        compare(old, new)


def test_runtime_revision_assessment_ledger_is_well_formed():
    path = ROOT / "gap_reports" / "runtime-revision-assessments.json"
    ledger = json.loads(path.read_text())
    assert ledger["schema_version"] == 1
    assert ledger["document_type"] == "tbx.runtime_revision_assessments"
    assert len(ledger["corpus_fingerprint"]) == 64

    entries = ledger["assessments"]
    ids = [entry["id"] for entry in entries]
    assert len(ids) == len(set(ids))
    for entry in entries:
        assert entry["signatures"]
        assert entry["disposition"] in {
            "candidate", "closed", "coverage-only", "unresolved"
        }
        assert entry["evidence_class"] in ledger["evidence_classes"]
        if entry["disposition"] != "closed":
            assert entry["promotion_criteria"]


def test_batch_probe_parallel_keep(tmp_path, monkeypatch, capsys):
    probes, kept = tmp_path / "probes", tmp_path / "kept"
    probes.mkdir()
    for name in ("a", "b"):
        (probes / f"{name}.bas").write_text("10 END\n")

    monkeypatch.setattr(batch_probe.oracle, "preflight", lambda: None)
    monkeypatch.setattr(
        batch_probe,
        "probe_one",
        lambda path, dialect: ("clean", f"{dialect} {path.stem}", path.stem.encode()),
    )
    assert batch_probe.main(
        [str(probes), "--dialect", "1.0", "--jobs", "2", "--keep", str(kept)]
    ) == 0
    assert {path.name: path.read_bytes() for path in kept.iterdir()} == {
        "a.exe": b"a",
        "b.exe": b"b",
    }
    output = capsys.readouterr().out
    assert "clean  a: 1.0 a" in output
    assert "clean  b: 1.0 b" in output


def test_deep_register_spill_store_and_restore():
    ops = []
    code = bytes.fromhex("89 3e 7e 00 8b 0e 7e 00 8b 3e 7e 00")
    assert _scan_direct2(code, 0, code[0], ops) == 4
    assert _scan_direct2(code, 4, code[4], ops) == 8
    assert _scan_direct2(code, 8, code[8], ops) == 12
    assert [op[1:] for op in ops] == [
        ("spill_store", "di", 0x7E),
        ("spill_load", "cx", 0x7E),
        ("spill_load", "di", 0x7E),
    ]

    value = ir.Lit(7)
    state = _handler_state(di=value, cx=None, reg_spills={}, k=0)
    assert arith.int_alu(state, ops[0], 0, "spill_store")
    assert state.di is None and state.reg_spills == {0x7E: value}
    assert arith.int_alu(state, ops[1], 4, "spill_load")
    assert state.cx == value and state.reg_spills == {}


def test_integer_call_argument_temp_staging():
    ops = []
    code = bytes.fromhex("36 89 04")
    assert _scan_direct2(code, 0, code[0], ops) == 3
    assert ops == [(0, "movm_ax_temp")]
    ops.append((3, "arg_push_temp"))  # a plain SUB CALL argument frame

    value = ir.Lit(9)
    state = _handler_state(
        ax=value, pend_args=[], fn_args={}, si=None, cur=123, k=0, ops=ops
    )
    assert arith.int_alu(state, ops[0], 0, "movm_ax_temp")
    assert state.pend_args == [value]
    assert state.fn_args == {}
    # cur is left alone (still 123): this op stages one argument value
    # mid-expression inside a CALL statement that's still open -- no
    # put() happens here, so there's no statement boundary to close.
    # Clearing it unconditionally let the generic top-of-loop fallback
    # re-stamp a LATER op's address as the CALL's own, so a loop's
    # backward branch targeting the CALL's real start failed to resolve
    # (wild morcalc.exe).
    assert state.ax is None and state.cur == 123 and state.k == 1


def test_nested_fn_call_argument_temp_staging():
    # A DEF FN call used as another call's own argument stages its OWN
    # literal argument via SI+SP addressing (no arg_push_temp follows --
    # the frame closes straight into mov_bp_sp; fn_call), so it must land in
    # fn_args (keyed by the si offset), not pend_args (t1_fnargcall).
    ops = []
    code = bytes.fromhex("36 c7 04 03 00")
    assert _scan_direct2(code, 0, code[0], ops) == 5
    assert ops == [(0, "movm_imm_temp", 3)]
    ops.append((5, "mov_bp_sp"))  # a nested DEF FN call's own frame

    state = _handler_state(
        ax=None, pend_args=[], fn_args={}, si=2, cur=123, k=0, ops=ops
    )
    assert arith.int_alu(state, ops[0], 0, "movm_imm_temp")
    assert state.pend_args == []
    assert state.fn_args == {2: ir.Lit(3)}
    assert state.cur == 123 and state.k == 1


def test_non_for_integer_add_immediate():
    var = ir.Var("A%")
    emitted = []
    state = _handler_state(
        fors=[],
        loc=lambda _disp: var,
        put=lambda stmt, addr: emitted.append((stmt, addr)),
        cur=100,
        k=0,
    )
    op = (100, "addm_i8", 0x382, 50)
    assert arith.int_alu(state, op, 100, "addm_i8")
    assert emitted == [(ir.Assign(var, ir.BinOp("+", var, ir.Lit(50))), 100)]
    assert state.cur is None and state.k == 1


def test_non_for_memory_to_ax_integer_compare():
    lhs, rhs = ir.Var("A%"), ir.Var("B%")
    state = _handler_state(
        ax=rhs,
        pend_cmp=None,
        loc=lambda _disp: lhs,
        k=0,
    )
    op = (100, "cmpm_ax", 0x382)
    assert arith.int_alu(state, op, 100, "cmpm_ax")
    assert state.pend_cmp == (lhs, rhs)
    assert state.ax is None and state.k == 1


def test_logical_value_chain_uses_combine_provenance_for_operand_order():
    a, b, c = ir.Var("A%"), ir.Var("B%"), ir.Var("C%")
    accumulated = ir.BinOp("AND", a, b)
    state = _handler_state(
        ax=c,
        bx=accumulated,
        direct_bool_gate=False,
        reg_logical_results=[accumulated],
        k=0,
    )

    assert arith.int_bitwise_bx(state, (100, "oraxbx"), 100, "oraxbx")
    assert state.ax == ir.BinOp("OR", accumulated, c)
    assert state.bx is None and state.k == 1


def test_logical_value_chain_does_not_reverse_independent_group():
    a, b, c = ir.Var("A%"), ir.Var("B%"), ir.Var("C%")
    independent = ir.BinOp("AND", a, b)
    state = _handler_state(
        ax=c,
        bx=independent,
        direct_bool_gate=False,
        reg_logical_results=[],
        k=0,
    )

    assert arith.int_bitwise_bx(state, (100, "andaxbx"), 100, "andaxbx")
    assert state.ax == ir.BinOp("AND", c, ir.Group(independent))


def test_logical_value_chain_preserves_lower_precedence_right_group():
    a, b, c = ir.Var("A%"), ir.Var("B%"), ir.Var("C%")
    right_group = ir.BinOp("OR", b, c)
    state = _handler_state(
        ax=a,
        bx=right_group,
        direct_bool_gate=False,
        reg_logical_results=[right_group],
        k=0,
    )

    assert arith.int_bitwise_bx(state, (100, "andaxbx"), 100, "andaxbx")
    assert state.ax == ir.BinOp("AND", a, ir.Group(right_group))


def test_equal_precedence_logical_value_chain_keeps_evaluation_order():
    a, b, c = ir.Var("A%"), ir.Var("B%"), ir.Var("C%")
    accumulated = ir.BinOp("OR", a, b)
    state = _handler_state(
        ax=c,
        bx=accumulated,
        direct_bool_gate=False,
        reg_logical_results=[accumulated],
        k=0,
    )

    assert arith.int_bitwise_bx(state, (100, "oraxbx"), 100, "oraxbx")
    assert state.ax == ir.BinOp("OR", c, ir.Group(accumulated))
