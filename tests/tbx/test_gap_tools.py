import pytest
from types import SimpleNamespace

from tbx import ir
from tbx.decode0.handlers import arith
from tbx.decode0.scan import _scan_direct2
from tbx.tools.compare_gap_reports import compare


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
    state = SimpleNamespace(di=value, cx=None, reg_spills={}, k=0)
    assert arith.int_alu(state, ops[0], 0, "spill_store")
    assert state.di is None and state.reg_spills == {0x7E: value}
    assert arith.int_alu(state, ops[1], 4, "spill_load")
    assert state.cx == value and state.reg_spills == {}


def test_integer_call_argument_temp_staging():
    ops = []
    code = bytes.fromhex("36 89 04")
    assert _scan_direct2(code, 0, code[0], ops) == 3
    assert ops == [(0, "movm_ax_temp")]

    value = ir.Lit(9)
    state = SimpleNamespace(ax=value, pend_args=[], cur=123, k=0)
    assert arith.int_alu(state, ops[0], 0, "movm_ax_temp")
    assert state.pend_args == [value]
    assert state.ax is None and state.cur is None and state.k == 1


def test_non_for_integer_add_immediate():
    var = ir.Var("A%")
    emitted = []
    state = SimpleNamespace(
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
    state = SimpleNamespace(
        ax=rhs,
        pend_cmp=None,
        loc=lambda _disp: lhs,
        k=0,
    )
    op = (100, "cmpm_ax", 0x382)
    assert arith.int_alu(state, op, 100, "cmpm_ax")
    assert state.pend_cmp == (lhs, rhs)
    assert state.ax is None and state.k == 1
