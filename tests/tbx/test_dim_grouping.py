"""Comma-list DIM statements (per-statement commit markers) and the OB0-plain
sub-free static form (OPTION BASE re-issue)."""

import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PAIRS = ["t1_dimm", "t1_ob2", "t1_ob3"]


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_decode_t1_dimm():
    """DIM A(N,3), B(N), C(2*N) is ONE statement (one trailing commit): the three
    allocate brackets merge into a single Dim with `also` entries."""
    from tbx import decode0

    stmts = decode0.decode_user_code(_exe("t1_dimm.exe"))
    dims = [s for s in stmts if isinstance(s, ir.Dim)]
    assert len(dims) == 2, [type(s).__name__ for s in stmts]
    assert len(dims[0].also) == 2, dims[0]
    assert dims[1].also == (), dims[1]
    assert len(stmts) == 10, len(stmts)


def test_emit_t1_dimm():
    from tbx import decode0, emit0

    out = emit0.emit(decode0.decode_user_code(_exe("t1_dimm.exe")))
    lines = out.splitlines()
    assert lines[2].count(",") >= 3 and lines[2].count("(") == 3, lines[2]
    assert "), " in lines[2], lines[2]


def test_decode_t1_ob2():
    """Static with lo=0 in an OPTION BASE 1 program: plain DIM emitted inside an
    OPTION BASE 0 window (sub-free access witness)."""
    from tbx import decode0, emit0

    out = emit0.emit(decode0.decode_user_code(_exe("t1_ob2.exe")))
    lines = out.splitlines()
    assert lines[0].endswith("DIM V0(10,10)"), lines[0]
    assert "0:" not in out, out


def test_decode_t1_ob3():
    """lo=0 static between lo=1 statics. No runtime DIMs -> no OPTION BASE witness,
    so the canonical form keeps explicit (1:hi) ranges (gate-proven free, t1_arrv)
    and the lo=0 array stays PLAIN (sub-free witness)."""
    from tbx import decode0, emit0

    stmts = decode0.decode_user_code(_exe("t1_ob3.exe"))
    assert not any(isinstance(s, ir.OptionBase) for s in stmts)
    out = emit0.emit(stmts)
    assert "0:" not in out, out
    assert "DIM V1(10,10)" in out, out
    assert "(1:6,1:6)" in out, out


def test_dialect_invariant():
    from tbx import decode0

    for name in PAIRS:
        assert decode0.decode_user_code(
            _exe(f"v10_{name}.exe")
        ) == decode0.decode_user_code(_exe(f"{name}.exe")), name


if __name__ == "__main__":
    test_decode_t1_dimm()
    test_emit_t1_dimm()
    test_decode_t1_ob2()
    test_decode_t1_ob3()
    test_dialect_invariant()
    print("ALL PASS")
