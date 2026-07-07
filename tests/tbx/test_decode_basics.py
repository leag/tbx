from tbx import ir


def test_end_statement_node():
    assert ir.End() == ir.End()
    assert ir.unparse_stmt(ir.End()) == "END"


def _trivial_exe():
    import os

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return open(
        os.path.join(root, "fixtures", "corpus", "tier0_trivial.exe"), "rb"
    ).read()


def test_decode_trivial():
    from tbx import decode0

    stmts = decode0.decode_user_code(_trivial_exe())
    assert stmts == [ir.Assign(ir.Var("A"), ir.Lit(1)), ir.End()], stmts


def test_decode_fild_const_pool():
    # Synthetic image exercising the FILD path (the `A = 2` shape).
    # Layout rules (see the decode0 docstring): 1 scalar -> pool base
    # DS:0134, preceded by the 00 80 16 00 marker at DS:0130. With ds = 0x100 the marker
    # sits at file 0x230 and the pool word [0134] at 0x234. Prologue position is free.
    from tbx import decode0

    buf = bytearray(0x300)
    buf[0x230:0x234] = decode0.MARKER
    buf[0x234:0x236] = (2).to_bytes(2, "little")  # const pool: 2
    code = bytes.fromhex("cdecbacd3b063401cd351e2001cd87cdec32cdece8")
    buf[0x1C0 : 0x1C0 + len(code)] = code
    stmts = decode0.decode_user_code(bytes(buf))
    assert stmts == [ir.Assign(ir.Var("A"), ir.Lit(2)), ir.End()], stmts


def test_emit_canonical_source():
    from tbx import emit0

    stmts = [ir.Assign(ir.Var("A"), ir.Lit(1)), ir.End()]
    assert emit0.emit(stmts) == "10 A = 1\n20 END\n"


def test_decode_emit_reproduces_original_source():
    # Canonical naming (A.. by first store) and numbering (10,20..) happen to match the
    # authored source exactly -- decode+emit recovers the original text verbatim.
    import os
    from tbx import decode0, emit0

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    original = open(
        os.path.join(root, "fixtures", "corpus", "tier0_trivial.bas")
    ).read()
    assert emit0.emit(decode0.decode_user_code(_trivial_exe())) == original


if __name__ == "__main__":
    test_end_statement_node()
    test_decode_trivial()
    test_decode_fild_const_pool()
    test_emit_canonical_source()
    test_decode_emit_reproduces_original_source()
    print("ALL PASS")
