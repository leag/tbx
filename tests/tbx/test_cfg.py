import pytest

pytest.importorskip("iced_x86", reason="debug extra not installed")

from tbx.tools import cfg


def test_insns_from_decode_classifies_flow():
    # decode() yields (addr, kind, text); multiple lines may share an addr. Control flow
    # comes from the x86 line's mnemonic. Use in-range addresses so jump_target resolves.
    lines = [
        (0xC000, "x86", "mov ax,1"),
        (0xC003, "fp", "FLD V_0010"),  # non-x86 -> seq
        (0xC003, "BAS", "V_0010 = 1"),  # same addr annotation
        (0xC008, "x86", "je short C100h"),  # conditional branch
        (0xC00A, "x86", "jmp C200h"),  # unconditional
        (0xC00D, "x86", "call C300h"),  # subroutine call
        (0xC010, "x86", "ret"),  # return
    ]
    insns = cfg.insns_from_decode(lines)
    by = {i.addr: (i.flow, i.target) for i in insns}
    assert by[0xC000] == ("seq", None), by[0xC000]
    assert by[0xC003] == ("seq", None), by[0xC003]
    assert by[0xC008] == ("branch", 0xC100), by[0xC008]
    assert by[0xC00A] == ("jmp", 0xC200), by[0xC00A]
    assert by[0xC00D] == ("call", 0xC300), by[0xC00D]
    assert by[0xC010] == ("ret", None), by[0xC010]
    # one Insn per unique address, sorted
    assert [i.addr for i in insns] == [0xC000, 0xC003, 0xC008, 0xC00A, 0xC00D, 0xC010]


def test_build_cfg_blocks():
    # Straight run, a branch, its target, and a fall-through. Leaders: first addr, branch
    # target, and the instruction after a branch/jmp/ret.
    insns = [
        cfg.Insn(0x100, "seq", None),
        cfg.Insn(
            0x102, "branch", 0x108
        ),  # block ends here; 0x104 and 0x108 are leaders
        cfg.Insn(0x104, "seq", None),
        cfg.Insn(
            0x106, "jmp", 0x10A
        ),  # block ends; 0x108 leader (target) , 0x10A leader
        cfg.Insn(0x108, "seq", None),
        cfg.Insn(0x10A, "ret", None),
    ]
    g = cfg.build_cfg(insns)
    starts = sorted(b.start for b in g.blocks)
    assert starts == [0x100, 0x104, 0x108, 0x10A], [hex(s) for s in starts]
    # the first block spans 0x100..0x102 (ends at the branch)
    b0 = g.block_at(0x100)
    assert b0.start == 0x100 and b0.end == 0x102, (hex(b0.start), hex(b0.end))
    assert b0.last.flow == "branch"


def test_cfg_edges():
    insns = [
        cfg.Insn(0x100, "seq", None),
        cfg.Insn(0x102, "branch", 0x108),
        cfg.Insn(0x104, "seq", None),
        cfg.Insn(0x106, "jmp", 0x10A),
        cfg.Insn(0x108, "call", 0x900),  # external (out of range) call -> falls through
        cfg.Insn(0x10A, "ret", None),
    ]
    g = cfg.build_cfg(insns)

    def edges(start):
        return sorted((e.dst, e.kind) for e in g.block_at(start).succ)

    # branch block: taken -> 0x108, fall -> 0x104
    assert edges(0x100) == [(0x104, "fall"), (0x108, "jump")], edges(0x100)
    # jmp block: only -> 0x10A
    assert edges(0x104) == [(0x10A, "jump")], edges(0x104)
    # call block: external call (0x900 not a block) + fall-through to 0x10A
    assert edges(0x108) == [(0x10A, "fall"), (0x900, "call")], edges(0x108)
    # ret block: no successors
    assert edges(0x10A) == [], edges(0x10A)


def test_to_dot():
    insns = [
        cfg.Insn(0x100, "branch", 0x104),
        cfg.Insn(0x102, "seq", None),
        cfg.Insn(0x104, "ret", None),
    ]
    dot = cfg.build_cfg(insns).to_dot()
    assert dot.startswith("digraph cfg {"), dot[:40]
    assert '"b100"' in dot and '"b104"' in dot, dot
    # branch-taken edge to 0x104 and fall-through to 0x102's block
    assert '"b100" -> "b104"' in dot, dot
    assert dot.rstrip().endswith("}")


if __name__ == "__main__":
    test_insns_from_decode_classifies_flow()
    test_build_cfg_blocks()
    test_cfg_edges()
    test_to_dot()
    print("ALL PASS")
