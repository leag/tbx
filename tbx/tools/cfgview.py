"""Build a raw-x86 CFG over a compiled EXE's user-code region and write a
Graphviz .dot, printing block/edge stats.

Usage: python -m tbx.tools.cfgview PROGRAM.EXE [--out cfg.dot]

The user-code region is located with decode0: the prologue scan gives the
start, and the end is the last address the statement scan reaches.
"""

import sys
from pathlib import Path

from tbx import decode0
from tbx.tools import cfg, insns


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    if not args:
        print(
            "usage: python -m tbx.tools.cfgview PROGRAM.EXE [--out cfg.dot]",
            file=sys.stderr,
        )
        return 2
    out = argv[argv.index("--out") + 1] if "--out" in argv else "cfg.dot"
    data = Path(args[0]).read_bytes()
    start, dia = decode0.find_prologue(data)
    ops = decode0._scan(data, start, dia, set())
    end = max(op[0] for op in ops) if ops else start
    lines = insns.decode_insns(data, start, end)
    decoded = cfg.insns_from_decode(lines, code_range=(start, end))
    g = cfg.build_cfg(decoded)
    n_edges = sum(len(b.succ) for b in g.blocks)
    kinds = {}
    for b in g.blocks:
        kinds[b.last.flow] = kinds.get(b.last.flow, 0) + 1
    print(f"instructions: {len(decoded)}")
    print(f"basic blocks: {len(g.blocks)}")
    print(f"edges: {n_edges}")
    print(f"block terminators: {kinds}")
    Path(out).write_text(g.to_dot())
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
