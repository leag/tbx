"""Basic-block control-flow graph over a linear instruction decode.

The core is representation-agnostic: `build_cfg` consumes a list of
Insn(addr, flow, target). The `insns_from_decode` adapter derives those from
(addr, kind, text) decode lines using tbx.insns for mnemonic classification
and target resolution.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tbx import insns

_UNCOND = {"jmp", "jmps"}
_RET = {"ret", "retf"}


@dataclass(frozen=True)
class Insn:
    addr: int
    flow: str  # "seq" | "jmp" | "branch" | "call" | "ret"
    target: int | None  # resolved address for jmp/branch/call, else None


def insns_from_decode(lines, code_range=None) -> list[Insn]:
    """One Insn per unique instruction address.

    Flow classification comes from the 'x86' line at that address (if any);
    lines of other kinds are annotations and stay sequential. `code_range`
    is forwarded to jump-target resolution (see insns.jump_target).
    """
    by_addr: dict[int, list[tuple[str, str]]] = {}
    for addr, kind, text in lines:
        by_addr.setdefault(addr, []).append((kind, text))
    out = []
    for addr in sorted(by_addr):
        flow, target = "seq", None
        for kind, text in by_addr[addr]:
            if kind != "x86":
                continue
            mn = insns.mnemonic(text)
            if mn in insns.JCC or mn == "loop":
                flow, target = "branch", insns.jump_target(text, addr, code_range)
            elif mn in _UNCOND:
                flow, target = "jmp", insns.jump_target(text, addr, code_range)
            elif mn == "call":
                flow, target = "call", insns.jump_target(text, addr, code_range)
            elif mn in _RET:
                flow, target = "ret", None
        out.append(Insn(addr, flow, target))
    return out


@dataclass
class BasicBlock:
    start: int
    end: int  # addr of the last instruction (inclusive)
    insns: list[Insn]
    succ: list["Edge"] = field(default_factory=list)

    @property
    def last(self) -> Insn:
        return self.insns[-1]


@dataclass(frozen=True)
class Edge:
    src: int  # block start
    dst: int  # block start, or a target addr
    kind: str  # "fall" | "jump" | "call" | "external"


@dataclass
class CFG:
    blocks: list[BasicBlock]
    _by_start: dict[int, BasicBlock] = field(default_factory=dict)

    def block_at(self, start: int) -> BasicBlock:
        return self._by_start[start]

    def to_dot(self) -> str:
        styles = {
            "fall": "style=dashed",
            "jump": "style=solid",
            "call": "style=dotted,color=blue",
            "external": "style=dotted,color=gray",
        }
        out = ["digraph cfg {", '  node [shape=box,fontname="monospace"];']
        for b in self.blocks:
            out.append(
                f'  "b{b.start:X}" [label="{b.start:05X}-{b.end:05X}\\n{b.last.flow}"];'
            )
        for b in self.blocks:
            for e in b.succ:
                out.append(
                    f'  "b{e.src:X}" -> "b{e.dst:X}" [{styles.get(e.kind, "")}];'
                )
        out.append("}")
        return "\n".join(out)


def _leaders(insns: list[Insn]) -> set[int]:
    """Block leaders: the first address, every in-range jump/branch target,
    and the instruction following any control transfer."""
    addrs = [i.addr for i in insns]
    addr_set = set(addrs)
    leaders = {addrs[0]} if addrs else set()
    for k, ins in enumerate(insns):
        nxt = addrs[k + 1] if k + 1 < len(addrs) else None
        if ins.flow in ("jmp", "branch", "ret"):
            if nxt is not None:
                leaders.add(nxt)
        if ins.flow in ("jmp", "branch") and ins.target in addr_set:
            leaders.add(ins.target)
    return leaders


def build_cfg(insns: list[Insn]) -> CFG:
    leaders = _leaders(insns)
    blocks, cur = [], []
    for ins in insns:
        if ins.addr in leaders and cur:
            blocks.append(BasicBlock(cur[0].addr, cur[-1].addr, cur))
            cur = []
        cur.append(ins)
    if cur:
        blocks.append(BasicBlock(cur[0].addr, cur[-1].addr, cur))
    g = CFG(blocks)
    g._by_start = {b.start: b for b in blocks}
    starts = set(g._by_start)
    order = [b.start for b in blocks]
    for idx, b in enumerate(blocks):
        # Fall-through successor is the next block in address order.
        nxt = order[idx + 1] if idx + 1 < len(blocks) else None
        last = b.last
        if last.flow == "ret":
            pass  # terminal
        elif last.flow == "jmp":
            kind = "jump" if last.target in starts else "external"
            b.succ.append(Edge(b.start, last.target, kind))
        elif last.flow == "branch":
            tkind = "jump" if last.target in starts else "external"
            b.succ.append(Edge(b.start, last.target, tkind))
            if nxt is not None:
                b.succ.append(Edge(b.start, nxt, "fall"))
        else:  # seq or call: fall through
            if nxt is not None:
                b.succ.append(Edge(b.start, nxt, "fall"))
            if last.flow == "call" and last.target is not None:
                b.succ.append(Edge(b.start, last.target, "call"))
    return g
