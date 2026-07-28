import pytest

from tbx import ir
from tbx.decode0.control_graph import ControlGraph


def test_control_graph_collects_address_edges():
    graph = ControlGraph.from_statements(
        (ir.Goto(("addr", 0x20)), ir.End()),
        (0x10, 0x20),
    )

    assert graph.nodes[0].address == 0x10
    assert graph.outgoing(0)[0].target == 0x20
    graph.validate_targets()


def test_control_graph_rejects_unknown_targets():
    graph = ControlGraph.from_statements(
        (ir.IfGoto(ir.Lit(1), ("addr", 0x99)),),
        (0x10,),
    )

    with pytest.raises(ValueError, match="jump target 0x99"):
        graph.validate_targets()
