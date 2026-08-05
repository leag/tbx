from tbx import ir
from tbx.web.ir_json import program_to_json, to_json


def test_leaf_node_has_no_children():
    node = ir.Lit(value=42)

    result = to_json(node)

    assert result == {"type": "Lit", "fields": {"value": 42}, "children": []}


def test_single_child_field_nests_under_children():
    # ir.Neg wraps one expression in its `operand` field (not `value`).
    node = ir.Neg(operand=ir.Lit(value=1))

    result = to_json(node)

    assert result["type"] == "Neg"
    assert result["fields"] == {}
    assert result["children"] == [
        {"name": "operand", "node": {"type": "Lit", "fields": {"value": 1}, "children": []}}
    ]


def test_tuple_of_children_field_nests_as_nodes_list():
    # ir.ArrayRef has `name: str` and `indices: tuple[Expr, ...]`.
    node = ir.ArrayRef(name="A", indices=(ir.Lit(value=0), ir.Lit(value=1)))

    result = to_json(node)

    assert result["type"] == "ArrayRef"
    assert result["fields"] == {"name": "A"}
    assert result["children"] == [
        {
            "name": "indices",
            "nodes": [
                {"type": "Lit", "fields": {"value": 0}, "children": []},
                {"type": "Lit", "fields": {"value": 1}, "children": []},
            ],
        }
    ]


def test_bytes_field_is_hex_encoded_for_json_safety():
    # ir.Inline carries raw machine code in `data: bytes`, which is not
    # UTF-8 and must not be passed through to jsonable_encoder as-is.
    node = ir.Inline(data=b"\x90\xcd")

    result = to_json(node)

    assert result["fields"]["data"] == "90cd"
    assert isinstance(result["fields"]["data"], str)


def test_program_to_json_converts_a_statement_list():
    program = [ir.Assign(target=ir.Var(name="A"), value=ir.Lit(value=1))]

    result = program_to_json(program)

    assert len(result) == 1
    assert result[0]["type"] == "Assign"
