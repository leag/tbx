"""Recursive tbx.ir dataclass -> JSON converter, for the web UI's IR tab.

Lives outside tbx.ir itself so the core IR package stays free of
serialization/presentation concerns.
"""

from __future__ import annotations

import dataclasses
from typing import Any


def _is_ir_node(value: Any) -> bool:
    return dataclasses.is_dataclass(value) and not isinstance(value, type)


def _is_ir_node_tuple(value: Any) -> bool:
    return (
        isinstance(value, (tuple, list))
        and len(value) > 0
        and all(_is_ir_node(item) for item in value)
    )


def to_json(node: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    children: list[dict[str, Any]] = []
    for f in dataclasses.fields(node):
        value = getattr(node, f.name)
        if _is_ir_node(value):
            children.append({"name": f.name, "node": to_json(value)})
        elif _is_ir_node_tuple(value):
            children.append({"name": f.name, "nodes": [to_json(v) for v in value]})
        elif isinstance(value, (tuple, list)):
            fields[f.name] = list(value)
        else:
            fields[f.name] = value
    return {"type": type(node).__name__, "fields": fields, "children": children}


def program_to_json(stmts: list[Any]) -> list[dict[str, Any]]:
    return [to_json(stmt) for stmt in stmts]
