"""Transient decoder state stays in `frames.py`, and stays typed.

The dispatch loop carries a frame for every construct it has recognised but
not yet closed -- an open FOR, a SELECT mid-arm, a PRINT collecting items.
These were dicts built at the recognition site and read somewhere else
entirely, and that cost more than tidiness:

- `c.fors` held five different key sets across six sites, so nothing could
  tell you what was in one without finding all six;
- absences carried meaning, differently in different places. `frame_words`
  was read with two defaults -- 0 in one caller, `len(locals)` in another --
  so what "not set" meant depended on who asked;
- keys appeared mid-life. A SELECT frame gained `body_seq` when its body
  started, and no construction site mentioned it;
- one key's *existence* was conditional: `**({"mode": "lprint"} if
  want_lprint else {})`.

None of that is expressible in a dataclass, which is the point. These tests
keep it that way.
"""

import ast
from pathlib import Path

import pytest

from tbx.decode0 import frames

_ROOT = Path(__file__).resolve().parents[2]
_DECODE0 = _ROOT / "tbx" / "decode0"


def _dict_frames():
    """Dict literals appended to a frame stack or assigned to a frame field."""
    found = []
    for path in sorted(_DECODE0.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            literal = None
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "append"
                and node.args
                and isinstance(node.args[0], ast.Dict)
            ):
                literal = node.args[0]
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
                target = node.targets[0]
                if isinstance(target, ast.Attribute) and (
                    "frame" in target.attr or target.attr.startswith("pend_")
                ):
                    literal = node.value
            if literal is not None and any(
                isinstance(k, ast.Constant) for k in literal.keys
            ):
                found.append(f"{path.name}:{node.lineno}")
    return found


def test_no_frame_is_a_dict_literal():
    found = _dict_frames()

    assert not found, (
        f"{len(found)} frames are dict literals again: {found}. "
        "A frame belongs in tbx/decode0/frames.py as a dataclass."
    )


def test_no_frame_is_read_by_subscript():
    """The other half: a typed frame reached through `["key"]` is a bug.

    Worth checking separately because the failure is silent in one
    direction -- `.get("missing")` returns None rather than raising, which is
    how absences came to carry meaning in the first place.
    """
    names = {
        f
        for cls in vars(frames).values()
        if isinstance(cls, type) and hasattr(cls, "__dataclass_fields__")
        for f in cls.__dataclass_fields__
    }
    # `cells` and `block` are also plain-dict keys elsewhere (array
    # descriptors index by offset), so they cannot be checked this way.
    names -= {"cells", "base", "start", "exit", "seq", "idx", "op", "num"}

    offenders = []
    for path in sorted(_DECODE0.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.Subscript)
                and isinstance(node.slice, ast.Constant)
                and node.slice.value in names
            ):
                offenders.append(f"{path.name}:{node.lineno} [{node.slice.value!r}]")

    assert not offenders, f"frame fields reached by subscript: {offenders}"


@pytest.mark.parametrize(
    "name",
    sorted(
        n
        for n, v in vars(frames).items()
        if isinstance(v, type) and hasattr(v, "__dataclass_fields__")
    ),
)
def test_every_frame_says_what_it_is_and_what_each_field_means(name):
    """A field list without meanings is a dict with extra steps.

    The value of these records is not that they have names -- the dicts had
    names -- but that the name is defined where the compiler convention behind
    it can be written down. So each carries a docstring, and each field a
    comment.
    """
    cls = getattr(frames, name)
    source = (_DECODE0 / "frames.py").read_text()

    assert cls.__doc__ and cls.__doc__.strip(), f"{name} needs a docstring"

    # Own fields only: a subclass inherits both the fields and their comments,
    # and `ProcFrame` is entitled to say no more than "an open SUB body" when
    # `BodyFrame` above it carries the explanation.
    inherited = set()
    for base in cls.__mro__[1:]:
        inherited |= set(getattr(base, "__dataclass_fields__", ()))
    own = set(cls.__dataclass_fields__) - inherited

    import re

    head = re.search(rf"^class {name}\b[^\n]*:$", source, re.M)
    assert head, f"{name} is not declared in frames.py"
    body = source[head.end() :].split("\n@dataclass", 1)[0]
    documented = body.count("#:")
    assert documented >= len(own), (
        f"{name} declares {len(own)} fields of its own but describes "
        f"{documented}"
    )
