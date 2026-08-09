"""`INPUT X$` inside a DEF FN body writes the function's own parameter.

The string store into a DEF FN frame slot had exactly one shape: pop the
staged value off the string stack and assign it. A store with NOTHING staged
therefore raised `string store to [bp+N] in DEF FN body with no staged value`,
with a comment noting the shape was "not an assignment at all" -- correct, and
this is what it is. INPUT names its target instead of pushing a value, so the
op stream reads `input; read_str; movsi; strassign_bp` and the stack is empty
by design.

The LOCAL branch immediately above already routes exactly this through
`_input_target`; the DEF FN branch simply never did. Wild crossref.exe hits it
at [bp+68].

Deliberately narrow: the LOCAL branch also routes FIELD reads (`_FREAD`),
`GET$` (`pend_getstr`) and `READ` (`_READDATA`) the same way. None of those
has a DEF FN witness, so they still raise rather than being assumed to behave
like INPUT. Both dialects verified byte-exact.
"""

import os

import pytest

from tbx import decode0

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CORPUS = os.path.join(_ROOT, "fixtures", "corpus")


@pytest.mark.parametrize("stem", ("t1_fninput", "v10_t1_fninput"))
def test_input_into_a_def_fn_string_parameter(stem):
    with open(os.path.join(_CORPUS, f"{stem}.exe"), "rb") as handle:
        exe = handle.read()

    source = "\n".join(str(s) for s in decode0.decode_user_code(exe))

    assert "Input" in source, source
    # The INPUT targets the parameter, not a fresh local or the result cell.
    assert "P04$" in source or "A$" in source, source


@pytest.mark.parametrize("stem", ("t1_fninput", "v10_t1_fninput"))
def test_the_function_still_returns_its_parameter(stem):
    """The INPUT must not consume the assignment that follows it.

    `FNA$ = X$` comes straight after `INPUT X$`; routing the INPUT through the
    wrong branch would either swallow that statement or leave the string stack
    unbalanced for it.
    """
    with open(os.path.join(_CORPUS, f"{stem}.exe"), "rb") as handle:
        exe = handle.read()

    stmts = tuple(decode0.decode_user_code(exe))

    fn = next(s for s in stmts if type(s).__name__ == "DefFn")
    body = [type(s).__name__ for s in fn.body]

    # INPUT then the result assignment, in that order, inside the body.
    assert body == ["Input", "FnResult"], body
    assert fn.params == ("A$",), fn.params
