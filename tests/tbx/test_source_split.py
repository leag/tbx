"""Size-bounded BAS output at byte-invisible procedure seams."""

import pytest

from tbx import emit0


def _expand(bundle: emit0.SourceBundle) -> str:
    text = bundle.root
    for name, include in bundle.includes:
        text = text.replace(f'$INCLUDE "{name}"\n', include)
    return text


def test_split_preserves_the_rendered_byte_stream_at_line_seams():
    source = "".join(f'{n} PRINT "LINE {n}"\n' for n in range(10, 100, 10))

    bundle = emit0.split_source(
        source, prefix="long-name", limit=200, include_limit=50, force=True
    )

    assert _expand(bundle) == source
    assert [name for name, _ in bundle.includes] == [
        "LONGN001.INC",
        "LONGN002.INC",
        "LONGN003.INC",
        "LONGN004.INC",
        "LONGN005.INC",
    ]
    assert len(bundle.root.encode("latin-1")) <= 200
    assert all(len(text.encode("latin-1")) <= 50 for _, text in bundle.includes)


def test_a_scanned_sub_program_fails_loud():
    source = (
        "10 A = 1\n"
        "20 SUB SUB1\n"
        "END SUB\n"
        "30 SUB SUB2\n"
        "END SUB\n"
        "40 END\n"
    )

    with pytest.raises(ValueError, match="scanned statements"):
        emit0.split_source(source, limit=55)


def test_source_under_the_limit_is_left_alone():
    bundle = emit0.split_source("10 END\n", limit=20)

    assert bundle == emit0.SourceBundle("10 END\n")


def test_force_splits_an_under_limit_source_for_oracle_calibration():
    source = "10 A = 1\n20 B = 2\n30 END\n"

    bundle = emit0.split_source(
        source, prefix="probe", limit=100, include_limit=15, force=True
    )

    assert bundle.root == (
        '$INCLUDE "PROBE001.INC"\n'
        '$INCLUDE "PROBE002.INC"\n'
        '$INCLUDE "PROBE003.INC"\n'
    )
    assert _expand(bundle) == source


def test_an_over_limit_main_without_procedures_splits_at_physical_lines():
    source = "".join(f'{n} PRINT "1234567890"\n' for n in range(10, 60, 10))

    bundle = emit0.split_source(source, limit=70)

    assert len(bundle.includes) == 2
    assert _expand(bundle) == source


def test_a_single_large_procedure_does_not_get_an_uncalibrated_fallback():
    source = (
        "10 SUB SUB1\n"
        + '  PRINT "TOO LONG"\n' * 5
        + "END SUB\n20 END\n"
    )

    with pytest.raises(ValueError, match="scanned statements"):
        emit0.split_source(source, limit=70)


def test_single_line_def_fn_is_not_mistaken_for_a_block():
    source = "".join(
        f"{n} DEF FNFN{n}(A) = A + 1\n" for n in range(10, 50, 10)
    )

    bundle = emit0.split_source(source, limit=70)

    assert _expand(bundle) == source


def test_a_physical_line_larger_than_one_file_fails_loud():
    with pytest.raises(ValueError, match="one physical source line"):
        emit0.split_source('10 PRINT "TOO LONG"\n', limit=10)
