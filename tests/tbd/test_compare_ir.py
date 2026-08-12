from pathlib import Path

from tbx.tools.compare_tbd_ir import compare_paths, main

_CORPUS = Path(__file__).parents[1] / "fixtures" / "corpus"


def test_comparison_checks_exact_canonical_trees_for_migrated_fixtures():
    paths = [
        _CORPUS / f"{stem}.exe"
        for stem in ("t1_addimm", "t1_print", "t1_if", "t1_delay")
    ]

    report = compare_paths(paths)

    assert report.files == 4
    assert report.failures == 0
    assert report.tbx_statements == report.tbd_statements == 18
    assert report.aligned_kinds == 18
    assert report.kind_match_files == 4
    assert report.comparable_files == report.exact_files == 4


def test_comparison_separates_kind_and_tree_mismatches():
    report = compare_paths([_CORPUS / "t1_meta0.exe"])

    assert report.kind_match_files == 1
    assert report.comparable_files == 1
    assert report.exact_files == 0
    assert report.mismatches[0].category == "tree"
    assert "A%" in report.mismatches[0].detail


def test_comparison_cli_prints_coverage(capsys):
    result = main([str(_CORPUS / "t1_delay.exe"), "--examples", "0"])

    assert result == 0
    output = capsys.readouterr().out
    assert "statements: tbx=2 tbd=2 recovery=100.0%" in output
    assert "exact canonical trees: 1/1 comparable" in output
