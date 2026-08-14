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
    assert report.exact_files == 1
    assert report.mismatches == ()


def test_anchored_slot_types_close_both_dialect_tree_mismatches():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in ("t1_meta0", "t1_soundm", "t1_stack", "t1_stack4")
    ]

    report = compare_paths(paths)

    assert report.comparable_files == 8
    assert report.exact_files == 8
    assert report.mismatches == ()


def test_signature_complete_beep_is_an_exact_migrated_statement():
    paths = [
        _CORPUS / f"{prefix}t1_beep.exe"
        for prefix in ("", "v10_")
    ]

    report = compare_paths(paths)

    assert report.comparable_files == report.exact_files == 2
    assert report.mismatches == ()


def test_static_array_facts_close_both_dialect_tree_comparisons():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in ("t1_arr1", "t1_arr2", "t1_arr_mix", "t1_arr_two")
    ]

    report = compare_paths(paths)

    assert report.comparable_files == report.exact_files == 8
    assert report.mismatches == ()


def test_explicit_static_array_bounds_compare_as_bounds():
    report = compare_paths([_CORPUS / "v10_t1_intarrconst.exe"])

    assert report.comparable_files == report.exact_files == 1
    assert report.mismatches == ()


def test_wide_fp_facts_improve_both_dialect_assignment_alignment():
    paths = [
        _CORPUS / f"{prefix}t1_convf.exe"
        for prefix in ("", "v10_")
    ]

    report = compare_paths(paths)

    assert report.failures == 0
    assert report.tbx_statements == 8
    assert report.tbd_statements == 6
    assert report.aligned_by_kind["Assign"] == 4
    assert report.aligned_by_kind["End"] == 2


def test_long_fp_facts_close_direct_long_tree_comparisons():
    paths = [
        _CORPUS / f"{stem}.exe"
        for stem in ("zz_vm_ladd", "zz_vm_lsub", "zz_vm_lmul", "zz_vm_lmix")
    ]

    report = compare_paths(paths)

    assert report.tbx_statements == report.tbd_statements == 22
    assert report.aligned_kinds == 22
    assert report.comparable_files == report.exact_files == 4
    assert report.mismatches == ()


def test_wrapped_code_segment_branches_recover_large_source_regions():
    paths = [
        _CORPUS / f"{prefix}t1_bigjmp.exe"
        for prefix in ("", "v10_")
    ]

    report = compare_paths(paths)

    assert report.failures == 0
    assert report.tbx_statements == 5616
    assert report.tbd_statements == report.aligned_kinds == 5610
    assert report.aligned_by_kind["Assign"] == 5600
    assert report.aligned_by_kind["Print"] == 6


def test_comparison_cli_prints_coverage(capsys):
    result = main([str(_CORPUS / "t1_delay.exe"), "--examples", "0"])

    assert result == 0
    output = capsys.readouterr().out
    assert "statements: tbx=2 tbd=2 recovery=100.0%" in output
    assert "exact canonical trees: 1/1 comparable" in output
