from pathlib import Path

from tbx import decode0, ir as tbx_ir
from tbx.tools.compare_tbd_ir import _statement, compare_paths, main
from tbd import decode

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


def test_signature_complete_operandless_statements_are_exact():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in ("t1_keylist", "t1_mtimer", "t1_reset", "t1_scr")
    ]

    report = compare_paths(paths)

    assert report.comparable_files == report.exact_files == 8
    assert report.mismatches == ()


def test_signature_complete_key_toggle_operands_are_exact():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in ("t1_keyoff", "t1_keyon")
    ]

    report = compare_paths(paths)

    assert report.comparable_files == report.exact_files == 4
    assert report.mismatches == ()


def test_control_operands_are_exact_migrated_statements():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in ("t1_onerr", "t1_ongoto", "t1_ongosub", "t1_run2")
    ]

    report = compare_paths(paths)

    assert report.comparable_files == report.exact_files == 8
    assert report.mismatches == ()


def test_complete_out_scaffolds_are_exact_in_both_dialects():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in ("t1_out", "t1_out2")
    ]

    report = compare_paths(paths)

    assert report.tbx_statements == report.tbd_statements == 10
    assert report.aligned_kinds == 10
    assert report.comparable_files == report.exact_files == 4
    assert report.mismatches == ()


def test_complete_wait_scaffolds_are_exact_in_both_dialects():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in ("t1_wait", "t1_wait3")
    ]

    report = compare_paths(paths)

    assert report.tbx_statements == report.tbd_statements == 8
    assert report.aligned_kinds == 8
    assert report.comparable_files == report.exact_files == 4
    assert report.mismatches == ()


def test_resolved_lprint_chain_is_exact_in_both_dialects():
    paths = [
        _CORPUS / f"{prefix}t1_lprint.exe"
        for prefix in ("", "v10_")
    ]

    report = compare_paths(paths)

    assert report.tbx_statements == report.tbd_statements == 4
    assert report.aligned_kinds == 4
    assert report.comparable_files == report.exact_files == 2
    assert report.mismatches == ()


def test_consecutive_printer_flush_recovers_blank_lprint_exactly():
    report = compare_paths([_CORPUS / "t1_lpstr.exe"])

    assert report.comparable_files == report.exact_files == 1
    assert report.mismatches == ()


def test_immediate_printer_controls_produce_an_exact_lprint_tree():
    report = compare_paths([_CORPUS / "t1_ltab.exe"])

    assert report.tbx_statements == report.tbd_statements == 3
    assert report.aligned_kinds == 3
    assert report.comparable_files == report.exact_files == 1
    assert report.mismatches == ()


def test_complete_write_chains_align_in_both_modes_and_dialects():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in ("t1_write", "t1_writefile")
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["Write"] == 4
    assert report.kind_match_files == 4


def test_complete_lset_rset_scaffolds_are_exact_in_both_dialects():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in ("t1_lset", "t1_rset")
    ]
    report = compare_paths(paths)

    assert report.comparable_files == report.exact_files == 4
    assert report.mismatches == ()


def test_scalar_mid_assignments_are_exact_in_both_dialects():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in ("t1_midas", "t1_midvarstart", "t1_mid3")
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["MidAssign"] == 6
    assert report.comparable_files == report.exact_files == 6
    assert report.mismatches == ()


def test_scalar_swap_template_is_exact_in_both_dialects():
    paths = [
        _CORPUS / f"{prefix}t1_swap.exe"
        for prefix in ("", "v10_")
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["Swap"] == 2
    assert report.comparable_files == report.exact_files == 2
    assert report.mismatches == ()


def test_static_array_swap_templates_align_with_tbx():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in ("t1_arrswap", "t1_arrswapf")
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["Swap"] == report.tbx_kinds["Swap"] == 4


def test_grouped_constant_locate_forms_align_with_tbx():
    stems = (
        "t1_locateomit",
        "t1_locate5",
        "t1_loccurs",
        "v10_t1_loccurs",
        "t1_scr2",
        "v10_t1_scr2",
        "t1_addpool",
        "v10_t1_addpool",
        "t1_locarr",
        "v10_t1_locarr",
        "t1_locarrcom",
        "v10_t1_locarrcom",
    )
    report = compare_paths([_CORPUS / f"{stem}.exe" for stem in stems])

    assert report.aligned_by_kind["Locate"] == report.tbx_kinds["Locate"] == 15
    assert report.failures == 0


def test_color_operands_are_exact_across_masks_and_dialects():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in ("t1_scr", "t1_scr2", "t1_color3", "t1_colorfp")
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["Color"] == report.tbx_kinds["Color"] == 10
    assert report.comparable_files == report.exact_files == 8
    assert report.mismatches == ()


def test_screen_operands_are_exact_across_calibrated_masks():
    paths = [
        _CORPUS / name
        for name in (
            "t1_blitline.exe",
            "t1_paintt.exe",
            "t1_screen.exe",
            "t1_screena.exe",
            "t1_screenb.exe",
            "t1_screenp.exe",
            "t1_viewbare.exe",
            "v10_t1_blitline.exe",
            "v10_t1_screen.exe",
            "v10_t1_viewbare.exe",
        )
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["Screen"] == report.tbx_kinds["Screen"] == 12
    assert report.comparable_files == report.exact_files == 3


def test_files_forms_are_exact_in_both_dialects():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in ("t1_files", "t1_files0")
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["Files"] == report.tbx_kinds["Files"] == 4
    assert report.comparable_files == report.exact_files == 4
    assert report.mismatches == ()


def test_single_string_statement_scaffolds_are_exact_in_both_dialects():
    stems = (
        "t1_chdir",
        "t1_dates",
        "t1_draw",
        "t1_environ",
        "t1_kill",
        "t1_mkdir",
        "t1_play",
        "t1_rmdir",
        "t1_shell",
        "t1_times",
    )
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in stems
    ]
    report = compare_paths(paths)

    for kind in ("Chdir", "Draw", "Environ", "Kill", "Mkdir", "Play", "Rmdir"):
        assert report.aligned_by_kind[kind] == report.tbx_kinds[kind] == 2
    assert report.aligned_by_kind["DateTimeSet"] == report.tbx_kinds["DateTimeSet"] == 4
    assert report.aligned_by_kind["Shell"] == report.tbx_kinds["Shell"] == 2
    assert report.comparable_files == report.exact_files == 20
    assert report.mismatches == ()


def test_direct_integer_for_loops_are_exact_in_both_dialects():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in (
            "t1_forstep",
            "t1_forstepm1",
            "t1_forstepn",
            "t1_forbig",
            "t1_forvarinit",
        )
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["For"] == report.tbx_kinds["For"] == 10
    assert report.aligned_by_kind["NextStmt"] == report.tbx_kinds["NextStmt"] == 10
    assert report.comparable_files == report.exact_files == 10
    assert report.mismatches == ()


def test_direct_integer_for_variable_limit_is_exact_in_both_dialects():
    paths = [
        _CORPUS / f"{prefix}t1_forvarlimneg.exe"
        for prefix in ("", "v10_")
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["For"] == report.tbx_kinds["For"] == 2
    assert report.aligned_by_kind["NextStmt"] == report.tbx_kinds["NextStmt"] == 2
    assert report.comparable_files == report.exact_files == 2
    assert report.mismatches == ()


def test_direct_integer_variable_step_loops_are_exact():
    paths = [
        _CORPUS / name
        for name in (
            "t1_forvarstep.exe",
            "v10_t1_forvarstep.exe",
            "t1_forvarstep2.exe",
            "v10_t1_forvarstep2.exe",
            "v10_t1_forvarstepinit.exe",
        )
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["For"] == report.tbx_kinds["For"] == 5
    assert report.aligned_by_kind["NextStmt"] == report.tbx_kinds["NextStmt"] == 5
    assert report.comparable_files == report.exact_files == 3


def test_fp_for_templates_are_exact_across_dialects_widths_and_distances():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in ("t1_for", "t1_for2", "t1_forlongfp")
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["For"] == report.tbx_kinds["For"] == 8
    assert report.aligned_by_kind["NextStmt"] == report.tbx_kinds["NextStmt"] == 8
    assert report.comparable_files == report.exact_files == 6
    assert report.mismatches == ()


def test_simple_do_loop_templates_are_exact():
    paths = [
        _CORPUS / name
        for name in (
            "t1_while.exe",
            "v10_t1_while.exe",
            "zz_do2.exe",
            "zz_do3.exe",
            "zz_do4.exe",
            "zz_do7.exe",
        )
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["Do"] == report.tbx_kinds["Do"] == 6
    assert report.aligned_by_kind["Loop"] == report.tbx_kinds["Loop"] == 6
    assert report.comparable_files == report.exact_files == 6
    assert report.mismatches == ()


def test_codeless_common_band_statements_are_exact():
    paths = [
        _CORPUS / name
        for name in (
            "t1_common1.exe",
            "t1_common2.exe",
            "v10_t1_common2.exe",
        )
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["Common"] == report.tbx_kinds["Common"] == 3
    assert report.comparable_files == report.exact_files == 3
    assert report.mismatches == ()


def test_common_slot_names_make_all_dim_trees_exact():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in (
            "t1_commonrt",
            "t1_erasesubcommon",
            "t1_locarrcom",
        )
    ]
    expected = actual = 0
    for path in paths:
        exact = decode0.decode_user_code(path.read_bytes())
        migrated = decode(path.read_bytes()).canonical_statements
        exact_dims = [
            _statement(node)
            for node in exact
            if isinstance(node, tbx_ir.Dim)
        ]
        migrated_dims = [
            (node.kind, node.operands)
            for node in migrated
            if node.kind == "Dim"
        ]
        expected += len(exact_dims)
        actual += len(migrated_dims)
        assert migrated_dims == exact_dims

    assert expected == actual == 8


def test_option_base_votes_materialize_all_corpus_declarations_exactly():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in (
            "t1_dimm",
            "t1_dimv2",
            "t1_dimw",
            "t1_dimw2",
            "t1_dimw3",
            "t1_mix",
            "t1_mix2",
            "t1_mix3",
        )
    ] + [_CORPUS / "fbd_t1_dimm.exe"]
    expected = actual = 0
    for path in paths:
        exact = decode0.decode_user_code(path.read_bytes())
        migrated = decode(path.read_bytes()).canonical_statements
        exact_options = [
            _statement(node)
            for node in exact
            if isinstance(node, tbx_ir.OptionBase)
        ]
        migrated_options = [
            (node.kind, node.operands)
            for node in migrated
            if node.kind == "OptionBase"
        ]
        expected += len(exact_options)
        actual += len(migrated_options)
        assert migrated_options == exact_options

    assert expected == actual == 17


def test_numeric_read_chains_align_in_both_dialects():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in ("t1_readnum", "t1_readfp", "t1_readalt")
    ]
    paths += [
        _CORPUS / f"{stem}.exe"
        for stem in (
            "t1_databig",
            "t1_datasharedlit",
            "t1_readsarr",
            "t1_readstr",
            "v10_t1_readiarr",
            "v10_t1_readsarr",
            "v10_t1_readstr",
        )
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["Read"] == report.tbx_kinds["Read"] == 13
    assert report.failures == 0


def test_scalar_input_file_chains_align_with_tbx():
    stems = (
        "t1_file",
        "v10_t1_file",
        "t1_file2",
        "v10_t1_file2",
        "t1_open2",
        "t1_fileint",
        "v10_t1_fileint",
        "t1_inpfilearr",
        "v10_t1_inpfilearr",
        "t1_sarr2",
        "v10_t1_sarr2",
    )
    report = compare_paths([_CORPUS / f"{stem}.exe" for stem in stems])

    assert report.aligned_by_kind["InputFile"] == report.tbx_kinds["InputFile"] == 13
    assert report.failures == 0


def test_console_input_scalar_and_multi_target_chains_align_with_tbx():
    stems = (
        "t1_inp",
        "t1_inp2",
        "t1_inp4",
        "t1_inpdbl",
        "t1_inpmixed",
        "t1_inpmulti",
        "t1_inpmulti3",
        "t1_inpsemi",
        "t1_inpsemis",
    )
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in stems
        if (_CORPUS / f"{prefix}{stem}.exe").exists()
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["Input"] == report.tbx_kinds["Input"]
    assert report.failures == 0


def test_open_kinds_align_for_both_source_scaffolds():
    paths = [
        _CORPUS / "t1_open2.exe",
        _CORPUS / "t1_openfor.exe",
        _CORPUS / "v10_t1_openfor.exe",
        _CORPUS / "v10_t1_openrandomlen.exe",
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["Open"] == report.tbx_kinds["Open"]
    assert report.failures == 0


def test_file_print_channels_restore_exact_open_file_trees():
    paths = [
        _CORPUS / f"{stem}.exe"
        for stem in (
            "t1_close",
            "t1_fpcomma",
            "t1_open2",
            "t1_openfor",
            "v10_t1_fpcomma",
            "v10_t1_openfor",
        )
    ]
    report = compare_paths(paths)

    assert report.comparable_files == report.exact_files == len(paths)
    assert report.failures == 0


def test_close_channels_are_exact_for_all_calibrated_forms():
    paths = [
        _CORPUS / f"{stem}.exe"
        for stem in (
            "t1_close",
            "t1_file",
            "v10_t1_file",
            "t1_closevar",
            "v10_t1_closevar",
        )
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["Close"] == report.tbx_kinds["Close"] == 5
    assert report.failures == 0


def test_trap_control_operands_are_exact_in_both_dialects():
    stems = (
        "t1_oncom",
        "t1_onkey",
        "t1_onpen",
        "t1_onplay",
        "t1_ontimer",
        "t1_strigoff",
        "t1_strigon",
    )
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in stems
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["TrapCtl"] == report.tbx_kinds["TrapCtl"]
    assert report.failures == 0


def test_on_trap_operands_are_exact_in_both_dialects():
    stems = ("t1_oncom", "t1_onkey", "t1_onpen", "t1_onplay", "t1_ontimer")
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in stems
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["OnTrap"] == report.tbx_kinds["OnTrap"]
    assert report.comparable_files == report.exact_files == len(paths)
    assert report.failures == 0


def test_complete_field_descriptors_are_exact_in_both_dialects():
    paths = [
        _CORPUS / f"{prefix}t1_field.exe"
        for prefix in ("", "v10_")
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["Field"] == 2
    assert report.kind_match_files == 2
    assert report.mismatches == ()


def test_profile_dispatches_normalize_source_kinds_and_inline_payloads():
    stems = (
        "t1_close",
        "t1_erasestatic", "v10_t1_erasestatic",
        "t1_palettereset", "v10_t1_palettereset",
        "t1_lineinf", "v10_t1_lineinf",
        "t1_line", "v10_t1_line",
        "t1_circle", "v10_t1_circle",
        "t1_errorn", "v10_t1_errorn",
        "t1_ongoto", "v10_t1_ongoto",
    )

    report = compare_paths([_CORPUS / f"{stem}.exe" for stem in stems])

    assert report.failures == 0
    assert report.tbx_statements == report.tbd_statements == 56
    assert report.aligned_kinds == 56
    assert report.kind_match_files == len(stems)


def test_resume_signatures_close_handler_kind_sequences():
    stems = (
        "t1_onerr", "v10_t1_onerr",
        "t1_resumen", "v10_t1_resumen",
        "t1_resumel", "v10_t1_resumel",
        "t1_tronerr", "v10_t1_tronerr",
        "t1_resumefar",
    )

    report = compare_paths([_CORPUS / f"{stem}.exe" for stem in stems])

    assert report.failures == 0
    assert report.tbx_statements == report.tbd_statements == 45
    assert report.aligned_kinds == 45
    assert report.kind_match_files == len(stems)


def test_profiled_source_control_closes_checked_and_computed_calls():
    stems = (
        "fst_t1_gosub",
        "t1_ongosub", "v10_t1_ongosub",
        "t1_run", "v10_t1_run",
    )

    report = compare_paths([_CORPUS / f"{stem}.exe" for stem in stems])

    assert report.failures == 0
    assert report.tbx_statements == report.tbd_statements == 20
    assert report.aligned_kinds == 20
    assert report.kind_match_files == len(stems)


def test_defseg_profile_signatures_close_both_dialect_kind_sequences():
    stems = (
        "t1_defseg", "v10_t1_defseg",
        "t1_bload0", "v10_t1_bload0",
    )

    report = compare_paths([_CORPUS / f"{stem}.exe" for stem in stems])

    assert report.failures == 0
    assert report.tbx_statements == report.tbd_statements == 14
    assert report.aligned_kinds == 14
    assert report.kind_match_files == len(stems)


def test_inline_procedure_signatures_replace_false_gosub_returns():
    stems = ("t1_inline", "v10_t1_inline", "t1_inlinefile")

    report = compare_paths([_CORPUS / f"{stem}.exe" for stem in stems])

    assert report.failures == 0
    assert report.tbx_statements == report.tbd_statements == 10
    assert report.aligned_kinds == 10
    assert report.kind_match_files == len(stems)


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
    assert report.tbd_statements == report.aligned_kinds == 5614
    assert report.aligned_by_kind["Assign"] == 5600
    assert report.aligned_by_kind["Print"] == 6
    assert report.aligned_by_kind["Gosub"] == 2
    assert report.aligned_by_kind["Return"] == 2


def test_source_subroutine_facts_close_both_dialect_tree_comparisons():
    paths = [
        _CORPUS / f"{prefix}t1_gosub.exe"
        for prefix in ("", "v10_")
    ]

    report = compare_paths(paths)

    assert report.tbx_statements == report.tbd_statements == 12
    assert report.aligned_kinds == 12
    assert report.comparable_files == report.exact_files == 2
    assert report.mismatches == ()


def test_targeted_return_templates_align_all_authored_return_lines():
    paths = [
        _CORPUS / "t1_returngosub.exe",
        _CORPUS / "t1_returnline.exe",
        _CORPUS / "v10_t1_returnline.exe",
    ]

    report = compare_paths(paths)

    assert report.failures == 0
    assert report.aligned_by_kind["Return"] == 4


def test_framed_procedures_align_definition_and_call_structure():
    paths = [
        _CORPUS / f"{stem}.exe"
        for stem in (
            "t1_subdef",
            "v10_subdef",
            "t1_argrefonly",
            "v10_t1_argrefonly",
            "t1_declnoend",
            "v10_t1_declnoend",
            "t1_gotosubline",
        )
    ]

    report = compare_paths(paths)

    assert report.failures == 0
    assert report.kind_match_files == 7
    assert report.aligned_by_kind["SubDef"] == report.tbx_kinds["SubDef"]
    assert report.aligned_by_kind["CallStmt"] == report.tbx_kinds["CallStmt"]


def test_trace_hook_facts_align_simple_repeated_and_loop_regions():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in ("t1_tron", "t1_tron2r2", "t1_tronml", "t1_tronfor")
    ]

    report = compare_paths(paths)

    assert report.failures == 0
    assert report.aligned_by_kind["Tron"] == report.tbx_kinds["Tron"] == 12
    assert report.aligned_by_kind["Troff"] == report.tbx_kinds["Troff"] == 4


def test_simple_trace_toggle_regions_are_exact_migrated_statements():
    paths = [
        _CORPUS / f"{prefix}{stem}.exe"
        for prefix in ("", "v10_")
        for stem in ("t1_tron", "t1_tron2r2")
    ]

    report = compare_paths(paths)

    assert report.comparable_files == report.exact_files == 4
    assert report.mismatches == ()


def test_final_trace_hook_after_block_if_recovers_troff_in_both_dialects():
    paths = [
        _CORPUS / f"{prefix}t1_tronerb.exe"
        for prefix in ("", "v10_")
    ]
    report = compare_paths(paths)

    assert report.aligned_by_kind["Troff"] == report.tbx_kinds["Troff"] == 2
    assert report.failures == 0


def test_comparison_cli_prints_coverage(capsys):
    result = main([str(_CORPUS / "t1_delay.exe"), "--examples", "0"])

    assert result == 0
    output = capsys.readouterr().out
    assert "statements: tbx=2 tbd=2 recovery=100.0%" in output
    assert "exact canonical trees: 1/1 comparable" in output
