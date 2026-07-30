from tbx.tools import scan_wild


def test_8087_builds_share_the_authored_program_family():
    assert scan_wild.program_family("wild/hits/cal.exe") == "cal"
    assert scan_wild.program_family("wild/hits/cal87.exe") == "cal"
    assert scan_wild.program_family("archive.zip!BIN/ELEC87.EXE") == "electron"
    assert scan_wild.program_family("wild/hits/inv87.exe") == "invoice"
    assert scan_wild.program_family("wild/hits/mdb87.exe") == "mdb"
    assert scan_wild.program_family("wild/hits/onelab87.exe") == "onelabel"
    assert scan_wild.program_family("wild/hits/state87.exe") == "state"


def test_family_totals_keep_variant_outcomes_separate(monkeypatch):
    monkeypatch.setattr(
        scan_wild,
        "hits",
        [
            ("cal.exe", "1.1", 1),
            ("cal87.exe", "1.1", 1),
            ("state.exe", "1.1", 1),
        ],
    )
    monkeypatch.setattr(
        scan_wild,
        "fails",
        [
            ("state87.exe", "1.1", "gap"),
            ("other.exe", "1.1", "gap"),
        ],
    )

    assert scan_wild.family_totals() == (3, 2, 2)
