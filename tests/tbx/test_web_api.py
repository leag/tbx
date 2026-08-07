from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tbx.tools import oracle
from tbx.web.app import app

client = TestClient(app)

FIXTURE = Path(__file__).parent.parent / "fixtures" / "corpus" / "f87_t1_beep.exe"


def _oracle_available() -> bool:
    try:
        oracle.preflight()
    except RuntimeError:
        return False
    return True


def _iced_x86_available() -> bool:
    try:
        import tbx.tools.insns  # noqa: F401
    except ImportError:
        return False
    return True


@pytest.mark.skipif(not _iced_x86_available(), reason="iced-x86 debug extra not installed")
def test_disassembly_returns_code_only_instructions():
    exe_bytes = FIXTURE.read_bytes()
    decompile_response = client.post(
        "/api/decompile", files={"exe": ("f87_t1_beep.exe", exe_bytes)}
    )
    session_id = decompile_response.json()["session_id"]

    response = client.post("/api/disassembly", json={"session_id": session_id})

    assert response.status_code == 200
    instructions = response.json()["instructions"]
    assert len(instructions) > 0
    assert all(set(i.keys()) == {"address", "text", "target"} for i in instructions)
    # Sorted, unique addresses -- decode_flow may skip unreached bytes
    # (data, jump tables) so this is no longer necessarily contiguous.
    addresses = [i["address"] for i in instructions]
    assert addresses == sorted(set(addresses))


def test_disassembly_unknown_session_returns_404():
    response = client.post("/api/disassembly", json={"session_id": "nope"})

    assert response.status_code == 404
    assert "error" in response.json()


@pytest.mark.skipif(not _iced_x86_available(), reason="iced-x86 debug extra not installed")
def test_disassembly_reaches_code_past_a_far_jump_on_tbd73():
    wild_path = Path(__file__).parent.parent.parent / "wild" / "hits" / "tbd73.exe"
    if not wild_path.exists():
        pytest.skip("wild/hits/tbd73.exe not present locally")

    decompile_response = client.post(
        "/api/decompile", files={"exe": ("tbd73.exe", wild_path.read_bytes())}
    )
    session_id = decompile_response.json()["session_id"]

    response = client.post("/api/disassembly", json={"session_id": session_id})

    instructions = response.json()["instructions"]
    addresses = {i["address"] for i in instructions}
    # 0x97b4 is the far jmp itself (the last instruction reached before far
    # jumps were followed); real code beyond the segment boundary it jumps
    # into starts well past it once they are.
    assert max(addresses) > 0x97B4


@pytest.mark.skipif(not _iced_x86_available(), reason="iced-x86 debug extra not installed")
def test_disassemble_bytes_matches_disassembly_for_the_same_exe():
    import base64

    exe_bytes = FIXTURE.read_bytes()
    decompile_response = client.post(
        "/api/decompile", files={"exe": ("f87_t1_beep.exe", exe_bytes)}
    )
    session_id = decompile_response.json()["session_id"]
    by_session = client.post("/api/disassembly", json={"session_id": session_id})

    data_b64 = base64.b64encode(exe_bytes).decode("ascii")
    by_bytes = client.post("/api/disassemble_bytes", json={"data_b64": data_b64})

    assert by_bytes.status_code == 200
    assert by_bytes.json() == by_session.json()


def test_disassemble_bytes_rejects_invalid_base64():
    response = client.post("/api/disassemble_bytes", json={"data_b64": "not valid base64!!"})

    assert response.status_code == 422
    assert "error" in response.json()


def test_decompile_returns_source_dialect_and_ir():
    exe_bytes = FIXTURE.read_bytes()

    response = client.post(
        "/api/decompile", files={"exe": ("f87_t1_beep.exe", exe_bytes)}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["dialect"] in ("1.0", "1.1")
    assert "BEEP" in body["source"] or len(body["source"]) > 0
    assert isinstance(body["ir"], list)
    assert len(body["ir"]) > 0
    assert isinstance(body["session_id"], str) and body["session_id"]
    assert isinstance(body["addresses"], list)
    assert len(body["addresses"]) == len(body["ir"])
    assert all(a is None or isinstance(a, int) for a in body["addresses"])
    assert isinstance(body["line_starts"], list)
    assert len(body["line_starts"]) == len(body["addresses"])
    assert body["line_starts"] == sorted(body["line_starts"])
    source_lines = body["source"].splitlines()
    assert all(0 <= n < len(source_lines) for n in body["line_starts"])


def test_decompile_line_starts_survive_a_program_with_block_structures():
    # tbd73.exe's IF/END IF, SUB/END SUB and $INLINE blocks mean a
    # top-level statement doesn't always emit exactly one digit-prefixed
    # line -- 70 top-level statements produce 97 lines matching that
    # pattern. line_starts must still pair each statement with its real
    # line 1:1, rather than a count of numbered-looking lines drifting out
    # of sync partway through (the bug this endpoint exists to avoid).
    # wild/hits/ is gitignored (a local scratch corpus, not a fixture) --
    # skip where it isn't present rather than asserting on a file that
    # can't be relied on to exist.
    wild_path = Path(__file__).parent.parent.parent / "wild" / "hits" / "tbd73.exe"
    if not wild_path.exists():
        pytest.skip("wild/hits/tbd73.exe not present locally")
    exe_bytes = wild_path.read_bytes()

    response = client.post("/api/decompile", files={"exe": ("tbd73.exe", exe_bytes)})

    assert response.status_code == 200
    body = response.json()
    assert len(body["line_starts"]) == len(body["addresses"])
    source_lines = body["source"].splitlines()
    for i, address in enumerate(body["addresses"]):
        if address is None:
            continue
        line_text = source_lines[body["line_starts"][i]]
        assert line_text.strip(), f"statement {i} points at a blank line"


def test_decompile_garbage_bytes_returns_diagnostics_error():
    response = client.post(
        "/api/decompile", files={"exe": ("bad.exe", b"not an exe")}
    )

    assert response.status_code == 422
    body = response.json()
    assert "error" in body
    assert "phase=" in body["error"]


def test_recompile_unknown_session_returns_404():
    response = client.post(
        "/api/recompile", json={"session_id": "nope", "source": "10 END"}
    )

    assert response.status_code == 404
    assert "error" in response.json()


def test_dialects_lists_the_oracles_supported_dialects():
    response = client.get("/api/dialects")

    assert response.status_code == 200
    body = response.json()
    assert "1.1" in body["dialects"]
    assert "1.0" in body["dialects"]


def test_toggles_lists_the_ide_options_toggles():
    response = client.get("/api/toggles")

    assert response.status_code == 200
    letters = {entry["letter"] for entry in response.json()["toggles"]}
    assert letters == {"8", "K", "B", "O", "S"}


@pytest.mark.skipif(not _oracle_available(), reason="Turbo Basic oracle not provisioned locally")
def test_recompile_rejects_an_unknown_toggle_letter():
    exe_bytes = FIXTURE.read_bytes()
    decompile_response = client.post(
        "/api/decompile", files={"exe": ("f87_t1_beep.exe", exe_bytes)}
    )
    session_id = decompile_response.json()["session_id"]
    source = decompile_response.json()["source"]

    response = client.post(
        "/api/recompile",
        json={"session_id": session_id, "source": source, "toggles": "Z"},
    )

    assert response.status_code == 422
    assert "error" in response.json()


@pytest.mark.skipif(not _oracle_available(), reason="Turbo Basic oracle not provisioned locally")
def test_recompile_rejects_an_unknown_dialect_override():
    exe_bytes = FIXTURE.read_bytes()
    decompile_response = client.post(
        "/api/decompile", files={"exe": ("f87_t1_beep.exe", exe_bytes)}
    )
    session_id = decompile_response.json()["session_id"]
    source = decompile_response.json()["source"]

    response = client.post(
        "/api/recompile",
        json={"session_id": session_id, "source": source, "dialect": "9.9"},
    )

    assert response.status_code == 422
    assert "error" in response.json()


@pytest.mark.skipif(not _oracle_available(), reason="Turbo Basic oracle not provisioned locally")
def test_recompile_matching_source_reports_full_match():
    exe_bytes = FIXTURE.read_bytes()
    decompile_response = client.post(
        "/api/decompile", files={"exe": ("f87_t1_beep.exe", exe_bytes)}
    )
    session_id = decompile_response.json()["session_id"]
    source = decompile_response.json()["source"]

    response = client.post(
        "/api/recompile", json={"session_id": session_id, "source": source}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["matched"] is True
    assert body["ratio"] == 1.0
    assert body["first_diff_offset"] is None
    import base64

    assert base64.b64decode(body["original_b64"]) == exe_bytes
    assert base64.b64decode(body["recompiled_b64"]) == exe_bytes


def test_decompile_inline_fixture_with_raw_bytes_does_not_crash():
    # t1_inline.exe contains a $INLINE block, whose ir.Inline node carries a
    # raw `data: bytes` field that must not be passed to jsonable_encoder
    # as-is (it is not UTF-8 and previously crashed with a bare 500).
    inline_fixture = Path(__file__).parent.parent / "fixtures" / "corpus" / "t1_inline.exe"
    exe_bytes = inline_fixture.read_bytes()

    response = client.post("/api/decompile", files={"exe": ("t1_inline.exe", exe_bytes)})

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body["ir"], list)
    assert len(body["ir"]) > 0


@pytest.mark.skipif(not _oracle_available(), reason="Turbo Basic oracle not provisioned locally")
def test_recompile_invalid_source_returns_compiler_error():
    exe_bytes = FIXTURE.read_bytes()
    decompile_response = client.post(
        "/api/decompile", files={"exe": ("f87_t1_beep.exe", exe_bytes)}
    )
    session_id = decompile_response.json()["session_id"]

    response = client.post(
        "/api/recompile",
        json={"session_id": session_id, "source": "10 THIS IS NOT BASIC ^^^"},
    )

    assert response.status_code == 422
    assert "error" in response.json()


@pytest.mark.skipif(not _oracle_available(), reason="Turbo Basic oracle not provisioned locally")
def test_recompile_splits_a_too_large_procedure_free_source_and_still_compiles():
    # Turbo Basic's editor can't load a source file over ~64KB at all (a
    # real compiler-era limit -- k.exe and cal.exe are wild witnesses).
    # A procedure-free program can sidestep it the same way the compiler's
    # own $INCLUDE does: split_source breaks it into <=32KB chunks a short
    # root $INCLUDEs, which this endpoint now does automatically.
    exe_bytes = FIXTURE.read_bytes()
    decompile_response = client.post(
        "/api/decompile", files={"exe": ("f87_t1_beep.exe", exe_bytes)}
    )
    session_id = decompile_response.json()["session_id"]

    lines = [f'{n} PRINT "{"X" * 60}"' for n in range(10, 10 + 2000 * 10, 10)]
    source = "\n".join(lines) + "\n"
    assert len(source.encode("latin-1")) > 65535

    response = client.post("/api/recompile", json={"session_id": session_id, "source": source})

    assert response.status_code == 200
    assert response.json()["recompiled_len"] > 0


@pytest.mark.skipif(not _oracle_available(), reason="Turbo Basic oracle not provisioned locally")
def test_recompile_rejects_a_too_large_source_with_subs_clearly():
    # Turbo Basic rejects $INCLUDE alongside a scanned SUB/block DEF FN, so
    # split_source can't help a too-large program that declares one --
    # it should say so plainly rather than failing generically or handing
    # the oracle a file it was never going to be able to load.
    exe_bytes = FIXTURE.read_bytes()
    decompile_response = client.post(
        "/api/decompile", files={"exe": ("f87_t1_beep.exe", exe_bytes)}
    )
    session_id = decompile_response.json()["session_id"]

    lines = ["10 SUB FOO", "20 END SUB"]
    lines += [f'{n} PRINT "{"X" * 60}"' for n in range(30, 30 + 2000 * 10, 10)]
    source = "\n".join(lines) + "\n"
    assert len(source.encode("latin-1")) > 65535

    response = client.post("/api/recompile", json={"session_id": session_id, "source": source})

    assert response.status_code == 422
    assert "SUB" in response.json()["error"]
