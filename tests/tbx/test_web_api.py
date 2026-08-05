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
