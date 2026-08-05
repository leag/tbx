from pathlib import Path

from fastapi.testclient import TestClient

from tbx.web.app import app

client = TestClient(app)

FIXTURE = Path(__file__).parent.parent / "fixtures" / "corpus" / "f87_t1_beep.exe"


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
