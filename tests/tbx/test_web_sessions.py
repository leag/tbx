import pytest

from tbx.web.sessions import SessionStore


def test_create_and_get_round_trips_exe_bytes(tmp_path):
    store = SessionStore(base_dir=tmp_path)
    session = store.create(b"\x4d\x5a\x00\x01", dialect="1.1")

    fetched = store.get(session.id)

    assert fetched.exe_path.read_bytes() == b"\x4d\x5a\x00\x01"
    assert fetched.dialect == "1.1"
    assert fetched.id == session.id


def test_get_unknown_session_raises_key_error(tmp_path):
    store = SessionStore(base_dir=tmp_path)

    with pytest.raises(KeyError):
        store.get("does-not-exist")
