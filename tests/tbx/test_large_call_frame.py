"""Large stack-temporary allocation used while staging CALL arguments."""

from pathlib import Path

import pytest

from tbx import decode0
from tbx.decode0 import scan

_ROOT = Path(__file__).resolve().parents[2]


def test_scan_large_call_frame_allocation():
    ops = []
    data = bytes.fromhex("81 ec 8a 00")
    assert scan._scan_direct(data, 0, data[0], decode0.TB11, ops, 0) == 4
    assert ops == [(0, "sub_sp", 0x8A)]


def test_scan_large_local_literal_store():
    ops = []
    data = bytes.fromhex("c7 86 86 00 07 00")
    assert scan._scan_direct2(data, 0, data[0], ops) == 6
    assert ops == [(0, "mov_bp_imm", 0x86, 7)]


def test_scan_large_local_add():
    ops = []
    data = bytes.fromhex("03 86 86 00")
    assert scan._scan_direct2(data, 0, data[0], ops) == 4
    assert ops == [(0, "addax_bp", 0x86)]


def test_scan_large_local_load_and_store():
    load_ops = []
    load = bytes.fromhex("8b 86 86 00")
    assert scan._scan_direct2(load, 0, load[0], load_ops) == 4
    assert load_ops == [(0, "movax_bp", 0x86)]

    store_ops = []
    store = bytes.fromhex("89 86 86 00")
    assert scan._scan_direct2(store, 0, store[0], store_ops) == 4
    assert store_ops == [(0, "movm_ax_bp", 0x86)]


def test_scan_large_local_step_sign_test():
    ops = []
    data = bytes.fromhex("f7 86 8a 00 00 80")
    assert scan._scan_direct(data, 0, data[0], decode0.TB11, ops, 0) == 6
    assert ops == [(0, "testw_bp", 0x8A, 0x8000)]


def test_scan_large_local_compare():
    ops = []
    data = bytes.fromhex("3b 86 84 00")
    assert scan._scan_direct2(data, 0, data[0], ops) == 4
    assert ops == [(0, "cmpax_bp", 0x84)]


@pytest.mark.parametrize(
    ("stem", "next_gap"),
    [
        ("cleanup.exe", "unhandled INT EC sub f0 at 0xbcb2"),
        ("reformat.exe", "unhandled INT EC sub f0 at 0xbcab"),
    ],
)
def test_large_local_family_advances_wild_program(stem, next_gap):
    data = (_ROOT / "wild" / "hits" / stem).read_bytes()
    with pytest.raises(ValueError, match=next_gap):
        decode0.decode_user_code(data)
