"""A `cd ec b8` match inside packed data is not a prologue.

`find_prologue` locates the dialect signature by content search, which finds
those three bytes wherever they occur -- including inside COMPRESSED payload.
Decoding then starts on whatever follows and dies with `unhandled byte 9e`,
which reads like a missing opcode and lands the file in the wild-corpus
failure tally as though the byte vocabulary were incomplete.

Two wild files were exactly this and neither is a decoder gap:

- brotheru.exe is LZEXE-compressed (`LZ91` at 0x1C, and the classic
  `06 0e 1f 8b 0e 0c 00` decompressor stub at its entry). Its ONE `cd ec b8`
  match is a coincidence in the packed bytes.
- pcdcfile.exe declares cs:ip = fff0:0100, an entry point 0x100020 bytes into
  a 119901-byte file.

The guard is the entry stub. Every Turbo Basic EXE begins at
`mov cs:[00b2], ds` -- the linked runtime's startup, ahead of any user code.
Measured over every MZ file in the fixture corpus and the wild set: 1220 begin
with `2e 8c 1e` and nothing else does, so this separates "cannot be a plain TB
image" from "TB image the decoder cannot yet read" without a heuristic.
"""

import glob
import os
import struct

import pytest

from tbx import decode0
from tbx.decode0 import dialect

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CORPUS = os.path.join(_ROOT, "fixtures", "corpus")


def test_every_corpus_fixture_carries_the_entry_stub():
    """The signature has to hold for all of them, or it is not a signature."""
    missing = []
    for path in sorted(glob.glob(os.path.join(_CORPUS, "*.exe"))):
        with open(path, "rb") as handle:
            exe = handle.read()
        if exe[:2] != b"MZ":
            continue
        if dialect._not_a_plain_tb_image(exe) is not None:
            missing.append(os.path.basename(path))

    assert not missing, missing


@pytest.mark.parametrize(
    ("name", "expected"),
    (
        ("brotheru.exe", "LZEXE-compressed"),
        ("pcdcfile.exe", "past the"),
    ),
)
def test_a_packed_or_bogus_image_says_so(name, expected):
    hits = os.path.join(os.path.dirname(_ROOT), "wild", "hits", name)
    if not os.path.isfile(hits):  # wild/hits is gitignored
        pytest.skip(f"{name} not present")

    with open(hits, "rb") as handle:
        exe = handle.read()

    with pytest.raises(ValueError) as caught:
        decode0.decode_user_code(exe)

    message = str(caught.value)
    assert "not a plain Turbo Basic EXE" in message, message
    assert expected in message, message
    # The misleading old signature must not come back.
    assert "unhandled byte" not in message, message


def test_a_non_mz_input_is_left_to_the_old_path():
    """The guard must not claim jurisdiction over things it cannot judge."""
    assert dialect._not_a_plain_tb_image(b"not an exe at all") is None
    assert dialect._not_a_plain_tb_image(b"") is None


def test_the_entry_offset_follows_the_mz_header():
    """cs:ip is relative to the header, which is what makes fff0:0100 land
    past the end of a small file rather than somewhere plausible."""
    header = bytearray(0x40)
    header[0:2] = b"MZ"
    struct.pack_into("<H", header, 8, 2)  # hdrpar
    struct.pack_into("<HH", header, 20, 0x1AA, 0)  # ip, cs

    assert dialect._entry_offset(bytes(header)) == 2 * 16 + 0x1AA
