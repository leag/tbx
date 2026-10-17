"""Undo executable packers seen on Turbo Basic programs.

Shareware authors often shrank their EXEs with LZEXE (0.90 and 0.91). The
packed file keeps nothing of the compiler's layout, so it has to be restored
before decoding. This is a port of the public-domain ``UNLZEXE`` algorithm.
"""

from __future__ import annotations

import struct


class UnpackError(ValueError):
    """The input looks packed but could not be restored."""


def detect(data: bytes) -> str | None:
    """Return the packer name (``"LZ90"``/``"LZ91"``) or ``None``."""

    if len(data) < 0x20 or data[:2] != b"MZ":
        return None
    words = struct.unpack_from("<16H", data, 0)
    if words[4] != 2 or words[0x0D] != 0 or words[0x0C] != 0x1C:
        return None
    magic = data[0x1C:0x20]
    if magic == b"LZ09":
        return "LZ90"
    if magic == b"LZ91":
        return "LZ91"
    return None


def unpack(data: bytes) -> tuple[bytes, str | None]:
    """Return ``(image, packer)``; the input is returned as is when not packed."""

    packer = detect(data)
    if packer is None:
        return data, None
    try:
        return _unlzexe(data, packer), packer
    except (IndexError, struct.error) as exc:
        raise UnpackError(f"corrupt {packer} executable: {exc}") from exc


def _unlzexe(data: bytes, packer: str) -> bytes:
    ihead = list(struct.unpack_from("<16H", data, 0))
    ohead = list(ihead)
    fpos = (ihead[0x0B] + ihead[4]) << 4
    inf = struct.unpack_from("<8H", data, fpos)
    ohead[0x0A], ohead[0x0B], ohead[0x08], ohead[0x07] = inf[0], inf[1], inf[2], inf[3]
    ohead[0x0C] = 0x1C

    relocations: list[tuple[int, int]] = []
    if packer == "LZ90":
        pos = fpos + 0x19D
        segment = 0
        while True:
            (count,) = struct.unpack_from("<H", data, pos)
            pos += 2
            for _ in range(count):
                (offset,) = struct.unpack_from("<H", data, pos)
                pos += 2
                relocations.append((offset, segment))
            segment += 0x1000
            if segment == 0x10000:
                break
    else:
        pos = fpos + 0x158
        offset = segment = 0
        while True:
            span = data[pos]
            pos += 1
            if span == 0:
                (span,) = struct.unpack_from("<H", data, pos)
                pos += 2
                if span == 0:
                    segment = (segment + 0x0FFF) & 0xFFFF
                    continue
                if span == 1:
                    break
            offset += span
            segment = (segment + ((offset & ~0x0F) >> 4)) & 0xFFFF
            offset &= 0x0F
            relocations.append((offset, segment))

    header = bytearray(0x1C)
    header += b"".join(struct.pack("<HH", o, s) for o, s in relocations)
    header += b"\0" * ((-len(header)) % 0x200)
    ohead[3] = len(relocations)
    ohead[4] = len(header) >> 4

    # Decompress the load module.
    src = (ihead[0x0B] - inf[4] + ihead[4]) << 4
    out = bytearray()
    bits = struct.unpack_from("<H", data, src)[0]
    src += 2
    count = 16

    def bit() -> int:
        nonlocal bits, count, src
        b = bits & 1
        count -= 1
        if count == 0:
            bits = struct.unpack_from("<H", data, src)[0]
            src += 2
            count = 16
        else:
            bits >>= 1
        return b

    while True:
        if bit():
            out.append(data[src])
            src += 1
            continue
        if not bit():
            length = (bit() << 1) | bit()
            length += 2
            span = data[src] - 0x100
            src += 1
        else:
            low = data[src]
            high = data[src + 1]
            src += 2
            span = (low | ((high & ~0x07) << 5) | 0xE000) - 0x10000
            length = (high & 0x07) + 2
            if length == 2:
                length = data[src]
                src += 1
                if length == 0:
                    break
                if length == 1:
                    continue
                length += 1
        start = len(out) + span
        if start < 0:
            raise UnpackError("back reference before the start of the image")
        for i in range(length):
            out.append(out[start + i])

    load_size = len(out)
    if ihead[6] != 0:
        ohead[5] = (ohead[5] - (inf[5] + ((inf[6] + 15) >> 4) + 9)) & 0xFFFF
        if ihead[6] != 0xFFFF:
            ohead[6] = (ohead[6] - (ihead[5] - ohead[5])) & 0xFFFF
    total = load_size + (ohead[4] << 4)
    ohead[1] = total & 0x1FF
    ohead[2] = (total + 0x1FF) >> 9
    header[:0x1C] = struct.pack("<14H", *ohead[:14])
    return bytes(header) + bytes(out)
