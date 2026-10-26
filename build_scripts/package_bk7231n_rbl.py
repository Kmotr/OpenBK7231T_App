#!/usr/bin/env python3
"""Create an OpenBeken-compatible BK7231N RT-Thread OTA RBL package."""

import argparse
import gzip
import hashlib
import struct
import zlib
from pathlib import Path

from Crypto.Cipher import AES

DEFAULT_KEY = b"0123456789ABCDEF0123456789ABCDEF"
DEFAULT_IV = b"0123456789ABCDEF"
RBL_HEADER_SIZE = 96


def make_package(source: Path, destination: Path, version: str) -> str:
    version_bytes = version.encode("ascii")
    if not version_bytes or len(version_bytes) > 24:
        raise ValueError("RBL version must be 1-24 ASCII bytes")

    firmware = source.read_bytes()
    compressed = bytearray(gzip.compress(firmware, compresslevel=6))
    compressed[4:10] = b"\x00\x00\x00\x00\x04\x00"
    padding = 16 - (len(compressed) % 16)
    encrypted = AES.new(DEFAULT_KEY, AES.MODE_CBC, DEFAULT_IV).encrypt(
        bytes(compressed) + bytes([padding]) * padding
    )

    fnv = 0x811C9DC5
    for byte in firmware:
        fnv = ((fnv ^ byte) * 0x01000193) & 0xFFFFFFFF

    header_without_crc = struct.pack(
        "<4B2HI16s24s24s4I",
        82, 66, 76, 0, 258, 0, int(source.stat().st_mtime),
        b"app", version_bytes, b"00010203040506070809\x00\x00\x00\x00",
        zlib.crc32(encrypted) & 0xFFFFFFFF, fnv, len(firmware), len(encrypted),
    )
    package = (
        header_without_crc
        + struct.pack("<I", zlib.crc32(header_without_crc) & 0xFFFFFFFF)
        + encrypted
    )

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(package)

    assert package[:4] == b"RBL\x00"
    assert len(package) == RBL_HEADER_SIZE + len(encrypted)
    assert zlib.crc32(package[:92]) & 0xFFFFFFFF == struct.unpack_from("<I", package, 92)[0]
    assert zlib.crc32(package[RBL_HEADER_SIZE:]) & 0xFFFFFFFF == struct.unpack_from("<I", package, 76)[0]
    clear = AES.new(DEFAULT_KEY, AES.MODE_CBC, DEFAULT_IV).decrypt(package[RBL_HEADER_SIZE:])
    pad_len = clear[-1]
    if not 1 <= pad_len <= 16 or clear[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid AES padding in generated RBL")
    restored = gzip.decompress(clear[:-pad_len])
    if restored != firmware:
        raise ValueError("RBL verification failed: firmware roundtrip differs")
    return hashlib.sha256(firmware).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path, help="OpenBK7231N .bin firmware image")
    parser.add_argument("output", type=Path, help="destination .rbl file")
    parser.add_argument("--version", required=True, help="RBL version field, up to 24 ASCII bytes")
    args = parser.parse_args()
    digest = make_package(args.firmware, args.output, args.version)
    print(f"created={args.output}")
    print(f"firmware_sha256={digest}")
    print(f"rbl_sha256={hashlib.sha256(args.output.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
