#!/usr/bin/env python3
"""Unit tests for exact ICC container handling."""

from __future__ import annotations

import struct
import unittest
import zlib

from contrib.scripts.icc_container import (
    ICCContainerError,
    classify_profile,
    extract_profile,
    inject_profile,
    mutate_profile,
    normalized_extension,
    sha256,
    validate_icc,
)


def png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", crc)


def minimal_png() -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    pixels = zlib.compress(b"\x00\x00\x00\x00\xff")
    return b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", ihdr) + png_chunk(b"IDAT", pixels) + png_chunk(b"IEND", b"")


def minimal_jpeg() -> bytes:
    app0 = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    return b"\xff\xd8\xff\xe0" + struct.pack(">H", len(app0) + 2) + app0 + b"\xff\xd9"


def minimal_tiff() -> bytes:
    return b"II*\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def valid_profile() -> bytes:
    data = bytearray(148)
    data[0:4] = len(data).to_bytes(4, "big")
    data[8:12] = b"\x04\x30\x00\x00"
    data[12:16] = b"mntr"
    data[16:20] = b"RGB "
    data[20:24] = b"XYZ "
    data[36:40] = b"acsp"
    data[128:132] = (1).to_bytes(4, "big")
    data[132:136] = b"desc"
    data[136:140] = (144).to_bytes(4, "big")
    data[140:144] = (4).to_bytes(4, "big")
    data[144:148] = b"text"
    return bytes(data)


class ICCContainerTests(unittest.TestCase):
    def test_profile_validation(self) -> None:
        validate_icc(valid_profile())
        self.assertEqual("png", normalized_extension(".png"))
        broken = bytearray(valid_profile())
        broken[0:4] = (999).to_bytes(4, "big")
        with self.assertRaises(ICCContainerError):
            validate_icc(bytes(broken))

    def test_exact_injection_round_trip(self) -> None:
        profile = valid_profile()
        fixtures = (("png", minimal_png()), ("jpg", minimal_jpeg()), ("tiff", minimal_tiff()))
        for extension, image in fixtures:
            with self.subTest(extension=extension):
                self.assertIsNone(extract_profile(image, extension))
                injected = inject_profile(image, profile, extension)
                self.assertEqual(profile, extract_profile(injected, extension))

    def test_malformed_containers_fail_closed(self) -> None:
        profile = valid_profile()

        png = bytearray(inject_profile(minimal_png(), profile, "png"))
        png[-1] ^= 1
        with self.assertRaises(ICCContainerError):
            extract_profile(bytes(png), "png")

        jpeg = bytearray(inject_profile(minimal_jpeg(), profile, "jpg"))
        header = jpeg.index(b"ICC_PROFILE\x00")
        jpeg[header + 13] = 2
        with self.assertRaises(ICCContainerError):
            extract_profile(bytes(jpeg), "jpg")

        tiff = bytearray(inject_profile(minimal_tiff(), profile, "tiff"))
        ifd_offset = int.from_bytes(tiff[4:8], "little")
        entry_offset = ifd_offset + 2
        tiff[entry_offset + 8 : entry_offset + 12] = (len(tiff) + 1).to_bytes(4, "little")
        with self.assertRaises(ICCContainerError):
            extract_profile(bytes(tiff), "tiff")

    def test_deterministic_mutations(self) -> None:
        profile = valid_profile()
        for strategy in (
            "declared-size", "tag-count", "tag-entry", "header-field", "payload-bitflip"
        ):
            with self.subTest(strategy=strategy):
                first = mutate_profile(profile, strategy, 7)
                second = mutate_profile(profile, strategy, 7)
                self.assertEqual(first, second)
                self.assertNotEqual(profile, first)

    def test_classification(self) -> None:
        requested = valid_profile()
        replacement = requested + b"x"
        catalog = {sha256(replacement): "/profiles/replacement.icc"}
        self.assertEqual(("absent_expected", None), classify_profile(None, None, catalog))
        self.assertEqual(("preserved_exact", None), classify_profile(requested, requested, catalog))
        self.assertEqual(("dropped", None), classify_profile(requested, None, catalog))
        self.assertEqual(
            ("injected_without_input", None), classify_profile(None, requested, catalog)
        )
        self.assertEqual(("rewritten", None), classify_profile(requested, b"other", {}))
        self.assertEqual(
            ("substituted_system_profile", "/profiles/replacement.icc"),
            classify_profile(requested, replacement, catalog),
        )


if __name__ == "__main__":
    unittest.main()
