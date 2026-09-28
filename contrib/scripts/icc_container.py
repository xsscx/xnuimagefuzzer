#!/usr/bin/env python3
"""Exact ICC extraction, insertion, validation, and classification helpers."""

from __future__ import annotations

import hashlib
import struct
import zlib
from pathlib import Path


class ICCContainerError(ValueError):
    """Raised when an image container or ICC payload is structurally invalid."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_icc(data: bytes) -> None:
    if len(data) < 132 or data[36:40] != b"acsp":
        raise ICCContainerError("invalid ICC header")
    declared = int.from_bytes(data[0:4], "big")
    if declared != len(data):
        raise ICCContainerError(
            f"ICC declared size {declared} does not match {len(data)}"
        )
    count = int.from_bytes(data[128:132], "big")
    table_end = 132 + count * 12
    if table_end > len(data):
        raise ICCContainerError("ICC tag table exceeds profile size")
    for index in range(count):
        entry = 132 + index * 12
        offset = int.from_bytes(data[entry + 4 : entry + 8], "big")
        size = int.from_bytes(data[entry + 8 : entry + 12], "big")
        if offset < table_end or size == 0 or offset > len(data) - size:
            raise ICCContainerError(f"invalid ICC tag entry {index}")


def _png_chunks(data: bytes) -> list[tuple[bytes, bytes]]:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ICCContainerError("invalid PNG signature")
    chunks = []
    offset = 8
    while offset + 12 <= len(data):
        length = int.from_bytes(data[offset : offset + 4], "big")
        end = offset + 12 + length
        if end > len(data):
            raise ICCContainerError("truncated PNG chunk")
        chunk_type = data[offset + 4 : offset + 8]
        payload = data[offset + 8 : offset + 8 + length]
        expected = int.from_bytes(data[offset + 8 + length : end], "big")
        actual = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
        if expected != actual:
            raise ICCContainerError(f"invalid PNG CRC for {chunk_type!r}")
        chunks.append((chunk_type, payload))
        offset = end
        if chunk_type == b"IEND":
            if offset != len(data):
                raise ICCContainerError("data follows PNG IEND")
            return chunks
    raise ICCContainerError("missing PNG IEND")


def extract_png(data: bytes) -> bytes | None:
    found = []
    for chunk_type, payload in _png_chunks(data):
        if chunk_type != b"iCCP":
            continue
        separator = payload.find(b"\x00")
        if separator < 1 or separator + 2 > len(payload):
            raise ICCContainerError("invalid PNG iCCP header")
        if payload[separator + 1] != 0:
            raise ICCContainerError("unsupported PNG iCCP compression method")
        try:
            found.append(zlib.decompress(payload[separator + 2 :]))
        except zlib.error as error:
            raise ICCContainerError(f"invalid PNG iCCP stream: {error}") from error
    if len(found) > 1:
        raise ICCContainerError("multiple PNG iCCP chunks")
    return found[0] if found else None


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", crc)


def inject_png(data: bytes, profile: bytes) -> bytes:
    chunks = _png_chunks(data)
    output = bytearray(b"\x89PNG\r\n\x1a\n")
    inserted = False
    for chunk_type, payload in chunks:
        if chunk_type in (b"iCCP", b"sRGB"):
            continue
        if not inserted and chunk_type in (b"PLTE", b"IDAT", b"IEND"):
            iccp = b"ICC Profile\x00\x00" + zlib.compress(profile, 9)
            output.extend(_png_chunk(b"iCCP", iccp))
            inserted = True
        output.extend(_png_chunk(chunk_type, payload))
    if not inserted:
        raise ICCContainerError("could not place PNG iCCP chunk")
    result = bytes(output)
    if extract_png(result) != profile:
        raise ICCContainerError("PNG ICC round-trip mismatch")
    return result


def _jpeg_segments(data: bytes) -> tuple[list[tuple[int, bytes]], bytes]:
    if not data.startswith(b"\xff\xd8"):
        raise ICCContainerError("invalid JPEG signature")
    segments = []
    offset = 2
    while offset < len(data):
        if data[offset] != 0xFF:
            raise ICCContainerError("invalid JPEG marker stream")
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            raise ICCContainerError("truncated JPEG marker")
        marker = data[offset]
        offset += 1
        if marker == 0xDA:
            if offset + 2 > len(data):
                raise ICCContainerError("truncated JPEG SOS")
            length = int.from_bytes(data[offset : offset + 2], "big")
            if length < 2 or offset + length > len(data):
                raise ICCContainerError("invalid JPEG SOS length")
            return segments, data[offset - 2 :]
        if marker == 0xD9:
            return segments, b"\xff\xd9"
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            segments.append((marker, b""))
            continue
        if offset + 2 > len(data):
            raise ICCContainerError("truncated JPEG segment")
        length = int.from_bytes(data[offset : offset + 2], "big")
        if length < 2 or offset + length > len(data):
            raise ICCContainerError("invalid JPEG segment length")
        segments.append((marker, data[offset + 2 : offset + length]))
        offset += length
    raise ICCContainerError("missing JPEG scan or EOI")


def extract_jpeg(data: bytes) -> bytes | None:
    segments, _ = _jpeg_segments(data)
    parts: dict[int, bytes] = {}
    expected_count = 0
    for marker, payload in segments:
        if marker != 0xE2 or not payload.startswith(b"ICC_PROFILE\x00"):
            continue
        if len(payload) < 14:
            raise ICCContainerError("truncated JPEG ICC segment")
        sequence, count = payload[12], payload[13]
        if sequence == 0 or count == 0 or sequence > count:
            raise ICCContainerError("invalid JPEG ICC sequence")
        if expected_count and expected_count != count:
            raise ICCContainerError("inconsistent JPEG ICC segment count")
        if sequence in parts:
            raise ICCContainerError("duplicate JPEG ICC segment")
        expected_count = count
        parts[sequence] = payload[14:]
    if not parts:
        return None
    if set(parts) != set(range(1, expected_count + 1)):
        raise ICCContainerError("incomplete JPEG ICC profile")
    return b"".join(parts[index] for index in range(1, expected_count + 1))


def inject_jpeg(data: bytes, profile: bytes) -> bytes:
    segments, tail = _jpeg_segments(data)
    clean = [
        (marker, payload)
        for marker, payload in segments
        if not (marker == 0xE2 and payload.startswith(b"ICC_PROFILE\x00"))
    ]
    chunk_size = 65519
    count = max(1, (len(profile) + chunk_size - 1) // chunk_size)
    if count > 255:
        raise ICCContainerError("ICC profile requires too many JPEG APP2 segments")
    icc_segments = []
    for sequence in range(1, count + 1):
        part = profile[(sequence - 1) * chunk_size : sequence * chunk_size]
        payload = b"ICC_PROFILE\x00" + bytes((sequence, count)) + part
        icc_segments.append((0xE2, payload))
    output = bytearray(b"\xff\xd8")
    inserted = False
    for marker, payload in clean:
        if not inserted and marker not in (0xE0, 0xE1):
            for icc_marker, icc_payload in icc_segments:
                output.extend(b"\xff" + bytes((icc_marker,)))
                output.extend(struct.pack(">H", len(icc_payload) + 2))
                output.extend(icc_payload)
            inserted = True
        output.extend(b"\xff" + bytes((marker,)))
        if payload or marker not in (0x01,) and not 0xD0 <= marker <= 0xD7:
            output.extend(struct.pack(">H", len(payload) + 2))
            output.extend(payload)
    if not inserted:
        for marker, payload in icc_segments:
            output.extend(b"\xff" + bytes((marker,)))
            output.extend(struct.pack(">H", len(payload) + 2))
            output.extend(payload)
    output.extend(tail)
    result = bytes(output)
    if extract_jpeg(result) != profile:
        raise ICCContainerError("JPEG ICC round-trip mismatch")
    return result


def _tiff_header(data: bytes) -> tuple[str, int]:
    if data.startswith(b"II*\x00"):
        endian = "<"
    elif data.startswith(b"MM\x00*"):
        endian = ">"
    else:
        raise ICCContainerError("unsupported TIFF signature")
    if len(data) < 8:
        raise ICCContainerError("truncated TIFF header")
    return endian, struct.unpack_from(endian + "I", data, 4)[0]


def _tiff_entries(data: bytes) -> tuple[str, int, list[bytes], bytes]:
    endian, ifd_offset = _tiff_header(data)
    if ifd_offset + 2 > len(data):
        raise ICCContainerError("invalid TIFF IFD offset")
    count = struct.unpack_from(endian + "H", data, ifd_offset)[0]
    end = ifd_offset + 2 + count * 12
    if end + 4 > len(data):
        raise ICCContainerError("truncated TIFF IFD")
    entries = [data[ifd_offset + 2 + i * 12 : ifd_offset + 14 + i * 12] for i in range(count)]
    return endian, ifd_offset, entries, data[end : end + 4]


def extract_tiff(data: bytes) -> bytes | None:
    endian, _, entries, _ = _tiff_entries(data)
    for entry in entries:
        tag, field_type, count = struct.unpack_from(endian + "HHI", entry)
        if tag != 34675:
            continue
        if field_type not in (1, 7):
            raise ICCContainerError("invalid TIFF ICC field type")
        if count <= 4:
            return entry[8 : 8 + count]
        offset = struct.unpack_from(endian + "I", entry, 8)[0]
        if offset > len(data) - count:
            raise ICCContainerError("invalid TIFF ICC offset")
        return data[offset : offset + count]
    return None


def inject_tiff(data: bytes, profile: bytes) -> bytes:
    endian, _, entries, next_ifd = _tiff_entries(data)
    entries = [entry for entry in entries if struct.unpack_from(endian + "H", entry)[0] != 34675]
    output = bytearray(data)
    if len(output) % 2:
        output.append(0)
    profile_offset = len(output)
    output.extend(profile)
    if len(output) % 2:
        output.append(0)
    new_ifd_offset = len(output)
    icc_entry = struct.pack(endian + "HHI", 34675, 7, len(profile)) + struct.pack(endian + "I", profile_offset)
    entries.append(icc_entry)
    entries.sort(key=lambda entry: struct.unpack_from(endian + "H", entry)[0])
    if len(entries) > 65535:
        raise ICCContainerError("too many TIFF IFD entries")
    output.extend(struct.pack(endian + "H", len(entries)))
    for entry in entries:
        output.extend(entry)
    output.extend(next_ifd)
    struct.pack_into(endian + "I", output, 4, new_ifd_offset)
    result = bytes(output)
    if extract_tiff(result) != profile:
        raise ICCContainerError("TIFF ICC round-trip mismatch")
    return result


def normalized_extension(path_or_extension: str | Path) -> str:
    value = str(path_or_extension).lower()
    if value.startswith(".") and value.count(".") == 1:
        value = value[1:]
    elif "." in value:
        value = Path(value).suffix.lower().lstrip(".")
    return "jpg" if value == "jpeg" else "tiff" if value == "tif" else value


def extract_profile(data: bytes, extension: str | Path) -> bytes | None:
    extension = normalized_extension(extension)
    extractors = {"png": extract_png, "jpg": extract_jpeg, "tiff": extract_tiff}
    if extension not in extractors:
        raise ICCContainerError(f"unsupported ICC container: {extension}")
    return extractors[extension](data)


def inject_profile(data: bytes, profile: bytes, extension: str | Path) -> bytes:
    extension = normalized_extension(extension)
    injectors = {"png": inject_png, "jpg": inject_jpeg, "tiff": inject_tiff}
    if extension not in injectors:
        raise ICCContainerError(f"unsupported ICC container: {extension}")
    return injectors[extension](data, profile)


def mutate_profile(profile: bytes, strategy: str, seed: int) -> bytes:
    if len(profile) < 132:
        raise ICCContainerError("ICC profile is too short to mutate")
    output = bytearray(profile)
    state = seed & 0xFFFFFFFF or 0x9E3779B9

    def next_value() -> int:
        nonlocal state
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFFFFFF
        return state & 0xFFFFFFFF

    if strategy == "declared-size":
        wrong = len(output) + 1 + next_value() % 4096
        output[0:4] = wrong.to_bytes(4, "big")
    elif strategy == "tag-count":
        count = int.from_bytes(output[128:132], "big")
        output[128:132] = (count + 1 + next_value() % 32).to_bytes(4, "big")
    elif strategy == "tag-entry":
        count = int.from_bytes(output[128:132], "big")
        if count == 0 or 132 + count * 12 > len(output):
            raise ICCContainerError("ICC profile has no mutable tag entry")
        index = next_value() % count
        entry = 132 + index * 12
        output[entry + 4 : entry + 8] = (len(output) - 1).to_bytes(4, "big")
        output[entry + 8 : entry + 12] = (0xFFFFFF00 | next_value() % 256).to_bytes(4, "big")
    elif strategy == "header-field":
        fields = (8, 12, 16, 20, 64)
        offset = fields[next_value() % len(fields)]
        output[offset : offset + 4] = next_value().to_bytes(4, "big")
    elif strategy == "payload-bitflip":
        start = 132 + int.from_bytes(output[128:132], "big") * 12
        if start >= len(output):
            start = 40
        offset = start + next_value() % (len(output) - start)
        output[offset] ^= 1 << (next_value() % 8)
    else:
        raise ICCContainerError(f"unknown ICC mutation strategy: {strategy}")
    if bytes(output) == profile:
        raise ICCContainerError("ICC mutation did not change the profile")
    return bytes(output)


def system_profile_catalog(root: Path) -> dict[str, str]:
    catalog = {}
    if not root.is_dir():
        return catalog
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() in (".icc", ".icm"):
            data = path.read_bytes()
            catalog[sha256(data)] = str(path)
    return catalog


def classify_profile(
    requested: bytes | None,
    observed: bytes | None,
    system_catalog: dict[str, str],
) -> tuple[str, str | None]:
    if requested is None and observed is None:
        return "absent_expected", None
    if requested is None and observed is not None:
        match = system_catalog.get(sha256(observed))
        return "injected_without_input", match
    if requested is not None and observed is None:
        return "dropped", None
    if requested == observed:
        return "preserved_exact", None
    match = system_catalog.get(sha256(observed or b""))
    if match:
        return "substituted_system_profile", match
    return "rewritten", None
