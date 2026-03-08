#!/usr/bin/env python3
"""
extract-icc-seeds.py — Extract ICC profiles from fuzzed images for CFL fuzzer seeds.

Bridges xnuimagetools pipeline output into CFL fuzzer seed corpus.
Extracts embedded ICC profiles from TIFF/PNG/JPEG images and copies them
as standalone .icc files suitable for CFL fuzzers (profile, dump, toxml, etc.).

Also copies TIFF images directly for tiffdump and specsep fuzzers.

Usage:
    # Extract from latest fuzzed-images run
    python3 extract-icc-seeds.py --input ../fuzzed-images/ --output /tmp/extracted-seeds

    # Extract and inject directly into CFL corpus
    python3 extract-icc-seeds.py --input ../fuzzed-images/ --inject-cfl ../../cfl

    # Extract from a specific device run
    python3 extract-icc-seeds.py --input ../fuzzed-images/2026-03-03-030143/ --output /tmp/seeds

Output structure:
    output/
    ├── icc/          # Standalone ICC profiles (for profile/dump/deep_dump/toxml fuzzers)
    ├── tiff/         # TIFF files (for tiffdump/specsep fuzzers)
    └── manifest.json # Extraction metadata
"""

import argparse
import hashlib
import json
import os
import shutil
import struct
import sys
from pathlib import Path


def extract_icc_from_tiff(data: bytes) -> bytes | None:
    """Extract ICC profile from TIFF IFD (tag 34675 = 0x8773)."""
    if len(data) < 8:
        return None

    # Determine byte order
    if data[:2] == b'II':
        endian = '<'
    elif data[:2] == b'MM':
        endian = '>'
    else:
        return None

    # Read IFD offset
    ifd_offset = struct.unpack(endian + 'I', data[4:8])[0]
    if ifd_offset >= len(data) - 2:
        return None

    # Read IFD entry count
    num_entries = struct.unpack(endian + 'H', data[ifd_offset:ifd_offset + 2])[0]

    for i in range(num_entries):
        entry_offset = ifd_offset + 2 + i * 12
        if entry_offset + 12 > len(data):
            break

        tag = struct.unpack(endian + 'H', data[entry_offset:entry_offset + 2])[0]
        if tag == 34675:  # ICC Profile tag
            count = struct.unpack(endian + 'I', data[entry_offset + 4:entry_offset + 8])[0]
            value_offset = struct.unpack(endian + 'I', data[entry_offset + 8:entry_offset + 12])[0]
            if value_offset + count <= len(data):
                return data[value_offset:value_offset + count]

    return None


def extract_icc_from_png(data: bytes) -> bytes | None:
    """Extract ICC profile from PNG iCCP chunk."""
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        return None

    pos = 8
    while pos < len(data) - 12:
        chunk_len = struct.unpack('>I', data[pos:pos + 4])[0]
        chunk_type = data[pos + 4:pos + 8]

        if chunk_type == b'iCCP':
            chunk_data = data[pos + 8:pos + 8 + chunk_len]
            # iCCP: profile_name\0 compression_method compressed_profile
            null_pos = chunk_data.find(b'\x00')
            if null_pos >= 0 and null_pos + 2 < len(chunk_data):
                compressed = chunk_data[null_pos + 2:]  # skip compression method byte
                try:
                    import zlib
                    return zlib.decompress(compressed)
                except Exception:
                    return None

        pos += 12 + chunk_len  # 4 len + 4 type + data + 4 CRC

    return None


def extract_icc_from_jpeg(data: bytes) -> bytes | None:
    """Extract ICC profile from JPEG APP2 marker (ICC_PROFILE)."""
    if data[:2] != b'\xff\xd8':
        return None

    icc_chunks = {}
    pos = 2
    while pos < len(data) - 4:
        if data[pos] != 0xFF:
            pos += 1
            continue

        marker = data[pos + 1]
        if marker == 0xD9:  # EOI
            break
        if marker in (0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0x01, 0x00):
            pos += 2
            continue

        seg_len = struct.unpack('>H', data[pos + 2:pos + 4])[0]
        seg_data = data[pos + 4:pos + 2 + seg_len]

        # APP2 with ICC_PROFILE header
        if marker == 0xE2 and seg_data[:12] == b'ICC_PROFILE\x00':
            chunk_num = seg_data[12]
            icc_chunks[chunk_num] = seg_data[14:]

        pos += 2 + seg_len

    if icc_chunks:
        profile = b''
        for i in sorted(icc_chunks.keys()):
            profile += icc_chunks[i]
        return profile if len(profile) >= 128 else None

    return None


def sha256_short(data: bytes) -> str:
    """Short SHA256 hash for deduplication."""
    return hashlib.sha256(data).hexdigest()[:12]


def process_directory(input_dir: Path, output_dir: Path, inject_cfl: Path | None):
    """Walk input directory, extract ICC profiles and collect TIFFs."""
    icc_dir = output_dir / 'icc'
    tiff_dir = output_dir / 'tiff'
    icc_dir.mkdir(parents=True, exist_ok=True)
    tiff_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        'source': str(input_dir),
        'icc_profiles': [],
        'tiff_files': [],
        'stats': {'files_scanned': 0, 'icc_extracted': 0, 'tiff_copied': 0, 'duplicates_skipped': 0}
    }

    seen_hashes = set()
    image_extensions = {'.tiff', '.tif', '.png', '.jpg', '.jpeg'}

    for root, _, files in os.walk(input_dir):
        for filename in sorted(files):
            ext = Path(filename).suffix.lower()
            if ext not in image_extensions:
                continue

            filepath = Path(root) / filename
            manifest['stats']['files_scanned'] += 1

            try:
                data = filepath.read_bytes()
            except (OSError, PermissionError):
                continue

            # Extract ICC profile
            icc_data = None
            if ext in ('.tiff', '.tif'):
                icc_data = extract_icc_from_tiff(data)
            elif ext == '.png':
                icc_data = extract_icc_from_png(data)
            elif ext in ('.jpg', '.jpeg'):
                icc_data = extract_icc_from_jpeg(data)

            if icc_data and len(icc_data) >= 128:
                h = sha256_short(icc_data)
                if h not in seen_hashes:
                    seen_hashes.add(h)
                    stem = Path(filename).stem.replace(' ', '_')
                    icc_name = f'xnu_{stem}_{h}.icc'
                    (icc_dir / icc_name).write_bytes(icc_data)
                    manifest['icc_profiles'].append({
                        'name': icc_name,
                        'source': str(filepath.relative_to(input_dir)),
                        'size': len(icc_data),
                        'hash': h
                    })
                    manifest['stats']['icc_extracted'] += 1
                else:
                    manifest['stats']['duplicates_skipped'] += 1

            # Copy TIFF files for tiffdump/specsep fuzzers
            if ext in ('.tiff', '.tif') and len(data) >= 8:
                h = sha256_short(data)
                if h not in seen_hashes:
                    seen_hashes.add(h)
                    stem = Path(filename).stem.replace(' ', '_')
                    tiff_name = f'xnu_{stem}_{h}.tiff'
                    (tiff_dir / tiff_name).write_bytes(data)
                    manifest['tiff_files'].append({
                        'name': tiff_name,
                        'source': str(filepath.relative_to(input_dir)),
                        'size': len(data),
                        'hash': h
                    })
                    manifest['stats']['tiff_copied'] += 1

    # Write manifest
    (output_dir / 'manifest.json').write_text(json.dumps(manifest, indent=2))

    # Inject into CFL corpus if requested
    if inject_cfl:
        _inject_into_cfl(icc_dir, tiff_dir, inject_cfl, manifest)

    return manifest


def _inject_into_cfl(icc_dir: Path, tiff_dir: Path, cfl_dir: Path, manifest: dict):
    """Copy extracted seeds into CFL fuzzer corpus directories."""
    # ICC profiles → 4 fuzzers that parse ICC
    icc_targets = [
        'corpus-icc_profile_fuzzer',
        'corpus-icc_deep_dump_fuzzer',
        'corpus-icc_dump_fuzzer',
        'corpus-icc_toxml_fuzzer',
    ]

    # TIFF files → 2 fuzzers that parse TIFF
    tiff_targets = [
        'corpus-icc_tiffdump_fuzzer',
        'corpus-icc_specsep_fuzzer',
    ]

    injected_icc = 0
    injected_tiff = 0

    for target in icc_targets:
        target_dir = cfl_dir / target
        if target_dir.is_dir():
            for icc_file in icc_dir.iterdir():
                dest = target_dir / icc_file.name
                if not dest.exists():
                    shutil.copy2(icc_file, dest)
                    injected_icc += 1

    for target in tiff_targets:
        target_dir = cfl_dir / target
        if target_dir.is_dir():
            for tiff_file in tiff_dir.iterdir():
                dest = target_dir / tiff_file.name
                if not dest.exists():
                    shutil.copy2(tiff_file, dest)
                    injected_tiff += 1

    print(f'  Injected: {injected_icc} ICC profiles → {len(icc_targets)} fuzzers')
    print(f'  Injected: {injected_tiff} TIFF files → {len(tiff_targets)} fuzzers')


def main():
    parser = argparse.ArgumentParser(
        description='Extract ICC profiles from fuzzed images for CFL fuzzer seeds')
    parser.add_argument('--input', '-i', type=Path, required=True,
                        help='Input directory (fuzzed-images/ or a specific run)')
    parser.add_argument('--output', '-o', type=Path, default=Path('/tmp/extracted-seeds'),
                        help='Output directory for extracted seeds')
    parser.add_argument('--inject-cfl', type=Path, default=None,
                        help='Path to cfl/ directory to inject seeds directly into fuzzer corpora')
    args = parser.parse_args()

    if not args.input.is_dir():
        print(f'ERROR: Input directory not found: {args.input}', file=sys.stderr)
        sys.exit(1)

    print(f'Scanning: {args.input}')
    manifest = process_directory(args.input, args.output, args.inject_cfl)

    stats = manifest['stats']
    print('\n── Results ──')
    print(f'  Files scanned:      {stats["files_scanned"]}')
    print(f'  ICC profiles:       {stats["icc_extracted"]}')
    print(f'  TIFF files:         {stats["tiff_copied"]}')
    print(f'  Duplicates skipped: {stats["duplicates_skipped"]}')
    print(f'  Output: {args.output}')


if __name__ == '__main__':
    main()
