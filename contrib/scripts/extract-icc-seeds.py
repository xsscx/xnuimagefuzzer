#!/usr/bin/env python3
"""Export validated ICC and TIFF seeds from a verified QA corpus."""

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

from icc_container import ICCContainerError, extract_profile, validate_icc
from validate_qa_corpus import validate as validate_corpus


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export only hash-verified seeds from a QA manifest"
    )
    parser.add_argument("--input", required=True, type=Path,
                        help="QA corpus directory containing manifest.json")
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest_path = args.input / "manifest.json"
    if not manifest_path.is_file():
        print("ERROR: input must contain manifest.json", file=sys.stderr)
        return 2

    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    if manifest.get("generator") != "xnuimagefuzzer-qa-corpus":
        print("ERROR: unrecognized corpus generator", file=sys.stderr)
        return 2
    validate_corpus(args.input.resolve())

    if args.output.exists() and any(args.output.iterdir()):
        print("ERROR: output directory must be empty", file=sys.stderr)
        return 2

    icc_dir = args.output / "icc"
    tiff_dir = args.output / "tiff"
    icc_dir.mkdir(parents=True, exist_ok=True)
    tiff_dir.mkdir(parents=True, exist_ok=True)
    exported = []

    for entry in manifest.get("entries", []):
        relative = entry.get("path")
        if relative is None and entry.get("iccOutcome") == "rejected":
            continue
        if not isinstance(relative, str) or not relative:
            raise ValueError("invalid manifest artifact path")
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ValueError(f"unsafe manifest artifact path: {relative}")
        path = args.input / relative_path
        if not path.is_file():
            raise ValueError(f"missing manifest artifact: {relative}")
        data = path.read_bytes()
        if sha256(data) != entry.get("fileSHA256"):
            raise ValueError(f"file hash mismatch: {relative}")

        suffix = path.suffix.lower()
        if suffix in (".tif", ".tiff"):
            destination = tiff_dir / f"{path.stem}-{sha256(data)[:16]}{suffix}"
            if not destination.exists():
                shutil.copyfile(path, destination)
                exported.append({"kind": "tiff", "source": relative,
                                 "path": str(destination.relative_to(args.output)),
                                 "sha256": sha256(data)})

        if entry.get("iccOutcome") != "preserved_exact":
            continue
        profile = extract_profile(data, path)
        validate_icc(profile)
        if sha256(profile) != entry.get("observedICCSHA256"):
            raise ValueError(f"ICC hash mismatch: {relative}")
        destination = icc_dir / f"profile-{sha256(profile)[:16]}.icc"
        if not destination.exists():
            destination.write_bytes(profile)
            exported.append({"kind": "icc", "source": relative,
                             "path": str(destination.relative_to(args.output)),
                             "sha256": sha256(profile)})

    export_manifest = {
        "schemaVersion": 2,
        "sourceManifestSHA256": sha256(manifest_path.read_bytes()),
        "exports": exported,
    }
    (args.output / "manifest.json").write_text(
        json.dumps(export_manifest, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )
    print(f"PASS: exported {len(exported)} verified seeds to {args.output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ICCContainerError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
