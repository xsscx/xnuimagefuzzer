#!/usr/bin/env python3
"""Build a deterministic image/ICC QA corpus with verified provenance."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

from icc_container import (
    ICCContainerError,
    classify_profile,
    extract_profile,
    inject_profile,
    mutate_profile,
    normalized_extension,
    sha256,
    system_profile_catalog,
    validate_icc,
)


SUPPORTED_EXTENSIONS = {"png", "jpg", "tiff"}
DEFAULT_PROFILE_NAMES = (
    "sRGB Profile.icc",
    "Display P3.icc",
    "AdobeRGB1998.icc",
)
MUTATION_STRATEGIES = (
    "declared-size",
    "tag-count",
    "tag-entry",
    "header-field",
    "payload-bitflip",
)


def profile_slug(path: Path) -> str:
    return "".join(char.lower() if char.isalnum() else "-" for char in path.stem).strip("-")


def discover_profiles(root: Path, all_profiles: bool) -> list[Path]:
    candidates = sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in (".icc", ".icm")
    )
    if not all_profiles:
        by_name = {path.name: path for path in candidates}
        candidates = [by_name[name] for name in DEFAULT_PROFILE_NAMES if name in by_name]
    profiles = []
    for path in candidates:
        data = path.read_bytes()
        try:
            validate_icc(data)
        except ICCContainerError:
            continue
        if data[16:20] == b"RGB ":
            profiles.append(path)
    if not profiles:
        raise ICCContainerError(f"no valid RGB ICC profiles found in {root}")
    return profiles


def source_files(root: Path) -> list[Path]:
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and normalized_extension(path) in SUPPORTED_EXTENSIONS:
            files.append(path)
    if not files:
        raise ICCContainerError(f"no supported source images found in {root}")
    return files


def run_sips(source: Path, destination: Path) -> tuple[str, str]:
    extension = normalized_extension(source)
    format_name = "jpeg" if extension == "jpg" else extension
    process = subprocess.run(
        ["/usr/bin/sips", "-s", "format", format_name, str(source), "--out", str(destination)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return ("ok" if process.returncode == 0 and destination.is_file() else "rejected", process.stdout)


def write_case(
    output_root: Path,
    relative: Path,
    data: bytes,
    source: Path,
    pixel_mode: str,
    requested: bytes | None,
    requested_name: str | None,
    requested_valid: bool | None,
    mutation: str | None,
    seed: int | None,
    processor: str,
    system_catalog: dict[str, str],
    processor_log: str | None = None,
) -> dict:
    path = output_root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    observed = extract_profile(data, path)
    outcome, system_match = classify_profile(requested, observed, system_catalog)
    entry = {
        "path": str(relative),
        "sourcePath": source.name,
        "sourceSHA256": sha256(source.read_bytes()),
        "fileSHA256": sha256(data),
        "format": normalized_extension(path),
        "pixelMode": pixel_mode,
        "processor": processor,
        "iccOutcome": outcome,
        "requestedICCName": requested_name,
        "requestedICCSHA256": sha256(requested) if requested is not None else None,
        "requestedICCSize": len(requested) if requested is not None else None,
        "requestedICCValid": requested_valid,
        "observedICCSHA256": sha256(observed) if observed is not None else None,
        "observedICCSize": len(observed) if observed is not None else None,
        "systemProfileMatch": system_match,
        "mutation": mutation,
        "seed": seed,
    }
    if requested is not None and outcome != "preserved_exact":
        evidence = output_root / "evidence" / relative.with_suffix("")
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / "requested.icc").write_bytes(requested)
        if observed is not None:
            (evidence / "observed.icc").write_bytes(observed)
        if processor_log is not None:
            log_path = evidence / "processor.log"
            log_path.write_text(
                processor_log, encoding="ascii", errors="backslashreplace"
            )
            entry["logPath"] = str(log_path.relative_to(output_root))
    return entry


def build(args: argparse.Namespace) -> int:
    input_root = args.input.resolve()
    output_root = args.output.resolve()
    protected = {Path("/").resolve(), Path.home().resolve(), Path.cwd().resolve()}
    if output_root in protected:
        raise ICCContainerError(f"refusing unsafe output directory: {output_root}")
    if output_root == input_root or input_root in output_root.parents:
        raise ICCContainerError("output must not be inside the input directory")
    if output_root.exists():
        existing = list(output_root.iterdir())
        manifest_path = output_root / "manifest.json"
        if existing:
            try:
                prior = json.loads(manifest_path.read_text(encoding="ascii"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise ICCContainerError(
                    f"refusing to replace unmanaged output directory: {output_root}"
                ) from error
            if prior.get("generator") != "xnuimagefuzzer-qa-corpus":
                raise ICCContainerError(
                    f"refusing to replace foreign output directory: {output_root}"
                )
            shutil.rmtree(output_root)
    output_root.mkdir(parents=True)

    catalog = system_profile_catalog(args.system_profiles.resolve())
    profiles = discover_profiles(args.icc_dir.resolve(), args.all_profiles)
    entries = []
    requested_modes = []

    for source in source_files(input_root):
        source_data = source.read_bytes()
        extension = normalized_extension(source)
        source_name = source.stem
        pixel_mode = "fuzzed" if source_name.startswith("fuzzed-") else "clean"
        if extract_profile(source_data, extension) is not None:
            raise ICCContainerError(f"source expected to be ICC-free: {source}")

        if args.icc_mode in ("none", "both"):
            relative = Path(pixel_mode) / "no-icc" / f"{source_name}.{extension}"
            entries.append(
                write_case(
                    output_root, relative, source_data, source, pixel_mode,
                    None, None, None, None, None, "none", catalog,
                )
            )
            requested_modes.append("none")

        if args.icc_mode in ("with", "both"):
            for profile_path in profiles:
                profile = profile_path.read_bytes()
                relative = (
                    Path(pixel_mode)
                    / "with-icc"
                    / profile_slug(profile_path)
                    / f"{source_name}.{extension}"
                )
                injected = inject_profile(source_data, profile, extension)
                entries.append(
                    write_case(
                        output_root, relative, injected, source, pixel_mode,
                        profile, profile_path.name, True, None, None,
                        "direct-container-injection", catalog,
                    )
                )
                requested_modes.append("with")

                if args.include_mutated:
                    for offset, strategy in enumerate(MUTATION_STRATEGIES):
                        mutation_seed = args.seed + offset
                        mutated = mutate_profile(profile, strategy, mutation_seed)
                        try:
                            validate_icc(mutated)
                            mutation_valid = True
                        except ICCContainerError:
                            mutation_valid = False
                        mut_relative = (
                            Path(pixel_mode)
                            / "mutated-icc"
                            / profile_slug(profile_path)
                            / strategy
                            / f"{source_name}.{extension}"
                        )
                        mutated_image = inject_profile(source_data, mutated, extension)
                        entries.append(
                            write_case(
                                output_root, mut_relative, mutated_image, source,
                                pixel_mode, mutated, profile_path.name, mutation_valid,
                                strategy, mutation_seed, "direct-container-injection",
                                catalog,
                            )
                        )
                        requested_modes.append("mutated")

                        if args.apple_roundtrip:
                            round_relative = Path("apple-roundtrip") / mut_relative
                            with tempfile.TemporaryDirectory(prefix="xnuimagefuzzer-sips-") as temp:
                                temp_path = Path(temp) / f"input.{extension}"
                                out_path = Path(temp) / f"output.{extension}"
                                temp_path.write_bytes(mutated_image)
                                status, log = run_sips(temp_path, out_path)
                                if status == "ok":
                                    round_data = out_path.read_bytes()
                                    entries.append(
                                        write_case(
                                            output_root, round_relative, round_data,
                                            source, pixel_mode, mutated,
                                            profile_path.name, mutation_valid, strategy,
                                            mutation_seed, "sips-roundtrip", catalog,
                                            processor_log=log,
                                        )
                                    )
                                else:
                                    evidence = output_root / "evidence" / round_relative.with_suffix("")
                                    evidence.mkdir(parents=True, exist_ok=True)
                                    requested_path = evidence / "requested.icc"
                                    requested_path.write_bytes(mutated)
                                    log_path = evidence / "processor.log"
                                    log_path.write_text(log, encoding="ascii", errors="backslashreplace")
                                    entries.append({
                                        "path": None,
                                        "sourcePath": source.name,
                                        "pixelMode": pixel_mode,
                                        "processor": "sips-roundtrip",
                                        "iccOutcome": "rejected",
                                        "requestedICCName": profile_path.name,
                                        "requestedICCSHA256": sha256(mutated),
                                        "requestedICCSize": len(mutated),
                                        "requestedICCValid": mutation_valid,
                                        "mutation": strategy,
                                        "seed": mutation_seed,
                                        "logPath": str(log_path.relative_to(output_root)),
                                        "requestedEvidencePath": str(
                                            requested_path.relative_to(output_root)
                                        ),
                                    })

    manifest = {
        "schemaVersion": 2,
        "generator": "xnuimagefuzzer-qa-corpus",
        "requestedICCMode": args.icc_mode,
        "includeMutated": args.include_mutated,
        "appleRoundtrip": args.apple_roundtrip,
        "seed": args.seed,
        "platform": platform.platform(),
        "entries": entries,
        "summary": {
            "artifacts": sum(entry.get("path") is not None for entry in entries),
            "rejected": sum(entry["iccOutcome"] == "rejected" for entry in entries),
            "outcomes": {
                outcome: sum(entry["iccOutcome"] == outcome for entry in entries)
                for outcome in sorted({entry["iccOutcome"] for entry in entries})
            },
            "requestedClasses": {
                mode: requested_modes.count(mode) for mode in sorted(set(requested_modes))
            },
        },
    }
    manifest_path = output_root / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )
    print(
        f"PASS: {manifest['summary']['artifacts']} artifacts; "
        f"outcomes={manifest['summary']['outcomes']}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--icc-dir", type=Path, default=Path("/System/Library/ColorSync/Profiles"))
    parser.add_argument("--system-profiles", type=Path, default=Path("/System/Library/ColorSync/Profiles"))
    parser.add_argument("--icc-mode", choices=("none", "with", "both"), default="both")
    parser.add_argument("--include-mutated", action="store_true")
    parser.add_argument("--apple-roundtrip", action="store_true")
    parser.add_argument("--all-profiles", action="store_true")
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()
    if args.apple_roundtrip and not args.include_mutated:
        parser.error("--apple-roundtrip requires --include-mutated")
    try:
        return build(args)
    except (ICCContainerError, OSError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
