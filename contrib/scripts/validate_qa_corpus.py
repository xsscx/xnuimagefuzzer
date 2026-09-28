#!/usr/bin/env python3
"""Validate the complete xnuimagefuzzer QA corpus contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from icc_container import (
    ICCContainerError,
    extract_profile,
    normalized_extension,
    sha256,
    validate_icc,
)


class ValidationError(ValueError):
    """Raised when a QA corpus violates its manifest."""


def safe_relative(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"invalid {label} path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValidationError(f"unsafe {label} path: {value}")
    return path


def validate(root: Path) -> int:
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise ValidationError("missing manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    if manifest.get("schemaVersion") != 2:
        raise ValidationError("unsupported manifest schema")
    if manifest.get("generator") != "xnuimagefuzzer-qa-corpus":
        raise ValidationError("unrecognized corpus generator")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValidationError("manifest has no entries")

    declared = {"manifest.json"}
    artifact_count = 0
    for entry in entries:
        relative = entry.get("path")
        if relative is None:
            if entry.get("iccOutcome") != "rejected":
                raise ValidationError("entry without artifact is not rejected")
            log_path = safe_relative(entry.get("logPath"), "rejection log")
            declared.add(str(log_path))
            if not (root / log_path).is_file():
                raise ValidationError(f"missing rejection log: {log_path}")
            requested_path = safe_relative(
                entry.get("requestedEvidencePath"), "requested evidence"
            )
            if not (root / requested_path).is_file():
                raise ValidationError("rejected entry has no requested ICC evidence")
            if sha256((root / requested_path).read_bytes()) != entry.get("requestedICCSHA256"):
                raise ValidationError("rejected requested ICC evidence hash mismatch")
            declared.add(str(requested_path))
            continue
        path = safe_relative(relative, "artifact")
        if relative in declared:
            raise ValidationError(f"unsafe or duplicate path: {relative}")
        declared.add(relative)
        artifact = root / path
        if normalized_extension(path) != entry.get("format"):
            raise ValidationError(f"artifact format/path mismatch: {relative}")
        if not artifact.is_file():
            raise ValidationError(f"missing artifact: {relative}")
        data = artifact.read_bytes()
        if sha256(data) != entry.get("fileSHA256"):
            raise ValidationError(f"file hash mismatch: {relative}")
        observed = extract_profile(data, entry["format"])
        observed_hash = sha256(observed) if observed is not None else None
        if observed_hash != entry.get("observedICCSHA256"):
            raise ValidationError(f"observed ICC hash mismatch: {relative}")
        if (len(observed) if observed is not None else None) != entry.get("observedICCSize"):
            raise ValidationError(f"observed ICC size mismatch: {relative}")

        outcome = entry.get("iccOutcome")
        requested_hash = entry.get("requestedICCSHA256")
        if outcome == "absent_expected":
            if observed is not None or requested_hash is not None:
                raise ValidationError(f"no-ICC contract violated: {relative}")
        elif outcome == "preserved_exact":
            if observed is None or observed_hash != requested_hash:
                raise ValidationError(f"exact ICC contract violated: {relative}")
            if entry.get("requestedICCValid"):
                validate_icc(observed)
        elif outcome in ("rewritten", "substituted_system_profile"):
            if observed is None or observed_hash == requested_hash:
                raise ValidationError(f"ICC rewrite classification invalid: {relative}")
            if outcome == "substituted_system_profile" and not entry.get("systemProfileMatch"):
                raise ValidationError(f"system substitution has no matching profile: {relative}")
            if outcome == "rewritten" and entry.get("systemProfileMatch"):
                raise ValidationError(f"rewrite incorrectly names a system profile: {relative}")
        elif outcome == "dropped":
            if observed is not None or requested_hash is None:
                raise ValidationError(f"ICC drop classification invalid: {relative}")
        elif outcome == "injected_without_input":
            if observed is None or requested_hash is not None:
                raise ValidationError(f"ICC injection classification invalid: {relative}")
        else:
            raise ValidationError(f"unknown ICC outcome: {outcome}")

        if requested_hash is not None and outcome != "preserved_exact":
            evidence = root / "evidence" / path.with_suffix("")
            requested_path = evidence / "requested.icc"
            if not requested_path.is_file() or sha256(requested_path.read_bytes()) != requested_hash:
                raise ValidationError(f"missing requested ICC evidence: {relative}")
            declared.add(str(requested_path.relative_to(root)))
            if observed is not None:
                observed_path = evidence / "observed.icc"
                if not observed_path.is_file() or sha256(observed_path.read_bytes()) != observed_hash:
                    raise ValidationError(f"missing observed ICC evidence: {relative}")
                declared.add(str(observed_path.relative_to(root)))
        log_value = entry.get("logPath")
        if log_value:
            log_path = safe_relative(log_value, "processor log")
            if not (root / log_path).is_file():
                raise ValidationError(f"missing processor log: {relative}")
            declared.add(str(log_path))
        artifact_count += 1

    actual = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()}
    if actual != declared:
        raise ValidationError(
            f"manifest/file set mismatch; extra={sorted(actual - declared)}, "
            f"missing={sorted(declared - actual)}"
        )
    expected_count = manifest.get("summary", {}).get("artifacts")
    if expected_count != artifact_count:
        raise ValidationError(
            f"artifact count mismatch: manifest={expected_count}, actual={artifact_count}"
        )
    actual_outcomes = {
        outcome: sum(entry.get("iccOutcome") == outcome for entry in entries)
        for outcome in sorted({entry.get("iccOutcome") for entry in entries})
    }
    if manifest.get("summary", {}).get("outcomes") != actual_outcomes:
        raise ValidationError("outcome summary mismatch")
    actual_rejected = sum(entry.get("iccOutcome") == "rejected" for entry in entries)
    if manifest.get("summary", {}).get("rejected") != actual_rejected:
        raise ValidationError("rejection summary mismatch")
    print(f"PASS: {artifact_count} manifest artifacts validated")
    return artifact_count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        validate(args.output.resolve())
    except (ICCContainerError, ValidationError, OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
