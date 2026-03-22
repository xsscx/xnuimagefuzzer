# XNU Image Fuzzer

Objective-C image fuzzing app and local harness set for exercising Apple image decoding and re-encoding paths through CoreGraphics, ImageIO, ColorSync, and related consumers.

## What Is In This Repository

- `XNU Image Fuzzer/` contains the iOS app target, bundled sample inputs, and the core fuzzer implementation in `xnuimagefuzzer.m`.
- `.github/scripts/build-native.sh` is a Bash helper that builds a native arm64 Mac Catalyst-style binary with ASAN, UBSAN, and source-based coverage.
- `fuzz-apps.sh` feeds generated images into macOS parser consumers such as `sips`, QuickLook, `mdimport`, and `tiffutil`.
- `fuzz-gallery.py` serves a local WebKit/Safari decode gallery for browser-side exercising.
- `contrib/scripts/extract-icc-seeds.py` extracts ICC profiles and TIFF seeds from run output for downstream corpus use.
- `codeql-queries/` contains repository-local CodeQL queries for Objective-C/C security checks.
- `fuzzed-images/` stores timestamped sample outputs committed by CI runs.

## Current Behavior

- `processImage()` supports 17 bitmap-context permutations.
- The default no-argument mode generates 19 seed specs, saves `seed_*` and `corrupted_*` PNGs, and then runs the matched permutation for each seed.
- When `FUZZ_ICC_DIR` is set, the default mode also writes `seed_icc_*` PNGs plus real-ICC, mutated-ICC, no-ICC, and ICC-mismatch siblings for PNG/TIFF context outputs.
- Additional CLI modes are `<imagePath> <permutation>`, `--chain <image>`, `--input-dir <dir>`, and `--pipeline <dir>`.
- Chained fuzzing now cycles permutations `1..17`; the regular chain output remains decodable and any intentional final corruption is written separately under `corrupted_*`.
- Metrics are written as `*.metrics.json` sidecars plus `fuzz_metrics_summary.csv`.
- The checked-in Xcode project targets `iphoneos` and `iphonesimulator` and enables Mac Catalyst.
- The maintainer also verifies broader GitHub Actions build and output coverage, including watch-related outputs, separately from the local project file declared in this checkout.

## Quick Start

### Native clang helper

```bash
.github/scripts/build-native.sh
```

Run it as an executable or with `bash`. Do not invoke it with `sh`; the helper uses Bash syntax.

Artifacts land in:

- `/tmp/native-build/xnuimagefuzzer`
- `/tmp/fuzzed-output/`
- `/tmp/profraw/`
- `/tmp/coverage-report/`

### Xcode / Mac Catalyst

```bash
xcodebuild build \
  -project "XNU Image Fuzzer.xcodeproj" \
  -scheme "XNU Image Fuzzer" \
  -destination 'platform=macOS,variant=Mac Catalyst' \
  -configuration Debug \
  -derivedDataPath /tmp/DerivedData \
  CODE_SIGN_IDENTITY="-" \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=NO
```

Launch the built app bundle with `open`, not by executing the Mach-O directly:

```bash
APP=$(find /tmp/DerivedData -name "XNU Image Fuzzer.app" -type d | sed -n '1p')
open --env FUZZ_OUTPUT_DIR=/tmp/fuzzed-output "$APP"
```

### CLI modes

```bash
/tmp/native-build/xnuimagefuzzer
/tmp/native-build/xnuimagefuzzer /path/to/image.png 12
/tmp/native-build/xnuimagefuzzer --chain /path/to/image.png --iterations 3
/tmp/native-build/xnuimagefuzzer --input-dir /path/to/images --iterations 2
/tmp/native-build/xnuimagefuzzer --pipeline /path/to/images --iterations 2
```

Environment variables:

- `FUZZ_OUTPUT_DIR`
- `FUZZ_ICC_DIR`
- `LLVM_PROFILE_FILE`

## Output Layout

Default mode writes directly into the output directory:

- `seed_perm##_###.png`
- `corrupted_perm##_###.png`
- `seed_icc_perm##_<profile>_###.png` when ICC profiles are available
- `fuzzed_image_<context>.<ext>` plus ICC, no-ICC, and mismatch variants for PNG and TIFF outputs
- `corrupted_<input>_perm##_inj##_<icc-or-none>_###.<ext>` for intentionally corrupted final chained outputs
- `*.metrics.json`
- `fuzz_metrics_summary.csv`

Pipeline mode adds subdirectories:

- `pipeline-clean`
- `pipeline-formats`
- `pipeline-fuzzed`
- `pipeline-icc`
- `pipeline-combo`
- `pipeline-chained`
- `pipeline-profiles`

## Utilities

- `./fuzz-apps.sh <dir>` exercises macOS parser consumers and captures crash reports.
- `python3 fuzz-gallery.py <dir>` serves a local gallery for Safari/WebKit decode paths.
- `python3 contrib/scripts/extract-icc-seeds.py --input <dir> --output <dir>` extracts ICC and TIFF seeds.
- `python3 read-magic-numbers.py` is an ad hoc report generator that currently uses a hard-coded directory at the bottom of the script.
- `python3 exr-channel-subsampling-example.py` and `python3 fuzzing-memory-pattern-generator.py` are focused helper scripts, not polished CLIs.

## Notes For Future Work

- `performPipelineFuzzing()` uses a curated subset of 14 permutations and currently skips alpha-only, Display P3, and BT.2020 outputs in its fuzz phase.
- `saveFuzzedImage()` uses fixed `fuzzed_image_*` names, so repeated default runs overwrite context outputs; provenance-style naming is used for seeds, corrupted outputs, and chained outputs instead.
- The simulator `build-and-test` workflow now sets `FUZZ_ICC_DIR=/System/Library/ColorSync/Profiles` and validates a 287-file top-level corpus: 19 `seed_perm*.png`, 19 `corrupted_perm*.png`, 19 `seed_icc_perm*.png`, 62 base `fuzzed_image_*` files, 32 each of `_no_icc`, `_icc_mismatch`, real `_icc_<profile>`, and `_icc_mutated` variants, 1 `1Bit_Monochrome.png`, 38 metrics JSON sidecars, and 1 summary CSV with 39 lines.
- Treat structurally broken files as intentional only when they are named `corrupted_*`. Regular `seed_*`, `seed_icc_*`, `fuzzed_image_*`, and `1Bit_*` outputs are expected to remain decodable.

## License

GPL-3.0-or-later. See `LICENSE`.
