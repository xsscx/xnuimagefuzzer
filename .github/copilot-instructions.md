# Copilot Instructions — XNU Image Fuzzer

## Project Overview

XNU Image Fuzzer is an Objective-C iOS app target with Mac Catalyst support plus local harness scripts for fuzzing Apple image parsing paths. The core implementation lives in `XNU Image Fuzzer/xnuimagefuzzer.m` and currently covers:

- 17 bitmap-context permutations in `processImage()`
- 19 seed specs in the default no-argument run
- ICC embedding, ICC mutation, and color-space stripping/mismatch variants
- multi-format re-encoding through `encodeImageMultiFormat()`
- chained, batch, and pipeline fuzzing modes
- metrics sidecars and summary CSV output

Important current caveats:

- `performPipelineFuzzing()` fuzzes a subset of permutations: `1,2,3,4,5,6,8,9,10,11,12,13,14,15`.
- `saveFuzzedImage()` uses fixed `fuzzed_image_*` names, so repeated default runs overwrite context outputs.
- `performChainedFuzzing()` now keeps the normal chain output decodable and writes the intentionally corrupted final pass as a separate `corrupted_*` provenance file.
- `ViewController` only loads `.png`, `.jpg`, and `.jpeg` files from Documents.
- Treat the checked-in Xcode project and the maintainer-verified GitHub Actions matrix as separate scopes. The project file shows the local target surface; Actions/output verification may be broader.

## Documentation Map

Detailed instructions are split into specialized files.

| Document | Path | Focus |
|----------|------|-------|
| Build & Run | `.github/instructions/build-and-run.instructions.md` | Xcode, native clang helper, environment variables |
| Architecture | `.github/instructions/architecture.instructions.md` | Entry modes, naming, permutations, pipeline behavior |
| Troubleshooting | `.github/instructions/troubleshooting.instructions.md` | Mac Catalyst launch quirks, coverage, CI pitfalls |
| CI Workflow Maintenance | `.github/prompts/ci-workflow-maintenance.prompt.md` | GitHub Actions conventions |
| Code Review | `.github/prompts/code-review.prompt.md` | Review focus areas |
| Fuzz & Validate | `.github/prompts/fuzz-and-validate.prompt.md` | Local fuzzing and artifact inspection |

## Repository Structure

```text
.
├── XNU Image Fuzzer/
│   ├── xnuimagefuzzer.m
│   ├── ViewController.m
│   ├── AppDelegate.m
│   ├── SceneDelegate.m
│   ├── Info.plist
│   ├── CMakeLists.txt
│   ├── Flowers.exr
│   └── 2225.jpg
├── XNU Image Fuzzer.xcodeproj/
├── .github/
│   ├── instructions/
│   ├── prompts/
│   ├── scripts/build-native.sh
│   └── workflows/
├── contrib/scripts/extract-icc-seeds.py
├── fuzz-apps.sh
├── fuzz-gallery.py
├── read-magic-numbers.py
├── fuzzing-memory-pattern-generator.py
├── exr-channel-subsampling-example.py
├── codeql-queries/
└── fuzzed-images/
```

## Quick Reference

### Native clang helper

```bash
.github/scripts/build-native.sh
```

This produces a directly runnable helper binary at `/tmp/native-build/xnuimagefuzzer`.

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

Launch the resulting `.app` with `open --env`; do not rely on directly executing the Mach-O inside the bundle.

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
- `ASAN_OPTIONS`
- `UBSAN_OPTIONS`

## Output Expectations

Default runs write:

- provenance-style seed and corrupted PNGs
- provenance-style `seed_icc_*` PNGs when `FUZZ_ICC_DIR` is populated
- fixed-name `fuzzed_image_*` outputs for each exercised bitmap context
- real-ICC, mutated-ICC, no-ICC, and mismatch siblings for PNG and TIFF outputs
- `1Bit_Monochrome.png`
- `*.metrics.json`
- `fuzz_metrics_summary.csv`

Workflow-specific invariants worth remembering:

- `build-and-test` now passes `FUZZ_ICC_DIR=/System/Library/ColorSync/Profiles` and validates an exact 287-file top-level simulator corpus with a 39-line summary CSV.
- `.github/scripts/build-native.sh` now fails if default-mode monochrome output is missing, if real/mutated ICC variants are missing, or if any regular top-level output is structurally invalid.
- Only `corrupted_*` files are allowed to be generic `data` or otherwise structurally broken.

Pipeline runs also create:

- `pipeline-clean`
- `pipeline-formats`
- `pipeline-fuzzed`
- `pipeline-icc`
- `pipeline-combo`
- `pipeline-chained`
- `pipeline-profiles`

## Platform Compatibility

| Platform | Status | Notes |
|----------|--------|-------|
| iOS 17.2+ | Configured | `iphoneos` target |
| iPadOS 17.2+ | Configured | same target family as iPhone/iPad |
| iOS Simulator | Configured | used by CI |
| Mac Catalyst | Configured | `SUPPORTS_MACCATALYST=YES` |
| Native clang helper on macOS | Supported helper path | used for sanitizer + coverage runs |
| Watch-related build/output validation | Maintainer-verified via GitHub Actions | do not infer absence from the local project file alone |
| visionOS | Not configured in the checked-in project file | no dedicated local target here |

## Local Utilities

| Script | Purpose | Notes |
|--------|---------|-------|
| `fuzz-apps.sh` | Feed generated files into macOS parser consumers | captures exit codes and crash reports |
| `fuzz-gallery.py` | Serve a local WebKit/Safari decode gallery | browser-focused harness |
| `contrib/scripts/extract-icc-seeds.py` | Extract ICC/TIFF seeds from fuzz outputs | useful for downstream corpus seeding |
| `read-magic-numbers.py` | Generate a file-signature HTML report | currently hard-codes a directory path at the bottom |
| `fuzzing-memory-pattern-generator.py` | Generate a cyclic memory pattern | simple helper, no CLI args |
| `exr-channel-subsampling-example.py` | Inspect EXR channel layout and subsampling | example script with hard-coded input path |

## Git Identity For CI Commits

```bash
git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
```
