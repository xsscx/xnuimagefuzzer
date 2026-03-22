# XNU Image Fuzzer App Target

This directory contains the app target resources and the Objective-C implementation that drives the fuzzer.

## What Lives Here

- `xnuimagefuzzer.m` is the main entry point and contains the permutation logic, metrics code, ICC handling, batch mode, chain mode, and pipeline mode.
- `ViewController.m` is a simple collection-view gallery for files written into the app Documents directory.
- `Info.plist` enables file sharing and in-place document access.
- `Flowers.exr` and `2225.jpg` are bundled sample inputs.
- `AppDelegate.*`, `SceneDelegate.*`, and the storyboards provide the app shell around the fuzzer code.

## Runtime Behavior

- Default output goes to the app Documents directory unless `FUZZ_OUTPUT_DIR` is set.
- The app supports these modes:
  - no arguments: generate 19 seed specs and run the matched permutation for each
  - `<imagePath> <permutation>`
  - `--chain <image> [--iterations N]`
  - `--input-dir <directory> [--iterations N]`
  - `--pipeline <directory> [--iterations N]`
- `processImage(-1)` reaches 17 permutations.
- Chained fuzzing now cycles permutations `1..17`.
- The final chained iteration keeps the regular output decodable and writes any intentional post-encoding corruption as a separate `corrupted_*` provenance file.
- `ViewController` only loads `.png`, `.jpg`, and `.jpeg` files from Documents. It does not enumerate the full set of generated formats.

## Output Naming

- Fixed bitmap-context saves use `fuzzed_image_<context>.<ext>`.
- Default seed generation also writes provenance-style files such as `seed_perm01_001.png` and `corrupted_perm01_001.png`.
- Chained outputs use `provenanceFileName()`, for example `input_perm06_inj03_sRGB2014_001.png`.
- Intentionally corrupted final chained outputs are written separately, for example `corrupted_input_perm06_inj03_sRGB2014_001.png`.
- Metrics are emitted as `*.metrics.json` plus `fuzz_metrics_summary.csv`.
- In CI-style runs with `FUZZ_ICC_DIR` populated, expect `seed_icc_*` PNGs, real/mutated ICC siblings for PNG/TIFF context outputs, and one `1Bit_Monochrome.png`.

## Build Notes

- The primary build surface is `../XNU Image Fuzzer.xcodeproj`.
- The Xcode project targets `iphoneos` and `iphonesimulator` and enables Mac Catalyst.
- `CMakeLists.txt` is an experimental alternative and is not a full mirror of the Xcode app target.
