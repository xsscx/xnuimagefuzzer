# Copilot Instructions — XNU Image Fuzzer

## Project Overview

XNU Image Fuzzer is a proof-of-concept iOS/macOS image fuzzing framework that generates
fuzzed images using 15 CGBitmapContext color space and pixel format combinations (including
CMYK, HDR Float16, and Indexed Color), plus structure-aware PNG chunk mutations.
It exercises Apple's CoreGraphics rendering pipeline across every supported bitmap
configuration to discover crashes, memory safety bugs, and undefined behavior.

This is the **primary development repository** for the fuzzer. It is used as a
[git submodule](https://github.com/xsscx/xnuimagetools) in xnuimagetools at path
`XNU Image Fuzzer/`. Code changes go here first, then the submodule pointer is updated.

- **Language**: Objective-C (main fuzzer), Python (validation scripts)
- **Platforms**: iOS 14.2+, macOS (Mac Catalyst), iPadOS, visionOS
- **License**: GPL v3
- **Author**: David Hoyt (@xsscx / @h02332)

## Documentation Map

Detailed instructions are split into specialized files. Copilot loads them
automatically based on which files you're editing.

| Document | Path | Triggered By |
|----------|------|-------------|
| **Build & Run** | `.github/instructions/build-and-run.instructions.md` | Build scripts, CMakeLists.txt, workflows |
| **Architecture** | `.github/instructions/architecture.instructions.md` | xnuimagefuzzer.m, ViewController.m |
| **Troubleshooting** | `.github/instructions/troubleshooting.instructions.md` | CI workflows, debugging sessions |
| **CI Workflow Maintenance** | `.github/prompts/ci-workflow-maintenance.prompt.md` | GitHub Actions workflow files |
| **Code Review** | `.github/prompts/code-review.prompt.md` | Pull request reviews |
| **Fuzz & Validate** | `.github/prompts/fuzz-and-validate.prompt.md` | End-to-end test runs |

## Repository Structure

```
XNU Image Fuzzer/
├── xnuimagefuzzer.m          # Core fuzzer — 15 bitmap contexts, fuzz permutations
├── ViewController.m           # UICollectionView displaying fuzzed images
├── AppDelegate.m              # App lifecycle, exception handler
├── SceneDelegate.{h,m}        # Multi-window scene management
├── CMakeLists.txt             # CMake build (iOS arm64, Debug with ASAN)
├── Info.plist                 # JPEG/PNG/GIF doc types, UIFileSharingEnabled=YES
├── Assets.xcassets            # App icon asset catalog
├── Flowers.exr / 2225.jpg     # Sample input images
└── Base.lproj/                # Storyboards
contrib/scripts/
├── validate_fuzzed_images.py  # Steganography / injection detection
├── compare_image_directories.py  # MSE, SSIM, PSNR, entropy analysis
├── read-magic-numbers.py      # 40+ magic byte signatures
└── generate_filmstrip.py      # Side-by-side comparison strips
.github/
├── workflows/                 # 6 CI/CD workflows
├── instructions/              # Path-specific Copilot instructions
├── scripts/sanitize-sed.sh    # Input sanitization for CI
└── prompts/                   # Copilot prompt templates
```

## Quick Reference

### Build (one-liner)
```bash
.github/scripts/build-native.sh           # ASAN+UBSAN+coverage — recommended
```

### Run
```bash
FUZZ_OUTPUT_DIR=/tmp/fuzzed-output timeout 120 /tmp/xnuimagefuzzer
```

### Validate output
```bash
python3 contrib/scripts/validate_fuzzed_images.py /tmp/fuzzed-output
```

See `.github/instructions/build-and-run.instructions.md` for all build variants
(Xcode, native clang, CMake) and environment variable reference.

## CI/CD Workflows

| Workflow | Purpose | Trigger |
|----------|---------|---------|
| `code-quality.yml` | ObjC syntax, Python lint, CMake check | push/PR |
| `build-and-test.yml` | Build, generate images, commit output | push/PR, cron 12h |
| `cached-build.yml` | Fast build with DerivedData cache | push/PR |
| `instrumented.yml` | ASAN+UBSAN testing + native clang coverage | push/PR, dispatch |
| `release.yml` | Tag-triggered release with artifacts | tag v* |
| `codeql-analysis.yml` | GitHub CodeQL security scanning | push/PR |

### CI Security Hardening
- All action SHAs pinned (no `@v4` tags)
- `persist-credentials: false` on all checkouts
- `BASH_ENV=/dev/null`, `bash --noprofile --norc`
- `permissions: contents: read` (least privilege)
- Concurrency groups with `cancel-in-progress: true`
- Input sanitization via `.github/scripts/sanitize-sed.sh`

## Platform Compatibility

| Platform | Status | Notes |
|----------|--------|-------|
| macOS 14+ arm64 | ✅ | Mac Catalyst, native execution |
| macOS 15+ x86_64 | ✅ | Rosetta 2 |
| iOS 17+ | ✅ | Primary target |
| iPadOS 17+ | ✅ | Full support |
| visionOS 1.x | ✅ | Supported |
| watchOS | ❌ | Not applicable |

## Git Identity

Use bot identity for all commits — never personal info:
```bash
git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
```

## Quality Validation Scripts

| Script | Purpose |
|--------|---------|
| `validate_fuzzed_images.py` | Steganography — LSB/MSB injection detection (XSS, SQLi, XXE, path traversal) |
| `read-magic-numbers.py` | 40+ file magic signatures, MIME type checking, HTML report |
| `compare_image_directories.py` | MSE, SSIM, PSNR, perceptual hash, entropy (requires opencv-python, scikit-image) |
| `generate_filmstrip.py` | Side-by-side comparison strips |
