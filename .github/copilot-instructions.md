# Copilot Instructions — XNU Image Fuzzer

## Project Overview

XNU Image Fuzzer is a proof-of-concept iOS/macOS image fuzzing framework that generates
fuzzed images using all 12 CGBitmapContext color space and pixel format combinations.
It exercises Apple's CoreGraphics rendering pipeline across every supported bitmap
configuration to discover crashes, memory safety bugs, and undefined behavior.

- **Language**: Objective-C (main fuzzer), Python (validation scripts)
- **Platforms**: iOS 14.2+, macOS (Mac Catalyst), iPadOS, visionOS
- **License**: GPL v3
- **Author**: David Hoyt (@xsscx / @h02332)

## Repository Structure

```
XNU Image Fuzzer/
├── xnuimagefuzzer.m          # Core fuzzer — 12 bitmap contexts, fuzz permutations
├── ViewController.m           # UICollectionView displaying fuzzed images
├── AppDelegate.m              # App lifecycle, exception handler
├── SceneDelegate.{h,m}        # Multi-window scene management
├── CMakeLists.txt             # CMake build (iOS arm64, Debug with ASAN)
├── Info.plist                 # UIFileSharingEnabled=YES
├── Flowers.exr / 2225.jpg     # Sample input images
└── Base.lproj/                # Storyboards
contrib/scripts/
├── validate_fuzzed_images.py  # Steganography / injection detection
├── compare_image_directories.py  # MSE, SSIM, PSNR, entropy analysis
├── read-magic-numbers.py      # 40+ magic byte signatures
└── generate_filmstrip.py      # Side-by-side comparison strips
.github/
├── workflows/                 # 6 CI/CD workflows
├── scripts/sanitize-sed.sh    # Input sanitization for CI
└── prompts/                   # Copilot prompt templates
```

## Build Commands

### Xcode (primary — Mac Catalyst)
```bash
xcodebuild build \
  -project "XNU Image Fuzzer.xcodeproj" \
  -scheme "XNU Image Fuzzer" \
  -destination 'platform=macOS,variant=Mac Catalyst' \
  -configuration Debug \
  -derivedDataPath /tmp/DerivedData \
  CODE_SIGN_IDENTITY="-" \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=NO \
  ONLY_ACTIVE_ARCH=YES \
  GCC_TREAT_WARNINGS_AS_ERRORS=YES
```

### Xcode (instrumented — ASAN + UBSAN + Coverage)
```bash
xcodebuild build \
  -project "XNU Image Fuzzer.xcodeproj" \
  -scheme "XNU Image Fuzzer" \
  -destination 'platform=macOS,variant=Mac Catalyst' \
  -configuration Debug \
  -derivedDataPath /tmp/DerivedData \
  CODE_SIGN_IDENTITY="-" \
  CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO \
  ONLY_ACTIVE_ARCH=YES \
  GCC_TREAT_WARNINGS_AS_ERRORS=YES \
  CLANG_ADDRESS_SANITIZER=YES \
  CLANG_UNDEFINED_BEHAVIOR_SANITIZER=YES \
  CLANG_ENABLE_CODE_COVERAGE=YES \
  OTHER_CFLAGS='$(inherited) -fno-omit-frame-pointer'
```

### CMake (alternative)
```bash
mkdir xcode_build && cd xcode_build
cmake -G Xcode ../XNU\ Image\ Fuzzer/CMakeLists.txt
cmake --build . --config Debug
```

### Running the built binary
```bash
# Locate after build
BINARY=$(find /tmp/DerivedData -name "XNU Image Fuzzer" -type f -perm +111 \
  ! -path "*/Contents/Resources/*" | head -1)

# Run with sanitizers + coverage
FUZZ_OUTPUT_DIR=/tmp/fuzzed-output \
ASAN_OPTIONS="detect_leaks=0:halt_on_error=0" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
LLVM_PROFILE_FILE="/tmp/profraw/fuzzer-%m_%p.profraw" \
  timeout 120 "$BINARY"
```

## Architecture

### Core Fuzzing Pipeline
```
main() → UIApplicationMain()
  → AppDelegate → ViewController.viewDidLoad
    → dispatch_async(background)
      → performAllImagePermutations()
        → for each of 12 bitmap contexts:
            createBitmapContext*() → fill with fuzz data
            → CGBitmapContextCreateImage()
            → saveFuzzedImage() → Documents/
        → loadFuzzedImagesFromDocumentsDirectory()
        → UICollectionView reload
```

### 12 Bitmap Context Types
| # | Function | Format |
|---|----------|--------|
| 1 | createBitmapContextStandardRGB | RGBA premultiplied last |
| 2 | createBitmapContextPremultipliedFirstAlpha | ARGB premultiplied first |
| 3 | createBitmapContextNonPremultipliedAlpha | RGBA straight alpha |
| 4 | createBitmapContext16BitDepth | 16-bit per component |
| 5 | createBitmapContextGrayscale | 8-bit grayscale |
| 6 | createBitmapContextHDRFloatComponents | 32-bit float HDR |
| 7 | createBitmapContextAlphaOnly | Alpha channel only |
| 8 | createBitmapContext1BitMonochrome | 1-bit black/white |
| 9 | createBitmapContextBigEndian | Big-endian 32-bit |
| 10 | createBitmapContextLittleEndian | Little-endian 32-bit |
| 11 | createBitmapContext8BitInvertedColors | Inverted 8-bit |
| 12 | createBitmapContext32BitFloat4Component | RGBA 128-bit float |

### Output Formats
Images are saved as: PNG, JPEG, GIF, BMP, TIFF, HEIF
using `CGImageDestinationCreateWithURL` with the appropriate UTType.

### Environment Variables
| Variable | Purpose |
|----------|---------|
| `FUZZ_OUTPUT_DIR` | Override image output directory |
| `LLVM_PROFILE_FILE` | Coverage profraw output path |
| `ASAN_OPTIONS` | AddressSanitizer configuration |
| `UBSAN_OPTIONS` | UBSanitizer configuration |

## Coding Conventions

### Objective-C Style
- Use `#pragma mark -` sections for code organization
- ANSI color macros for console output: `MAG`, `BLUE`, `RED`, `GRN`, `YEL`, `CYN`
- Guard all `CGContextRef` with NULL checks before use
- Always `CGContextRelease()` and `free()` bitmap data in error paths
- Use `os_log` and `os_signpost` for structured logging
- `static int verboseLogging = 0;` controls debug output

### Memory Management
- Manual retain/release patterns in Core Graphics code
- `@autoreleasepool` blocks around image generation loops
- Always pair `CGColorSpaceCreate*` with `CGColorSpaceRelease`
- Always pair `CGContextRef` creation with release in all code paths
- Check `malloc()` return values — never assume success

### CGBitmapInfo Correctness
- Always cast `CGImageAlphaInfo` to `CGBitmapInfo`: `(CGBitmapInfo)kCGImageAlphaPremultipliedLast`
- Combine with byte order using `|`: `(CGBitmapInfo)kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big`
- Never pass raw `kCGImageAlpha*` constants where `CGBitmapInfo` is expected

### Build Flags
- `GCC_TREAT_WARNINGS_AS_ERRORS=YES` — all warnings are errors
- `-Wall -Wextra` for clang builds
- `-Werror=macro-redefined` will catch duplicate `#define` issues

## CI/CD Workflows

| Workflow | Purpose | Trigger |
|----------|---------|---------|
| `code-quality.yml` | ObjC syntax, Python lint, CMake check | push/PR |
| `build-and-test.yml` | Build, generate images, commit output | push/PR, cron 12h |
| `cached-build.yml` | Fast build with DerivedData cache | push/PR |
| `instrumented.yml` | ASAN+UBSAN+Coverage, quality validation | push/PR, dispatch |
| `release.yml` | Tag-triggered release with artifacts | tag v* |
| `codeql-analysis.yml` | GitHub CodeQL security scanning | push/PR |

### CI Security Hardening
- All action SHAs pinned (no `@v4` tags)
- `persist-credentials: false` on all checkouts
- `BASH_ENV=/dev/null`, `bash --noprofile --norc`
- `permissions: contents: read` (least privilege)
- Concurrency groups with `cancel-in-progress: true`
- No user-controllable inputs in `run:` blocks
- Input sanitization via `.github/scripts/sanitize-sed.sh`

### Pinned Action SHAs
```yaml
actions/checkout: 11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
actions/upload-artifact: ea165f8d65b6e75b540449e92b4886f43607fa02  # v4.6.2
actions/cache: 5a3ec84eff668545956fd18022155c47e93e2684  # v4.2.3
actions/download-artifact: d3f86a106a0bac45b974a628896c90dbdf5c8093  # v4.3.0
```

## Git Identity

Use bot identity for all commits — never personal info:
```bash
git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
```

## Platform Compatibility

| Platform | Status | Notes |
|----------|--------|-------|
| macOS 14+ arm64 | ✅ | Mac Catalyst, native execution |
| macOS 15+ x86_64 | ✅ | Rosetta 2 |
| iOS 17+ | ✅ | Primary target |
| iPadOS 17+ | ✅ | Full support |
| visionOS 1.x | ✅ | Supported |
| watchOS | ❌ | Not applicable |

## Quality Validation Scripts

### validate_fuzzed_images.py
Steganography analysis — checks LSB/MSB for injected attack strings:
- Buffer overflow patterns
- XSS payloads
- SQL injection
- Format string vulnerabilities
- XXE injection
- Path traversal

### read-magic-numbers.py
Validates 40+ file magic signatures, MIME type checking, HTML report generation.

### compare_image_directories.py
Cross-device comparison: MSE, SSIM, PSNR, perceptual hash, entropy.
**Requires**: opencv-python, scikit-image, imagehash, pillow-heif

## Common Issues & Solutions

### Build fails with `-Werror=macro-redefined`
Duplicate `#define` in xnuimagefuzzer.m. Remove the duplicate.

### Build fails with `-Wenum-conversion`
Cast `CGImageAlphaInfo` to `CGBitmapInfo`:
```objc
CGBitmapInfo bitmapInfo = (CGBitmapInfo)kCGImageAlphaPremultipliedLast;
```

### No images generated in CI
The app requires `UIApplicationMain()` to run — it's a UI app, not a CLI.
Mac Catalyst build runs the app natively with a 120s timeout.

### Coverage report empty
Check `LLVM_PROFILE_FILE` is set before running the binary.
Profraw files must be merged: `xcrun llvm-profdata merge -sparse *.profraw -o merged.profdata`
