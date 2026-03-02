# Copilot Instructions — XNU Image Fuzzer

## Project Overview

XNU Image Fuzzer is a proof-of-concept iOS/macOS image fuzzing framework that generates
fuzzed images using 15 CGBitmapContext color space and pixel format combinations (including
CMYK, HDR Float16, and Indexed Color), plus structure-aware PNG chunk mutations.
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

### Xcode (ASAN + UBSAN — sanitizer testing only)
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
  OTHER_CFLAGS='$(inherited) -fno-omit-frame-pointer'
```

> **⚠️ Do NOT add `CLANG_ENABLE_CODE_COVERAGE=YES` to xcodebuild Mac Catalyst builds.**
> Xcode does NOT inject `-fprofile-instr-generate -fcoverage-mapping` for Mac Catalyst.
> The binary will have ASAN/UBSAN symbols but zero coverage instrumentation.
> Use the native clang build below for coverage.

### Native clang (ASAN + UBSAN + Coverage — recommended)
```bash
# Use the build script (handles everything):
.github/scripts/build-native.sh           # full pipeline: build + run + coverage
.github/scripts/build-native.sh --build-only  # compile only
.github/scripts/build-native.sh --run-only    # run existing binary

# Or build manually:
clang -arch arm64 -target arm64-apple-ios17.2-macabi \
  -isysroot $(xcrun --show-sdk-path) \
  -iframework $(xcrun --show-sdk-path)/System/iOSSupport/System/Library/Frameworks \
  -fobjc-arc -g -O0 -fno-omit-frame-pointer \
  -fsanitize=address,undefined \
  -fprofile-instr-generate -fcoverage-mapping \
  -framework Foundation -framework UIKit -framework CoreGraphics \
  -framework ImageIO -framework UniformTypeIdentifiers \
  -I"XNU Image Fuzzer" \
  "XNU Image Fuzzer"/*.m -o /tmp/xnuimagefuzzer
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
  ! -path "*/Contents/Resources/*" | sed -n '1p')

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
main() → performAllImagePermutations()
  → for each of 17 seed specs (8×8 to 4096×4096):
      createBitmapContext*() → fill with fuzz data
      → CGBitmapContextCreateImage()
      → saveFuzzedImage(seed) → FUZZ_OUTPUT_DIR/
      → applyPostEncodingCorruption(seed) → 6 PNG chunk-level mutations
      → saveFuzzedImage(corrupted) → FUZZ_OUTPUT_DIR/
      → processImage(seed, permutation) → save as PNG/JPEG/GIF/TIFF
  → __llvm_profile_write_file() (if instrumented)
```

### Post-Encoding Corruption (Structure-Aware)
6 PNG chunk mutation strategies applied after encoding:
1. IHDR dimension corruption (width/height = 0 or 0xFFFF)
2. IDAT stream truncation (50% of data removed)
3. CRC invalidation on random chunks
4. Chunk type mangling (swap chunk names)
5. Extra data injection between chunks
6. Chunk reordering (move IDAT before IHDR)

### 15 Bitmap Context Types
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
| 13 | createBitmapContextCMYK | CMYK with RGB fallback |
| 14 | createBitmapContextHDRFloat16 | IEEE 754 half-precision edge cases |
| 15 | createBitmapContextIndexedColor | 5 palette variants with corruption |

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
| `instrumented.yml` | ASAN+UBSAN testing + native clang coverage | push/PR, dispatch |
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

### Mac Catalyst app exits immediately
Running the bare Mach-O binary directly doesn't work for Mac Catalyst UIKit apps.
Must use `open "$APP_BUNDLE"` to properly initialize UIKit.

### Running Mac Catalyst with env vars
`launchctl setenv` is unreliable. Use `open --env` (macOS 13+):
```bash
open --env FUZZ_OUTPUT_DIR=/tmp/fuzzed-output \
     --env LLVM_PROFILE_FILE=/tmp/profraw/%m_%p.profraw \
     "$APP_BUNDLE"
```

### Coverage report empty (no profraw)
The app uses `dlsym(RTLD_DEFAULT, "__llvm_profile_write_file")` to resolve
coverage runtime symbols at runtime — this avoids linker errors on non-instrumented
builds (iOS Simulator without `-fprofile-instr-generate`). Do NOT use
`__attribute__((weak)) extern` for these symbols — it works on Mac Catalyst
but fails on the iOS Simulator linker.

If profraw is still missing:
1. Verify `LLVM_PROFILE_FILE` env var reaches the process (`open --env`)
2. Ensure the output directory exists and is writable
3. The app must exit cleanly (`return 0`) — not be killed by SIGTERM

### SIGPIPE crash in CI
Never pipe `xcodebuild`, `xcrun`, `ls`, `file`, `find`, or any Apple/BSD CLI
tools through `| head`. They use NSFileHandle for stdout and crash with
`NSFileHandleOperationException` (SIGABRT exit 134) or `stdout: Undefined error: 0`
when the reader closes early. Use these alternatives:
- `| head -N` → `| sed -n '1,Np'`
- `| head -1` → `| sed -n '1p'`
- `| head -cN` → `| cut -c1-N`
- `| head -2 | tail -1` → `| sed -n '2p'`

### Preserving output with `| tail`
Bare `| tail` discards everything except the last lines. Use `| tee /tmp/log | tail`
to preserve full output in a log file while showing a summary in CI:
```bash
xcodebuild ... | tee /tmp/xcodebuild.log | tail -5
```

### No images generated in CI
Mac Catalyst build uses `open --env` to launch the app. The CI polls for
≥80 files with a 120s timeout. If the app generates fewer than expected,
increase the timeout or check if new permutations were added without
updating the polling threshold.

## Local Development (macOS)

### Quick build + run
```bash
# Build
xcodebuild build \
  -project "XNU Image Fuzzer.xcodeproj" \
  -scheme "XNU Image Fuzzer" \
  -destination 'platform=macOS,variant=Mac Catalyst' \
  -configuration Debug \
  -derivedDataPath /tmp/DerivedData \
  CODE_SIGN_IDENTITY="-" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO \
  GCC_TREAT_WARNINGS_AS_ERRORS=YES

# Find the app bundle
APP=$(find /tmp/DerivedData -name "XNU Image Fuzzer.app" -type d | sed -n '1p')

# Run with output directory
open --env FUZZ_OUTPUT_DIR=/tmp/fuzzed-output "$APP"

# Wait for completion (check file count)
while [ $(find /tmp/fuzzed-output -type f 2>/dev/null | wc -l) -lt 80 ]; do sleep 2; done

# View results
ls -la /tmp/fuzzed-output/
```

### CoreGraphics debug environment variables
For verbose CoreGraphics/Quartz diagnostics during local fuzzing, export
these Apple-private debug env vars. They surface internal CG errors,
backtraces, color conversion details, and memory allocation info that
would otherwise be silent:
```bash
# CoreGraphics verbose diagnostics
export CG_VERBOSE=1
export CG_INFO=1
export CG_PDF_VERBOSE=1
export CG_CONTEXT_SHOW_BACKTRACE=1
export CG_CONTEXT_SHOW_BACKTRACE_ON_ERROR=1
export CG_IMAGE_SHOW_MALLOC=1
export CG_IMAGE_LOG_FORCE=1
export CG_LAYER_SHOW_BACKTRACE=1
export CGBITMAP_CONTEXT_LOG=1
export CGBITMAP_CONTEXT_LOG_ERRORS=1
export CGCOLORDATAPROVIDER_VERBOSE=1
export CG_RASTERIZER_VERBOSE=1
export CG_VERBOSE_COPY_IMAGE_BLOCK_DATA=1
export CG_FONT_RENDERER_VERBOSE=1
export CG_COLOR_CONVERSION_VERBOSE=1
export CG_POSTSCRIPT_VERBOSE=1

# PDF-specific
export CGPDF_LOG_PAGES=1
export CGPDF_VERBOSE=1
export CGPDF_DRAW_VERBOSE=1
export CGPDFCONTEXT_VERBOSE=1

# QuartzCore / Core Animation
export QuartzCoreDebugEnabled=1
export CI_PRINT_TREE=1
```

When running via `open --env`, pass each var individually:
```bash
open --env CG_VERBOSE=1 --env CGBITMAP_CONTEXT_LOG=1 \
     --env CG_CONTEXT_SHOW_BACKTRACE_ON_ERROR=1 \
     --env FUZZ_OUTPUT_DIR=/tmp/fuzzed-output "$APP"
```

### macOS malloc debugging
Apple's libmalloc has built-in guards that catch heap corruption, use-after-free,
and buffer overruns independent of ASAN. Useful when running without sanitizers
or to cross-validate ASAN findings:
```bash
# Heap corruption detection
export MallocGuardEdges=1          # Guard pages at heap block edges
export MallocDoNotProtectPrelude=1 # Don't guard before block (detect overruns)
export MallocDoNotProtectPostlude=1 # Don't guard after block (detect underruns)
export MallocScribble=1            # Fill freed memory with 0x55, alloc with 0xAA
export MallocCheckHeapStart=100    # Start heap validation after N allocs
export MallocCheckHeapEach=100     # Validate heap every N allocs
export MallocStackLogging=1        # Record stack traces for allocs (use with leaks/malloc_history)
export MallocStackLoggingNoCompact=1 # Full stack logging (not compacted)

# Crash on error instead of continuing
export MallocErrorAbort=1
export MallocCorruptionAbort=1
```

Post-mortem analysis with malloc stack logging:
```bash
# After a crash, use malloc_history to find the allocation
malloc_history <pid> <address>

# Or use leaks(1) for live process
leaks --atExit -- /tmp/xnuimagefuzzer
```

### Objective-C runtime debugging
```bash
# Zombie objects — detect use-after-release (messages to freed objects)
export NSZombieEnabled=YES
export NSDeallocateZombies=NO      # Keep zombies around (don't re-free)

# Autorelease pool debugging
export OBJC_DEBUG_POOL_ALLOCATION=YES
export OBJC_DEBUG_MISSING_POOLS=YES

# Log method dispatch (extremely verbose — use sparingly)
# export OBJC_PRINT_EXCEPTIONS=YES
# export OBJC_PRINT_EXCEPTION_THROW=YES
# export NSObjCMessageLoggingEnabled=YES
```

### ASAN + UBSAN tuning for image fuzzing
```bash
# ASAN — recommended settings for image fuzzer
export ASAN_OPTIONS="detect_leaks=0:halt_on_error=0:print_stats=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:detect_odr_violation=0:alloc_dealloc_mismatch=0"

# UBSAN — catch everything
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:silence_unsigned_overflow=1"

# TSAN (if building with -fsanitize=thread instead)
# export TSAN_OPTIONS="halt_on_error=0:second_deadlock_stack=1"
```

### DYLD debugging (dynamic linker)
```bash
# Show library load order (helps diagnose missing frameworks)
export DYLD_PRINT_LIBRARIES=1

# Show search paths for frameworks
export DYLD_PRINT_SEARCHING=1

# Insert custom dylibs (e.g. libgmalloc for Guard Malloc)
# export DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib

# Note: SIP-protected binaries ignore DYLD_* vars.
# Native clang builds are NOT SIP-protected, so these work.
```

### Guard Malloc (libgmalloc)
Extreme heap protection — each allocation gets its own VM page with guard pages.
Catches single-byte overruns that ASAN might miss but runs 100x slower:
```bash
# Via DYLD (native clang builds only — not SIP-protected)
DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib /tmp/xnuimagefuzzer

# Or via env var
export MALLOC_PROTECT_BEFORE=1  # Guard page before allocation (catch underruns)
# Default: guard page after allocation (catch overruns)
```

### Crash report collection
```bash
# macOS crash reports land here:
ls ~/Library/Logs/DiagnosticReports/

# For immediate crashes, use lldb:
lldb -- /tmp/xnuimagefuzzer
(lldb) env FUZZ_OUTPUT_DIR=/tmp/fuzzed-output
(lldb) env ASAN_OPTIONS=detect_leaks=0:halt_on_error=1
(lldb) run
# On crash: bt, frame variable, register read
```

### ImageIO / image format debugging
```bash
# Force ImageIO to log decode errors
export IMAGEIO_DEBUG=1

# CGImageSource verbose logging
export CG_IMAGE_LOG_FORCE=1
```

### Instrumented build + coverage (native clang — recommended)
```bash
# The build script handles everything:
.github/scripts/build-native.sh

# This will:
# 1. Build with clang -fsanitize=address,undefined -fprofile-instr-generate -fcoverage-mapping
# 2. Run the binary (produces fuzzed images + profraw)
# 3. Generate coverage report (text + HTML + LCOV)
```

### ASAN-only build (xcodebuild — no coverage)
```bash
# Build with sanitizers (no coverage — Xcode doesn't inject it for Mac Catalyst)
xcodebuild build \
  -project "XNU Image Fuzzer.xcodeproj" \
  -scheme "XNU Image Fuzzer" \
  -destination 'platform=macOS,variant=Mac Catalyst' \
  -configuration Debug \
  -derivedDataPath /tmp/DerivedData \
  CODE_SIGN_IDENTITY="-" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO \
  CLANG_ADDRESS_SANITIZER=YES CLANG_UNDEFINED_BEHAVIOR_SANITIZER=YES \
  OTHER_CFLAGS='$(inherited) -fno-omit-frame-pointer'

# Run with sanitizers
mkdir -p /tmp/fuzzed-output
APP=$(find /tmp/DerivedData -name "XNU Image Fuzzer.app" -type d | sed -n '1p')
open --env FUZZ_OUTPUT_DIR=/tmp/fuzzed-output \
     --env ASAN_OPTIONS="detect_leaks=0:halt_on_error=0" \
     "$APP"

# Wait for completion
while [ $(find /tmp/fuzzed-output -type f 2>/dev/null | wc -l) -lt 80 ]; do sleep 2; done
```
