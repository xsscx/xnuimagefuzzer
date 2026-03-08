# Build & Run — XNU Image Fuzzer

## Xcode (primary — Mac Catalyst)
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

## Xcode (ASAN + UBSAN — sanitizer testing only)
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

## Native clang (ASAN + UBSAN + Coverage — recommended)
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

## CMake (alternative)
```bash
mkdir xcode_build && cd xcode_build
cmake -G Xcode ../XNU\ Image\ Fuzzer/CMakeLists.txt
cmake --build . --config Debug
```

## Running the built binary
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

## Build Flags
- `GCC_TREAT_WARNINGS_AS_ERRORS=YES` — all warnings are errors
- `-Wall -Wextra` for clang builds
- `-Werror=macro-redefined` will catch duplicate `#define` issues

## Environment Variables
| Variable | Purpose |
|----------|---------|
| `FUZZ_OUTPUT_DIR` | Override image output directory (default: app Documents) |
| `FUZZ_ICC_DIR` | Directory of `.icc`/`.icm` profiles for embedding (round-robin) |
| `LLVM_PROFILE_FILE` | Coverage profraw output path |
| `ASAN_OPTIONS` | AddressSanitizer configuration |
| `UBSAN_OPTIONS` | UBSanitizer configuration |

## Coverage Instrumentation
- Uses clang source-based coverage: `-fprofile-instr-generate -fcoverage-mapping`
- The app uses `dlsym(RTLD_DEFAULT, "__llvm_profile_write_file")` to resolve
  coverage runtime symbols at runtime — avoids linker errors on non-instrumented builds
- Do NOT use `__attribute__((weak)) extern` — works on Mac Catalyst but fails on iOS Simulator linker
- Collect: `LLVM_PROFILE_FILE=/tmp/profraw/fuzzer-%m_%p.profraw ./binary`
- Merge: `llvm-profdata merge -sparse *.profraw -o merged.profdata`
- Report: `llvm-cov report ./binary -instr-profile=merged.profdata`
