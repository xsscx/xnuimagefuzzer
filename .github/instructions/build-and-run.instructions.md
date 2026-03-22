# Build & Run — XNU Image Fuzzer

## Recommended Path: Native Clang Helper

The fastest local way to get a runnable binary with sanitizers and coverage is:

```bash
.github/scripts/build-native.sh
.github/scripts/build-native.sh --build-only
.github/scripts/build-native.sh --run-only
```

This script builds `/tmp/native-build/xnuimagefuzzer`, runs it directly, writes fuzzed output to `/tmp/fuzzed-output`, and generates coverage artifacts in `/tmp/coverage-report`.

The helper now also validates the default-mode top-level corpus before reporting success:

- at least one `1Bit_Monochrome.png`
- non-zero real ICC and mutated ICC variant counts
- no structurally broken regular top-level outputs; only `corrupted_*` files may be malformed

## Xcode / Mac Catalyst Build

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

### Launching The Xcode-Built App

For Xcode-built Mac Catalyst output, launch the `.app` bundle with `open`. Do not rely on directly executing the Mach-O inside the bundle.

```bash
APP=$(find /tmp/DerivedData -name "XNU Image Fuzzer.app" -type d | sed -n '1p')
open --env FUZZ_OUTPUT_DIR=/tmp/fuzzed-output "$APP"
```

If you need extra environment variables:

```bash
open --env FUZZ_OUTPUT_DIR=/tmp/fuzzed-output \
     --env FUZZ_ICC_DIR=/System/Library/ColorSync/Profiles \
     --env LLVM_PROFILE_FILE=/tmp/profraw/fuzzer-%m_%p.profraw \
     "$APP"
```

## Xcode Sanitizer Build

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
  GCC_TREAT_WARNINGS_AS_ERRORS=YES \
  CLANG_ADDRESS_SANITIZER=YES \
  CLANG_UNDEFINED_BEHAVIOR_SANITIZER=YES \
  OTHER_CFLAGS='$(inherited) -fno-omit-frame-pointer'
```

> Do not add `CLANG_ENABLE_CODE_COVERAGE=YES` to the Mac Catalyst `xcodebuild` path. Coverage is handled by the native clang helper instead.

## Manual Native Clang Build

```bash
clang -arch arm64 -target arm64-apple-ios17.2-macabi \
  -isysroot "$(xcrun --show-sdk-path)" \
  -iframework "$(xcrun --show-sdk-path)/System/iOSSupport/System/Library/Frameworks" \
  -fobjc-arc -g -O0 -fno-omit-frame-pointer \
  -fsanitize=address,undefined \
  -fprofile-instr-generate -fcoverage-mapping \
  -framework Foundation -framework UIKit -framework CoreGraphics \
  -framework ImageIO -framework UniformTypeIdentifiers \
  -I"XNU Image Fuzzer" \
  "XNU Image Fuzzer"/*.m -o /tmp/xnuimagefuzzer
```

This output is a directly runnable helper binary, unlike the Xcode-built `.app` bundle path above.

## Run Modes

```bash
/tmp/native-build/xnuimagefuzzer
/tmp/native-build/xnuimagefuzzer /path/to/image.png 12
/tmp/native-build/xnuimagefuzzer --chain /path/to/image.png --iterations 3
/tmp/native-build/xnuimagefuzzer --input-dir /path/to/images --iterations 2
/tmp/native-build/xnuimagefuzzer --pipeline /path/to/images --iterations 2
```

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `FUZZ_OUTPUT_DIR` | Override image output directory |
| `FUZZ_ICC_DIR` | Directory of `.icc` and `.icm` profiles for embedding |
| `LLVM_PROFILE_FILE` | Coverage profraw output path |
| `ASAN_OPTIONS` | AddressSanitizer configuration |
| `UBSAN_OPTIONS` | UBSanitizer configuration |

## CI-Style Corpus Expectations

When default mode runs with `FUZZ_ICC_DIR=/System/Library/ColorSync/Profiles`, the simulator workflow expects this exact top-level output shape:

- 19 `seed_perm*.png`
- 19 `corrupted_perm*.png`
- 19 `seed_icc_perm*.png`
- 62 base `fuzzed_image_*` files
- 32 `_no_icc` files
- 32 `_icc_mismatch` files
- 32 real `_icc_<profile>` files
- 32 `_icc_mutated` files
- 1 `1Bit_Monochrome.png`
- 38 metrics JSON sidecars
- 1 `fuzz_metrics_summary.csv` with 39 lines

## Coverage

- Native clang builds use source-based coverage: `-fprofile-instr-generate -fcoverage-mapping`.
- The code resolves `__llvm_profile_write_file` and `__llvm_profile_set_filename` with `dlsym()` to avoid linker failures on non-instrumented builds.
- Do not switch to `__attribute__((weak)) extern` for those runtime symbols.

Manual coverage commands:

```bash
xcrun llvm-profdata merge -sparse /tmp/profraw/*.profraw -o /tmp/coverage-report/merged.profdata
xcrun llvm-cov report /tmp/native-build/xnuimagefuzzer \
  -instr-profile=/tmp/coverage-report/merged.profdata
```

## CMake

`XNU Image Fuzzer/CMakeLists.txt` is an experimental alternative and is not a feature-for-feature mirror of the Xcode app target. Use it only when you specifically need that path.
