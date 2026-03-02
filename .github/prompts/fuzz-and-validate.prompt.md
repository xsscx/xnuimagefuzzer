---
name: Fuzz and Validate Images
description: Build the fuzzer with sanitizers, run it, and validate output quality
---

# Fuzz and Validate Images

Build XNU Image Fuzzer with ASAN+UBSAN, run the fuzzer on macOS (Mac Catalyst),
and validate the output images for quality and correctness.

## Steps

1. **Build with instrumentation**
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
     CLANG_ADDRESS_SANITIZER=YES \
     CLANG_UNDEFINED_BEHAVIOR_SANITIZER=YES \
     CLANG_ENABLE_CODE_COVERAGE=YES
   ```

2. **Locate the binary**
   ```bash
   BINARY=$(find /tmp/DerivedData -name "XNU Image Fuzzer" -type f -perm +111 \
     ! -path "*/Contents/Resources/*" | head -1)
   ```

3. **Run under sanitizers**
   ```bash
   FUZZ_OUTPUT_DIR=/tmp/fuzzed-output \
   ASAN_OPTIONS="detect_leaks=0:halt_on_error=0:print_stats=1" \
   UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
   LLVM_PROFILE_FILE="/tmp/profraw/fuzzer-%m_%p.profraw" \
     timeout 120 "$BINARY"
   ```

4. **Validate output**
   - Check each file with `sips -g format -g pixelWidth -g pixelHeight`
   - Verify non-zero file sizes
   - Check magic bytes with `file -b`
   - Run `validate_fuzzed_images.py` for steganography analysis (requires Pillow)

5. **Generate coverage report**
   ```bash
   xcrun llvm-profdata merge -sparse /tmp/profraw/*.profraw -o merged.profdata
   xcrun llvm-cov report "$BINARY" -instr-profile=merged.profdata
   ```

## Expected Output
- 72+ fuzzed images in various formats (PNG, JPEG, GIF, BMP, TIFF, HEIF)
- All 12 bitmap context types exercised
- Zero ASAN/UBSAN findings (or documented known issues)
- Coverage report showing function/line percentages

## Failure Detection
- Exit code != 0 → crash or assertion
- `ERROR: AddressSanitizer` in stderr → memory safety bug (CRITICAL)
- `runtime error:` in stderr → undefined behavior
- Zero images produced → app didn't run long enough or crashed early
- Empty files → image creation failed silently
