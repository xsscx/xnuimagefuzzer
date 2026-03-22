# Troubleshooting — XNU Image Fuzzer

## Build Errors

### Build fails with `-Werror=macro-redefined`

There is a duplicate `#define` in `xnuimagefuzzer.m`. Remove the duplicate rather than weakening warning policy.

### Build fails with `-Wenum-conversion`

Cast `CGImageAlphaInfo` to `CGBitmapInfo`:

```objc
CGBitmapInfo bitmapInfo = (CGBitmapInfo)kCGImageAlphaPremultipliedLast;
```

## Mac Catalyst Launch Behavior

### Xcode-built app exits immediately when the Mach-O is run directly

For Mac Catalyst output built by Xcode, launch the `.app` bundle with `open`, not the inner executable:

```bash
APP=$(find /tmp/DerivedData -name "XNU Image Fuzzer.app" -type d | sed -n '1p')
open --env FUZZ_OUTPUT_DIR=/tmp/fuzzed-output "$APP"
```

### Native clang helper binary

The binary produced by `.github/scripts/build-native.sh` is intended to run directly:

```bash
FUZZ_OUTPUT_DIR=/tmp/fuzzed-output /tmp/native-build/xnuimagefuzzer
```

### Passing environment variables

`launchctl setenv` is inconsistent for local Mac Catalyst work. Prefer `open --env` when launching the Xcode-built app bundle:

```bash
open --env FUZZ_OUTPUT_DIR=/tmp/fuzzed-output \
     --env LLVM_PROFILE_FILE=/tmp/profraw/%m_%p.profraw \
     "$APP"
```

## Coverage

### Coverage report is empty

The project resolves `__llvm_profile_write_file` and `__llvm_profile_set_filename` with `dlsym()`. That avoids linker failures on non-instrumented builds and on iOS Simulator configurations without coverage flags.

If profraw is still missing:

1. Verify `LLVM_PROFILE_FILE` reaches the process.
2. Ensure the output directory exists and is writable.
3. Let the process exit cleanly.
4. Use the native clang helper path for real coverage collection.

Do not replace the `dlsym()` pattern with `__attribute__((weak)) extern`.

## CI Issues

### SIGPIPE crash in CI

Never pipe Apple or BSD tools through `| head`. Use `sed -n` or similar full-reader commands instead.

- `| head -N` -> `| sed -n '1,Np'`
- `| head -1` -> `| sed -n '1p'`
- `| head -2 | tail -1` -> `| sed -n '2p'`

### Preserving logs while showing a short tail

Use `tee`:

```bash
xcodebuild ... | tee /tmp/xcodebuild.log | tail -5
```

### No images generated in CI

Check these first:

- `FUZZ_OUTPUT_DIR` was actually passed into the launched process
- the app had enough time to finish writing files
- the current run mode matched expectations
- `FUZZ_ICC_DIR` actually reached the process when CI parity counts were expected
- `1Bit_Monochrome.png` was present; if it is missing, suspect a monochrome encoding regression

### Regular outputs show up as generic `data`

Treat this as a real regression unless the file is intentionally named `corrupted_*`.

- Regular `seed_*`, `seed_icc_*`, `fuzzed_image_*`, and `1Bit_*` files should remain structurally decodable.
- In chained mode, intentional final corruption now belongs in separate `corrupted_*` provenance files, not in the normal `fuzzed_image_*` namespace.

## Local Development

### CoreGraphics debug environment variables

Useful debug variables:

```bash
export CG_VERBOSE=1 CG_INFO=1 CG_CONTEXT_SHOW_BACKTRACE_ON_ERROR=1
export CGBITMAP_CONTEXT_LOG=1 CGBITMAP_CONTEXT_LOG_ERRORS=1
export CG_IMAGE_SHOW_MALLOC=1 CG_IMAGE_LOG_FORCE=1 CG_COLOR_CONVERSION_VERBOSE=1
export IMAGEIO_DEBUG=1
```

For `open --env`, pass them individually:

```bash
open --env CG_VERBOSE=1 \
     --env CGBITMAP_CONTEXT_LOG=1 \
     --env CG_CONTEXT_SHOW_BACKTRACE_ON_ERROR=1 \
     --env FUZZ_OUTPUT_DIR=/tmp/fuzzed-output \
     "$APP"
```

### macOS memory debugging

```bash
export MallocGuardEdges=1 MallocScribble=1 MallocErrorAbort=1
export MallocStackLogging=1
export NSZombieEnabled=YES
```

Guard Malloc is practical only for native clang helper runs:

```bash
DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib /tmp/native-build/xnuimagefuzzer
```

### ASAN + UBSAN tuning

```bash
export ASAN_OPTIONS="detect_leaks=0:halt_on_error=0:print_stats=1:detect_stack_use_after_return=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:silence_unsigned_overflow=1"
```

### Crash report collection

```bash
ls ~/Library/Logs/DiagnosticReports/
lldb -- /tmp/native-build/xnuimagefuzzer
```

## Benign Simulator Noise

Some iOS Simulator console messages come from system services rather than this app. Treat them as framework noise unless they line up with a real failure in the run output or crash logs.
