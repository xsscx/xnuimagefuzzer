# Troubleshooting — XNU Image Fuzzer

## Build Errors

### Build fails with `-Werror=macro-redefined`
Duplicate `#define` in xnuimagefuzzer.m. Remove the duplicate.

### Build fails with `-Wenum-conversion`
Cast `CGImageAlphaInfo` to `CGBitmapInfo`:
```objc
CGBitmapInfo bitmapInfo = (CGBitmapInfo)kCGImageAlphaPremultipliedLast;
```

## Mac Catalyst

### App exits immediately
Running the bare Mach-O binary directly doesn't work for Mac Catalyst UIKit apps.
Must use `open "$APP_BUNDLE"` to properly initialize UIKit.

### Running with environment variables
`launchctl setenv` is unreliable. Use `open --env` (macOS 13+):
```bash
open --env FUZZ_OUTPUT_DIR=/tmp/fuzzed-output \
     --env LLVM_PROFILE_FILE=/tmp/profraw/%m_%p.profraw \
     "$APP_BUNDLE"
```

## Coverage

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

## CI Issues

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

Build with the Xcode command from build-and-run.instructions.md, then:
```bash
APP=$(find /tmp/DerivedData -name "XNU Image Fuzzer.app" -type d | sed -n '1p')
open --env FUZZ_OUTPUT_DIR=/tmp/fuzzed-output "$APP"
```

### CoreGraphics debug environment variables
Key CG debug vars for local fuzzing (Apple-private, surfaces internal errors):
```bash
export CG_VERBOSE=1 CG_INFO=1 CG_CONTEXT_SHOW_BACKTRACE_ON_ERROR=1
export CGBITMAP_CONTEXT_LOG=1 CGBITMAP_CONTEXT_LOG_ERRORS=1
export CG_IMAGE_SHOW_MALLOC=1 CG_IMAGE_LOG_FORCE=1 CG_COLOR_CONVERSION_VERBOSE=1
export IMAGEIO_DEBUG=1
```

When running via `open --env`, pass each var individually:
```bash
open --env CG_VERBOSE=1 --env CGBITMAP_CONTEXT_LOG=1 \
     --env CG_CONTEXT_SHOW_BACKTRACE_ON_ERROR=1 \
     --env FUZZ_OUTPUT_DIR=/tmp/fuzzed-output "$APP"
```

### macOS memory debugging
```bash
# Malloc guards (independent of ASAN)
export MallocGuardEdges=1 MallocScribble=1 MallocErrorAbort=1
export MallocStackLogging=1  # Use with: malloc_history <pid> <addr>

# Zombie objects (use-after-release detection)
export NSZombieEnabled=YES

# Guard Malloc (extreme — 100x slower, catches single-byte overruns)
# Native clang builds only (SIP blocks DYLD_INSERT for system binaries)
DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib /tmp/xnuimagefuzzer
```

### ASAN + UBSAN tuning
```bash
export ASAN_OPTIONS="detect_leaks=0:halt_on_error=0:print_stats=1:detect_stack_use_after_return=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:silence_unsigned_overflow=1"
```

### Crash report collection
```bash
ls ~/Library/Logs/DiagnosticReports/           # macOS crash reports
lldb -- /tmp/xnuimagefuzzer                    # interactive debugging
```

## iOS Simulator — Benign Log Messages

These messages appear in Xcode console during Simulator runs. They are all harmless
system framework noise — not from app code. No action needed.

| Message | Source | Why It Appears |
|---------|--------|---------------|
| `CLIENT: Failure to determine if this machine is in the process of shutting down, err=1` | configd/powerd | Simulator process lacks Mach port entitlement |
| `LSPrefs: could not find untranslocated node ... Error Code=1 "Operation not permitted"` | Launch Services | Gatekeeper translocation check fails in Simulator sandbox |
| `dyld: Symbol not found: _OBJC_CLASS_$_AVPlayerView` | Xcode View Debugger | `libViewDebuggerSupport.dylib` references AVKit class unavailable in iOS runtime |
| `CGImageBlockCreate: invalid block size` | ImageIO | Expected for edge-case dimensions (1×1, 4096×1) |
| `deny(1) file-read-data /...` (duetexpertd) | Spotlight | Spotlight indexing tries to read fuzzed images; sandbox blocks it |
