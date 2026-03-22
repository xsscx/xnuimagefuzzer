---
name: CI Workflow Maintenance
description: Guidelines for creating and maintaining secure GitHub Actions workflows
---

# CI Workflow Maintenance

Standards for all GitHub Actions workflows in this repository.

## Security Requirements (Non-Negotiable)

### Action Pinning
Always use full SHA pins, never version tags:
```yaml
# ✅ CORRECT
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

# ❌ WRONG
uses: actions/checkout@v4
```

### Current Pinned SHAs
| Action | SHA | Version |
|--------|-----|---------|
| checkout | `11bd71901bbe5b1630ceea73d27597364c9af683` | v4.2.2 |
| upload-artifact | `ea165f8d65b6e75b540449e92b4886f43607fa02` | v4.6.2 |
| cache | `5a3ec84eff668545956fd18022155c47e93e2684` | v4.2.3 |
| download-artifact | `d3f86a106a0bac45b974a628896c90dbdf5c8093` | v4.3.0 |

### Permissions
```yaml
permissions:
  contents: read  # Least privilege — only escalate when needed
```

### Shell Hardening
```yaml
env:
  BASH_ENV: /dev/null
defaults:
  run:
    shell: bash --noprofile --norc {0}
```

### Credential Isolation
```yaml
- uses: actions/checkout@...
  with:
    persist-credentials: false

- name: Credential hardening
  run: |
    git config --global credential.helper ""
    unset GITHUB_TOKEN || true
```

### Input Sanitization
NEVER use user-controllable inputs directly in `run:` blocks:
```yaml
# ❌ DANGEROUS — command injection
run: echo "Branch: ${{ github.event.pull_request.head.ref }}"

# ✅ SAFE — pass through env
env:
  BRANCH: ${{ github.event.pull_request.head.ref }}
run: |
  SAFE_BRANCH=$(echo "$BRANCH" | LC_ALL=C sed 's/[^A-Za-z0-9._/-]//g')
  echo "Branch: $SAFE_BRANCH"
```

### Concurrency Control
```yaml
concurrency:
  group: workflow-name-${{ github.ref }}
  cancel-in-progress: true
```

## Build Configuration

## Corpus Validation

For workflow steps that generate fuzz outputs, prefer explicit category assertions over a single total-file threshold.

- If the simulator smoke workflow passes `FUZZ_ICC_DIR=/System/Library/ColorSync/Profiles`, preserve the current 287-file top-level corpus contract unless the generator intentionally changes.
- Validate regular outputs structurally with `file -b`; only `corrupted_*` files may be intentionally malformed.
- Do not treat `TOTAL >= N` alone as sufficient validation for this repository.

### Mac Catalyst Build
```yaml
- name: Build
  run: |
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

### DerivedData Caching
```yaml
- uses: actions/cache@5a3ec84eff668545956fd18022155c47e93e2684
  with:
    path: /tmp/DerivedData
    key: derived-${{ runner.os }}-${{ hashFiles('**/*.m', '**/*.h', '**/*.swift') }}
    restore-keys: derived-${{ runner.os }}-
```

## Git Identity for CI Commits
```yaml
- name: Configure git
  run: |
    git config user.name 'github-actions[bot]'
    git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
```

## Coverage Pipeline

> **⚠️ `CLANG_ENABLE_CODE_COVERAGE=YES` does NOT work for Mac Catalyst.**
> Xcode does not inject `-fprofile-instr-generate` for Mac Catalyst builds.
> ASAN and coverage must be separate jobs.

### ASAN+UBSAN job (xcodebuild)
```yaml
# Sanitizer testing only — NO coverage flags
CLANG_ADDRESS_SANITIZER=YES
CLANG_UNDEFINED_BEHAVIOR_SANITIZER=YES
# Do NOT add CLANG_ENABLE_CODE_COVERAGE=YES
```

### Coverage job (native clang)
```bash
# 1. Build with native clang (not xcodebuild)
.github/scripts/build-native.sh

# Invoke it with bash or via its shebang, never with sh.

# Or manually:
clang -arch arm64 -target arm64-apple-ios17.2-macabi \
  -isysroot $(xcrun --show-sdk-path) \
  -fsanitize=address,undefined \
  -fprofile-instr-generate -fcoverage-mapping \
  ...

# 2. Run (produces profraw)
LLVM_PROFILE_FILE="/tmp/profraw/%m.profraw" /tmp/binary

# 3. Merge
xcrun llvm-profdata merge -sparse /tmp/profraw/*.profraw -o merged.profdata

# 4. Report
xcrun llvm-cov report "$BINARY" -instr-profile=merged.profdata
xcrun llvm-cov show "$BINARY" -instr-profile=merged.profdata -format=html -output-dir=html/
xcrun llvm-cov export "$BINARY" -instr-profile=merged.profdata -format=lcov > coverage.lcov
```

## macOS CI Pitfalls

### SIGPIPE Prevention
NEVER pipe macOS/BSD tools (`ls`, `file`, `find`, `xcodebuild`, `xcrun`)
through `| head`. Use `| sed -n` or `| cut -c` instead:
```bash
# ❌ Crashes on macOS — ls: stdout: Undefined error: 0
ls -la /tmp/output/ | head -20

# ✅ Safe — sed reads all input
ls -la /tmp/output/ | sed -n '1,20p'

# ❌ Crashes with NSFileHandleOperationException
xcodebuild -version | head -1

# ✅ Safe
xcodebuild -version | sed -n '1p'
```

### LLVM Profile Symbols
Use `dlsym()` to resolve `__llvm_profile_write_file` and
`__llvm_profile_set_filename` at runtime. Do NOT use `__attribute__((weak))`
extern declarations — they cause linker failures on iOS Simulator builds
without `-fprofile-instr-generate`.

### Mac Catalyst App Launch
- Must use `open "$APP_BUNDLE"` — bare binary exits immediately
- `open` blocks until app exits — use `open ... & ; disown $!`
- Pass env vars via `open --env KEY=VALUE` (macOS 13+)
- Mac Catalyst ignores `osascript quit` — use `pgrep`/`kill`
- SIGTERM does NOT trigger `atexit()` — send SIGINT first
