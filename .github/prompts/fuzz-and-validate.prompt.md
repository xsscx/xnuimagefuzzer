---
name: Fuzz and Validate Images
description: Build the fuzzer, run it locally, and inspect the generated artifacts
---

# Fuzz and Validate Images

Build XNU Image Fuzzer, run it locally, and inspect the generated files, crash signals, and coverage artifacts.

## Steps

### Option A: Native clang helper (recommended)

```bash
.github/scripts/build-native.sh
```

Run the helper as an executable or with `bash`. Do not invoke it with `sh`; it is a Bash script.

This produces:

- `/tmp/native-build/xnuimagefuzzer`
- `/tmp/fuzzed-output/`
- `/tmp/profraw/`
- `/tmp/coverage-report/`

### Option B: Xcode / Mac Catalyst

1. Build:

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
     CLANG_UNDEFINED_BEHAVIOR_SANITIZER=YES
   ```

2. Locate the app bundle:

   ```bash
   APP=$(find /tmp/DerivedData -name "XNU Image Fuzzer.app" -type d | sed -n '1p')
   ```

3. Launch it:

   ```bash
   open --env FUZZ_OUTPUT_DIR=/tmp/fuzzed-output "$APP"
   ```

4. Wait for files to appear, then terminate the app if needed.

### Optional run modes

```bash
/tmp/native-build/xnuimagefuzzer /path/to/image.png 12
/tmp/native-build/xnuimagefuzzer --chain /path/to/image.png --iterations 3
/tmp/native-build/xnuimagefuzzer --input-dir /path/to/images --iterations 2
/tmp/native-build/xnuimagefuzzer --pipeline /path/to/images --iterations 2
```

### Validate the output

- Check file inventory with `find /tmp/fuzzed-output -type f | sed -n '1,40p'`
- Inspect types with `file -b`
- Inspect image metadata with `sips -g format -g pixelWidth -g pixelHeight`
- Run `./fuzz-apps.sh /tmp/fuzzed-output --timeout 15` to exercise macOS parser consumers
- Run `python3 fuzz-gallery.py /tmp/fuzzed-output --port 8088` for Safari/WebKit decode coverage
- Run `python3 contrib/scripts/extract-icc-seeds.py --input /tmp/fuzzed-output --output /tmp/extracted-seeds` if you need ICC/TIFF corpus material

If you want to use `read-magic-numbers.py`, update its hard-coded directory before running it.

### Coverage

Coverage is generated automatically by `.github/scripts/build-native.sh`.

Manual commands:

```bash
xcrun llvm-profdata merge -sparse /tmp/profraw/*.profraw -o /tmp/coverage-report/merged.profdata
xcrun llvm-cov report /tmp/native-build/xnuimagefuzzer \
  -instr-profile=/tmp/coverage-report/merged.profdata
```

## Expected Output

- In default no-argument mode with `FUZZ_ICC_DIR=/System/Library/ColorSync/Profiles`, expect this exact top-level shape:
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
- `*.metrics.json` sidecars and `fuzz_metrics_summary.csv` should be present.
- Option A should also produce `profraw` files and coverage reports.
- Chained mode should keep the regular chain output decodable and write any intentional final corruption as a separate `corrupted_*` provenance file.
- Only `corrupted_*` files are allowed to be structurally invalid or show up as generic `data`.

## Failure Detection

- non-zero exit code -> crash, assertion, or launch failure
- `ERROR: AddressSanitizer` -> memory safety bug
- `runtime error:` -> undefined behavior
- zero output files -> app did not launch correctly or did not receive `FUZZ_OUTPUT_DIR`
- empty files -> encoding or save failure
- regular `seed_*`, `seed_icc_*`, `fuzzed_image_*`, or `1Bit_*` files identified by `file` as generic `data` -> corpus regression
