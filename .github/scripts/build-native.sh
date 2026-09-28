#!/bin/bash
###############################################################
#
# build-native.sh - Native arm64 clang build for xnuimagefuzzer
#
# Compiles the Mac Catalyst binary directly with clang, using
# explicit -fprofile-instr-generate -fcoverage-mapping flags.
#
# Xcode's CLANG_ENABLE_CODE_COVERAGE=YES does NOT inject
# coverage flags for Mac Catalyst builds. This script does.
#
# Usage:
#   .github/scripts/build-native.sh              # build + run + coverage
#   .github/scripts/build-native.sh --build-only  # build only
#   .github/scripts/build-native.sh --run-only    # run pre-built binary
#
# Output:
#   /tmp/native-build/xnuimagefuzzer              # instrumented helper binary
#   /tmp/fuzzed-output/                           # verified QA corpus and source images
#   /tmp/profraw/                                 # coverage profraw
#   /tmp/coverage-report/                         # llvm-cov reports
#
# Copyright (c) 2021-2026 David H Hoyt LLC - GPL-3.0-or-later
###############################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SRC_DIR="$REPO_ROOT/XNU Image Fuzzer"

BUILD_DIR="${BUILD_DIR:-/tmp/native-build}"
PROFRAW_DIR="${PROFRAW_DIR:-/tmp/profraw}"
FUZZ_DIR="${FUZZ_DIR:-/tmp/fuzzed-output}"
COV_DIR="${COV_DIR:-/tmp/coverage-report}"
BINARY="$BUILD_DIR/xnuimagefuzzer"

MODE="${1:-}"
DO_RUN_STATUS=0

# Helpers
banner() { echo ""; echo "========================================"; echo "  $1"; echo "========================================"; }

die() { echo "ERROR: $1" >&2; exit 1; }

# Build
do_build() {
  banner "Building xnuimagefuzzer (arm64 Mac Catalyst, ASAN+UBSAN+Coverage)"

  SDKROOT="$(xcrun --show-sdk-path)"
  [ -d "$SDKROOT" ] || die "SDK not found. Install Xcode."

  mkdir -p "$BUILD_DIR"

  SOURCES=(
    "$SRC_DIR/xnuimagefuzzer.m"
    "$SRC_DIR/AppDelegate.m"
    "$SRC_DIR/SceneDelegate.m"
    "$SRC_DIR/ViewController.m"
  )
  for s in "${SOURCES[@]}"; do
    [ -f "$s" ] || die "Source not found: $s"
  done

  clang -arch arm64 \
    -target arm64-apple-ios17.2-macabi \
    -isysroot "$SDKROOT" \
    -iframework "$SDKROOT/System/iOSSupport/System/Library/Frameworks" \
    -fobjc-arc \
    -g -O0 \
    -fno-omit-frame-pointer \
    -fsanitize=address,undefined \
    -fprofile-instr-generate -fcoverage-mapping \
    -framework Foundation \
    -framework UIKit \
    -framework CoreGraphics \
    -framework ImageIO \
    -framework UniformTypeIdentifiers \
    -I"$SRC_DIR" \
    "${SOURCES[@]}" \
    -o "$BINARY"

  echo "Binary: $BINARY ($(du -h "$BINARY" | cut -f1))"

  # Verify instrumentation
  COV_SYMS=$(nm "$BINARY" 2>/dev/null | grep -c "llvm_profile" || echo 0)
  ASAN_SYMS=$(nm "$BINARY" 2>/dev/null | grep -c "asan" || echo 0)
  echo "   Coverage symbols: $COV_SYMS"
  echo "   ASAN symbols:     $ASAN_SYMS"
  [ "$COV_SYMS" -gt 0 ] || die "No coverage symbols - build broken"
  [ "$ASAN_SYMS" -gt 0 ] || die "No ASAN symbols - build broken"
}

# Run
do_run() {
  banner "Running deterministic QA generation under sanitizers"

  [ -x "$BINARY" ] || die "Binary not found at $BINARY - run with --build-only first"
  mkdir -p "$PROFRAW_DIR" "$FUZZ_DIR"
  : > /tmp/fuzzer-run.log
  find "$PROFRAW_DIR" -mindepth 1 -delete 2>/dev/null || true
  find "$FUZZ_DIR" -mindepth 1 -delete 2>/dev/null || true

  SOURCE_DIR="$FUZZ_DIR/sources"
  CORPUS_DIR="$FUZZ_DIR/corpus"
  mkdir -p "$SOURCE_DIR"

  set +e
  XNU_IMAGE_OUTPUT_DIR="$SOURCE_DIR" \
  LLVM_PROFILE_FILE="$PROFRAW_DIR/clean-%m_%p.profraw" \
  ASAN_OPTIONS="detect_leaks=0:halt_on_error=1" \
  UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1" \
    "$BINARY" --clean 2>&1 | tee /tmp/fuzzer-run.log
  CLEAN_EXIT=${PIPESTATUS[0]}
  set -e

  SAMPLE=$(find "$SOURCE_DIR" -maxdepth 1 -type f -name 'clean-*.png' | sort | sed -n '1p')
  [ -n "$SAMPLE" ] || die "Clean generation produced no PNG input"
  FUZZED_SAMPLE="$SOURCE_DIR/fuzzed-chart-sample.png"
  set +e
  LLVM_PROFILE_FILE="$PROFRAW_DIR/pixel-%m_%p.profraw" \
  ASAN_OPTIONS="detect_leaks=0:halt_on_error=1" \
  UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1" \
    "$BINARY" --fuzz-image "$SAMPLE" --output "$FUZZED_SAMPLE" --seed 1 \
    2>&1 | tee -a /tmp/fuzzer-run.log
  PIXEL_EXIT=${PIPESTATUS[0]}
  set -e

  python3 "$REPO_ROOT/contrib/scripts/build_qa_corpus.py" \
    --input "$SOURCE_DIR" \
    --output "$CORPUS_DIR" \
    --icc-mode both
  python3 "$REPO_ROOT/contrib/scripts/validate_qa_corpus.py" "$CORPUS_DIR"

  if [ "${RUN_LEGACY_FUZZ:-0}" = "1" ]; then
    LEGACY_DIR="$FUZZ_DIR/legacy-explicit"
    mkdir -p "$LEGACY_DIR"
    FUZZ_OUTPUT_DIR="$LEGACY_DIR" \
    FUZZ_ICC_DIR="/System/Library/ColorSync/Profiles" \
    LLVM_PROFILE_FILE="$PROFRAW_DIR/legacy-%m_%p.profraw" \
      "$BINARY" --legacy-default-fuzz 2>&1 | tee -a /tmp/fuzzer-run.log
  fi

  ASAN_HITS=$(grep -c "ERROR: AddressSanitizer" /tmp/fuzzer-run.log 2>/dev/null || true)
  UBSAN_HITS=$(grep -c "runtime error:" /tmp/fuzzer-run.log 2>/dev/null || true)
  PROFRAW_COUNT=$(find "$PROFRAW_DIR" -name '*.profraw' -type f | wc -l | tr -d ' ')
  [ "${ASAN_HITS:-0}" -eq 0 ] || die "AddressSanitizer findings detected"
  [ "${UBSAN_HITS:-0}" -eq 0 ] || die "UndefinedBehaviorSanitizer findings detected"
  [ "$CLEAN_EXIT" -eq 0 ] || die "Clean generation failed"
  [ "$PIXEL_EXIT" -eq 0 ] || die "Deterministic pixel fuzzing failed"
  [ "$PROFRAW_COUNT" -gt 0 ] || die "No profraw files - coverage collection failed"
  echo "Run complete: clean=$CLEAN_EXIT pixel=$PIXEL_EXIT profraw=$PROFRAW_COUNT"
}

# Coverage
do_coverage() {
  banner "Generating coverage report"

  mkdir -p "$COV_DIR"

  PROFRAW_COUNT=$(find "$PROFRAW_DIR" -name "*.profraw" -type f 2>/dev/null | wc -l | tr -d ' ')
  if [ "$PROFRAW_COUNT" -eq 0 ]; then
    echo "WARN: No profraw files - skipping coverage"
    echo "No profraw files collected." > "$COV_DIR/summary.txt"
    return
  fi

  xcrun llvm-profdata merge -sparse \
    "$PROFRAW_DIR"/*.profraw \
    -o "$COV_DIR/merged.profdata"

  echo "--- Coverage Summary ---"
  xcrun llvm-cov report \
    "$BINARY" \
    -instr-profile="$COV_DIR/merged.profdata" \
    2>&1 | tee "$COV_DIR/summary.txt"

  # HTML report (non-fatal)
  xcrun llvm-cov show \
    "$BINARY" \
    -instr-profile="$COV_DIR/merged.profdata" \
    -format=html \
    -output-dir="$COV_DIR/html" \
    2>/dev/null || echo "(HTML report skipped)"

  # LCOV export (non-fatal)
  xcrun llvm-cov export \
    "$BINARY" \
    -instr-profile="$COV_DIR/merged.profdata" \
    -format=lcov \
    > "$COV_DIR/coverage.lcov" \
    2>/dev/null || echo "(LCOV export skipped)"

  echo ""
  echo "Coverage report: $COV_DIR/summary.txt"
  echo "   HTML report:     $COV_DIR/html/index.html"
  echo "   LCOV:            $COV_DIR/coverage.lcov"
}

# Main
case "${MODE}" in
  --build-only) do_build ;;
  --run-only)   do_run; do_coverage; [ "$DO_RUN_STATUS" -eq 0 ] || die "One or more fuzzing phases failed" ;;
  *)            do_build; do_run; do_coverage; [ "$DO_RUN_STATUS" -eq 0 ] || die "One or more fuzzing phases failed" ;;
esac
