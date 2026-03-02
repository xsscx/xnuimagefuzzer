#!/bin/bash
###############################################################
#
# build-native.sh — Native arm64 clang build for xnuimagefuzzer
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
#   /tmp/native-build/xnuimagefuzzer              # instrumented binary
#   /tmp/fuzzed-output/                           # 88 fuzzed images
#   /tmp/profraw/                                 # coverage profraw
#   /tmp/coverage-report/                         # llvm-cov reports
#
# Copyright (c) 2021-2026 David H Hoyt LLC — GPL-3.0-or-later
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

# ── Helpers ──────────────────────────────────────────────────
banner() { echo ""; echo "════════════════════════════════════════"; echo "  $1"; echo "════════════════════════════════════════"; }

die() { echo "❌ $1" >&2; exit 1; }

# ── Build ────────────────────────────────────────────────────
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

  echo "✅ Binary: $BINARY ($(du -h "$BINARY" | cut -f1))"

  # Verify instrumentation
  COV_SYMS=$(nm "$BINARY" 2>/dev/null | grep -c "llvm_profile" || echo 0)
  ASAN_SYMS=$(nm "$BINARY" 2>/dev/null | grep -c "asan" || echo 0)
  echo "   Coverage symbols: $COV_SYMS"
  echo "   ASAN symbols:     $ASAN_SYMS"
  [ "$COV_SYMS" -gt 0 ] || die "No coverage symbols — build broken"
  [ "$ASAN_SYMS" -gt 0 ] || die "No ASAN symbols — build broken"
}

# ── Run ──────────────────────────────────────────────────────
do_run() {
  banner "Running xnuimagefuzzer under sanitizers with coverage"

  [ -x "$BINARY" ] || die "Binary not found at $BINARY — run with --build-only first"

  mkdir -p "$PROFRAW_DIR" "$FUZZ_DIR"
  # Clean stale data
  rm -f "$PROFRAW_DIR"/*.profraw "$FUZZ_DIR"/*

  FUZZ_OUTPUT_DIR="$FUZZ_DIR" \
  LLVM_PROFILE_FILE="$PROFRAW_DIR/fuzzer-%m_%p.profraw" \
  ASAN_OPTIONS="detect_leaks=0:halt_on_error=0" \
  UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
    "$BINARY" 2>&1 | tee /tmp/fuzzer-run.log

  RUN_EXIT=${PIPESTATUS[0]}

  FILE_COUNT=$(find "$FUZZ_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')
  PROFRAW_COUNT=$(find "$PROFRAW_DIR" -name "*.profraw" -type f 2>/dev/null | wc -l | tr -d ' ')

  echo ""
  echo "Exit code:    $RUN_EXIT"
  echo "Fuzzed files: $FILE_COUNT"
  echo "Profraw:      $PROFRAW_COUNT"

  # Check for ASAN/UBSAN findings in output
  ASAN_HITS=$(grep -c "ERROR: AddressSanitizer" /tmp/fuzzer-run.log 2>/dev/null || true)
  ASAN_HITS="${ASAN_HITS:-0}"
  UBSAN_HITS=$(grep -c "runtime error:" /tmp/fuzzer-run.log 2>/dev/null || true)
  UBSAN_HITS="${UBSAN_HITS:-0}"
  if [ "$ASAN_HITS" -gt 0 ]; then echo "⚠️  ASAN findings: $ASAN_HITS"; fi
  if [ "$UBSAN_HITS" -gt 0 ]; then echo "⚠️  UBSAN findings: $UBSAN_HITS"; fi

  [ "$FILE_COUNT" -ge 80 ] || die "Expected ≥80 fuzzed files, got $FILE_COUNT"
  [ "$PROFRAW_COUNT" -gt 0 ] || die "No profraw files — coverage collection failed"
  echo "✅ Run complete"
}

# ── Coverage ─────────────────────────────────────────────────
do_coverage() {
  banner "Generating coverage report"

  mkdir -p "$COV_DIR"

  PROFRAW_COUNT=$(find "$PROFRAW_DIR" -name "*.profraw" -type f 2>/dev/null | wc -l | tr -d ' ')
  if [ "$PROFRAW_COUNT" -eq 0 ]; then
    echo "⚠️  No profraw files — skipping coverage"
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
  echo "✅ Coverage report: $COV_DIR/summary.txt"
  echo "   HTML report:     $COV_DIR/html/index.html"
  echo "   LCOV:            $COV_DIR/coverage.lcov"
}

# ── Main ─────────────────────────────────────────────────────
case "${MODE}" in
  --build-only) do_build ;;
  --run-only)   do_run; do_coverage ;;
  *)            do_build; do_run; do_coverage ;;
esac
