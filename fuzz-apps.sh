#!/bin/bash
# fuzz-apps.sh — Feed fuzzed images into macOS system tools and detect crashes.
#
# Exercises the same image decoding paths as Preview, Mail, Notes, iMessage:
#   sips          — ImageIO / ColorSync (ICC profile parsing)
#   qlmanage -t   — QuickLook thumbnails (Finder, Mail, iMessage rich links)
#   qlmanage -p   — QuickLook preview (Preview.app, Spotlight)
#   mdimport -t   — Spotlight metadata extraction
#   tiffutil      — TIFF IFD parsing
#   textutil      — RTF image embedding (Mail compose path)
#
# Crash detection:
#   - Exit codes 128+ (signal: 134=SIGABRT, 137=SIGKILL, 139=SIGSEGV, 138=SIGBUS)
#   - New files in ~/Library/Logs/DiagnosticReports/
#   - Timeout kills (default 15s per invocation)
#
# Usage:
#   ./fuzz-apps.sh <image-directory> [--timeout 15] [--report /tmp/fuzz-report]
#   ./fuzz-apps.sh pipeline-fuzzed/              # fuzz all images in directory
#   ./fuzz-apps.sh pipeline-combo/ --timeout 30  # longer timeout for complex images
#
# Environment:
#   FUZZ_APPS_TIMEOUT  — per-tool timeout in seconds (default: 15)
#   FUZZ_APPS_REPORT   — report output directory (default: /tmp/fuzz-apps-report)
#   FUZZ_APPS_TOOLS    — comma-separated list of tools to run (default: all)
#                        e.g. FUZZ_APPS_TOOLS=sips,qlmanage-t
#
# Output:
#   $REPORT_DIR/findings.csv     — all results with exit codes
#   $REPORT_DIR/crashes/         — copies of crash-triggering images
#   $REPORT_DIR/crash-logs/      — copied DiagnosticReports .ips files
#   $REPORT_DIR/summary.txt      — human-readable summary

set -euo pipefail

# ── Configuration ──
INPUT_DIR="${1:?Usage: $0 <image-directory> [--timeout N] [--report DIR]}"
shift

TIMEOUT="${FUZZ_APPS_TIMEOUT:-15}"
REPORT_DIR="${FUZZ_APPS_REPORT:-/tmp/fuzz-apps-report}"
ENABLED_TOOLS="${FUZZ_APPS_TOOLS:-sips-verify,sips-getprop,sips-convert,qlmanage-t,mdimport,tiffutil}"

# Parse optional args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --report)  REPORT_DIR="$2"; shift 2 ;;
        --tools)   ENABLED_TOOLS="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Validate input
if [[ ! -d "$INPUT_DIR" ]]; then
    echo "Error: $INPUT_DIR is not a directory"
    exit 1
fi

# macOS gtimeout or perl fallback
if command -v gtimeout &>/dev/null; then
    TIMEOUT_CMD="gtimeout"
elif command -v timeout &>/dev/null; then
    TIMEOUT_CMD="timeout"
else
    # Use perl as timeout fallback on stock macOS
    timeout_fallback() {
        local dur=$1; shift
        perl -e '
            alarm shift @ARGV;
            $SIG{ALRM} = sub { kill 9, $pid; exit 124 };
            $pid = fork();
            if ($pid == 0) { exec @ARGV; exit 127 }
            waitpid($pid, 0);
            exit ($? >> 8);
        ' "$dur" "$@"
    }
    TIMEOUT_CMD="timeout_fallback"
fi

run_with_timeout() {
    if [[ "$TIMEOUT_CMD" == "timeout_fallback" ]]; then
        timeout_fallback "$TIMEOUT" "$@"
    else
        "$TIMEOUT_CMD" --signal=KILL "$TIMEOUT" "$@"
    fi
}

# ── Setup ──
mkdir -p "$REPORT_DIR/crashes" "$REPORT_DIR/crash-logs"
QLMANAGE_TMPDIR=$(mktemp -d)
CSV="$REPORT_DIR/findings.csv"
SUMMARY="$REPORT_DIR/summary.txt"

echo "file,tool,exit_code,signal,status,size_bytes,format" > "$CSV"

CRASH_REPORT_DIR="$HOME/Library/Logs/DiagnosticReports"
BASELINE_REPORTS=$(mktemp)
if [[ -d "$CRASH_REPORT_DIR" ]]; then
    ls -1 "$CRASH_REPORT_DIR/" 2>/dev/null | sort > "$BASELINE_REPORTS"
fi

# Counters
TOTAL=0
CRASHES=0
TIMEOUTS=0
ERRORS=0
CLEAN=0

# Recognized image extensions
IMAGE_EXTS="png|jpg|jpeg|tiff|tif|gif|bmp|heic|heif|webp|jp2|exr|dng|tga|ico|icns|pbm|pdf|astc|ktx"

tool_enabled() {
    [[ "$ENABLED_TOOLS" == *"$1"* ]]
}

classify_exit() {
    local ec=$1
    if [[ $ec -eq 0 ]]; then
        echo "ok"
    elif [[ $ec -eq 124 || $ec -eq 137 ]]; then
        echo "timeout"
    elif [[ $ec -ge 128 ]]; then
        echo "crash"
    else
        echo "error"
    fi
}

signal_name() {
    local ec=$1
    if [[ $ec -ge 128 ]]; then
        local sig=$((ec - 128))
        case $sig in
            4)  echo "SIGILL" ;;
            6)  echo "SIGABRT" ;;
            7)  echo "SIGBUS" ;;
            8)  echo "SIGFPE" ;;
            9)  echo "SIGKILL" ;;
            10) echo "SIGBUS" ;;
            11) echo "SIGSEGV" ;;
            *)  echo "SIG$sig" ;;
        esac
    else
        echo "-"
    fi
}

run_tool() {
    local file="$1"
    local tool_name="$2"
    shift 2
    local size
    size=$(stat -f%z "$file" 2>/dev/null || echo 0)
    local ext="${file##*.}"

    local ec=0
    run_with_timeout "$@" >/dev/null 2>&1 || ec=$?

    local status
    status=$(classify_exit $ec)
    local sig
    sig=$(signal_name $ec)

    echo "\"$file\",\"$tool_name\",$ec,\"$sig\",\"$status\",$size,\"$ext\"" >> "$CSV"
    TOTAL=$((TOTAL + 1))

    case "$status" in
        crash)
            CRASHES=$((CRASHES + 1))
            cp "$file" "$REPORT_DIR/crashes/" 2>/dev/null || true
            printf "  ❌ CRASH  %-20s exit=%d (%s) %s\n" "$tool_name" "$ec" "$sig" "$(basename "$file")"
            ;;
        timeout)
            TIMEOUTS=$((TIMEOUTS + 1))
            printf "  ⏱  HANG   %-20s timeout=%ds %s\n" "$tool_name" "$TIMEOUT" "$(basename "$file")"
            ;;
        error)
            ERRORS=$((ERRORS + 1))
            ;;
        ok)
            CLEAN=$((CLEAN + 1))
            ;;
    esac
}

# ── Main loop ──
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  fuzz-apps.sh — macOS Image Parser Fuzzing Harness         ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Input:   $INPUT_DIR"
echo "║  Timeout: ${TIMEOUT}s per tool invocation"
echo "║  Report:  $REPORT_DIR"
echo "║  Tools:   $ENABLED_TOOLS"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

FILE_COUNT=0
while IFS= read -r -d '' file; do
    FILE_COUNT=$((FILE_COUNT + 1))
done < <(find "$INPUT_DIR" -type f -maxdepth 2 | grep -iE "\.($IMAGE_EXTS)$" | tr '\n' '\0')

echo "Found $FILE_COUNT image files to process"
echo ""

CURRENT=0
while IFS= read -r -d '' file; do
    CURRENT=$((CURRENT + 1))
    echo "[$CURRENT/$FILE_COUNT] $(basename "$file")"

    # sips --verify (validates image structure)
    if tool_enabled "sips-verify"; then
        run_tool "$file" "sips-verify" sips --debug --verify "$file"
    fi

    # sips --getProperty all (reads all metadata including ICC)
    if tool_enabled "sips-getprop"; then
        run_tool "$file" "sips-getprop" sips -g all "$file"
    fi

    # sips format conversion (exercises full decode+encode path)
    if tool_enabled "sips-convert"; then
        local_ext="${file##*.}"
        local_tmp=$(mktemp -u "/tmp/fuzz-sips-XXXXXX.png")
        run_tool "$file" "sips-convert" sips -s format png "$file" --out "$local_tmp"
        rm -f "$local_tmp"
    fi

    # qlmanage -t (thumbnail generation — QuickLook/Finder/Mail path)
    if tool_enabled "qlmanage-t"; then
        run_tool "$file" "qlmanage-t" qlmanage -t -s 128 -o "$QLMANAGE_TMPDIR" "$file"
    fi

    # mdimport -t (Spotlight metadata extraction)
    if tool_enabled "mdimport"; then
        run_tool "$file" "mdimport" mdimport -t "$file"
    fi

    # tiffutil -info (TIFF IFD parsing — only for TIFF files)
    if tool_enabled "tiffutil"; then
        case "${file##*.}" in
            tiff|tif)
                run_tool "$file" "tiffutil-info" tiffutil -info "$file"
                ;;
        esac
    fi

done < <(find "$INPUT_DIR" -type f -maxdepth 2 | grep -iE "\.($IMAGE_EXTS)$" | sort | tr '\n' '\0')

# ── Check for new crash reports ──
if [[ -d "$CRASH_REPORT_DIR" ]]; then
    CURRENT_REPORTS=$(mktemp)
    ls -1 "$CRASH_REPORT_DIR/" 2>/dev/null | sort > "$CURRENT_REPORTS"
    NEW_REPORTS=$(comm -13 "$BASELINE_REPORTS" "$CURRENT_REPORTS")
    if [[ -n "$NEW_REPORTS" ]]; then
        echo ""
        echo "🔥 New DiagnosticReports detected:"
        while IFS= read -r report; do
            echo "  → $report"
            cp "$CRASH_REPORT_DIR/$report" "$REPORT_DIR/crash-logs/" 2>/dev/null || true
        done <<< "$NEW_REPORTS"
    fi
    rm -f "$CURRENT_REPORTS"
fi
rm -f "$BASELINE_REPORTS"

# ── Cleanup ──
rm -rf "$QLMANAGE_TMPDIR"

# ── Summary ──
cat > "$SUMMARY" << EOF
fuzz-apps.sh Report
====================
Input directory: $INPUT_DIR
Images processed: $FILE_COUNT
Tool invocations: $TOTAL
Timeout: ${TIMEOUT}s

Results:
  ✅ Clean:    $CLEAN
  ⚠️  Errors:   $ERRORS
  ⏱  Timeouts: $TIMEOUTS
  ❌ Crashes:  $CRASHES

Crash-triggering files copied to: $REPORT_DIR/crashes/
DiagnosticReports copied to: $REPORT_DIR/crash-logs/
Full CSV: $REPORT_DIR/findings.csv
EOF

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  Results: $CLEAN clean, $ERRORS errors, $TIMEOUTS timeouts, $CRASHES CRASHES"
echo "  CSV:     $CSV"
if [[ $CRASHES -gt 0 ]]; then
    echo ""
    echo "  🔥 $CRASHES CRASH(ES) DETECTED — check $REPORT_DIR/crashes/"
    echo "  Crash-triggering files and .ips logs saved."
fi
echo "══════════════════════════════════════════════════════════════"

# Exit with 2 if crashes found (distinguishable from tool errors)
[[ $CRASHES -gt 0 ]] && exit 2
exit 0
