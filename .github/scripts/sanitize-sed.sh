#!/usr/bin/env bash
# shellcheck shell=bash
#------------------------------------------------------------------------------
# sanitize-sed.sh — Input sanitization for GitHub Actions workflows
#
# Ported from iccDEV/.github/scripts/sanitize-sed.sh for xnuimagefuzzer.
# Provides functions to sanitize user-controllable inputs in CI/CD pipelines,
# preventing injection attacks via branch names, PR titles, commit messages,
# and other GitHub event context variables.
#
# Copyright (c) 2024-2026 David H Hoyt. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-or-later
#------------------------------------------------------------------------------

set -euo pipefail

# --- Configuration ---
SANITIZE_LINE_MAXLEN=${SANITIZE_LINE_MAXLEN:-1000}
SANITIZE_PRINT_MAXLEN=${SANITIZE_PRINT_MAXLEN:-8000}

# --- Low-level helpers -------------------------------------------------------

# escape_html STRING
# Replace &, <, >, " and ' with HTML entities.
escape_html() {
  local s="$1"
  s=$(printf '%s' "$s" | \
    sed 's/&/\&amp;/g' | \
    sed 's/</\&lt;/g' | \
    sed 's/>/\&gt;/g' | \
    sed 's/"/\&quot;/g' | \
    sed "s/'/\&#39;/g")
  printf '%s' "$s"
}

# _strip_ctrl_keep_newlines STRING
# Remove control characters except newline (0x0A).
_strip_ctrl_keep_newlines() {
  local s="$1"
  s="${s//$'\r'/}"
  s="$(printf '%s' "$s" | tr -d '\000-\011\013\014\016-\037\177')"
  printf '%s' "$s"
}

# _strip_ctrl_remove_newlines STRING
# Remove all control characters including newlines.
_strip_ctrl_remove_newlines() {
  local s="$1"
  s="${s//$'\r'/}"
  s="${s//$'\n'/ }"
  s="$(printf '%s' "$s" | tr -d '\000-\011\013\014\016-\037\177')"
  printf '%s' "$s"
}

# _strip_unicode_control STRING
# Remove Unicode bidi overrides, zero-width chars, interlinear annotations.
# Uses perl for portable Unicode handling (sed hex ranges are non-portable).
_strip_unicode_control() {
  local s="$1"
  if command -v perl >/dev/null 2>&1; then
    # Bidi overrides: U+202A-202E, U+2066-2069
    # Zero-width: U+200B-200F, U+2060, U+FEFF
    # Interlinear annotations: U+FFF9-FFFB
    s="$(printf '%s' "$s" | perl -CS -pe \
      's/[\x{202A}-\x{202E}\x{2066}-\x{2069}\x{200B}-\x{200F}\x{2060}\x{FEFF}\x{FFF9}-\x{FFFB}]//g')"
  else
    # Fallback: strip all non-printable, non-space characters
    s="$(printf '%s' "$s" | LC_ALL=C tr -cd '[:print:][:space:]')"
  fi
  printf '%s' "$s"
}

# _trim_whitespace STRING
_trim_whitespace() {
  local s="$1"
  printf '%s' "$s" | awk '{$1=$1; print}'
}

# _truncate STRING MAXLEN
_truncate() {
  local s="$1"
  local maxlen="$2"
  local len=${#s}
  if (( len <= maxlen )); then
    printf '%s' "$s"
    return 0
  fi
  local head="${s:0:((maxlen-3))}"
  printf '%s' "${head}..."
}

# --- Public sanitizers -------------------------------------------------------

# sanitize_line STRING
# Single-line safe string: strip control chars, trim, HTML-escape, truncate.
sanitize_line() {
  local input="$1"
  local s
  s="$(_strip_ctrl_remove_newlines "$input")"
  s="$(_strip_unicode_control "$s")"
  s="$(_trim_whitespace "$s")"
  s="$(escape_html "$s")"
  s="$(_truncate "$s" "$SANITIZE_LINE_MAXLEN")"
  printf '%s' "$s"
}

# sanitize_print STRING
# Multi-line safe string for step summaries.
sanitize_print() {
  local input="$1"
  local s
  s="$(_strip_ctrl_keep_newlines "$input")"
  s="$(_strip_unicode_control "$s")"
  s="$(printf '%s' "$s" | sed -E ':a;N;$!ba;s/\n{4,}/\n\n\n/g')"
  s="$(escape_html "$s")"
  s="$(_truncate "$s" "$SANITIZE_PRINT_MAXLEN")"
  printf '%s' "$s"
}

# sanitize_ref STRING
# Safe branch/tag/ref name for filenames and concurrency groups.
sanitize_ref() {
  local input="$1"
  local s
  s="$(printf '%s' "$input" | tr -d '\000')"
  s="${s//$'\r'/}"
  s="${s//$'\n'/}"
  # LC_ALL=C ensures ASCII-only matching (prevents overlong UTF-8 bypass)
  s="$(printf '%s' "$s" | LC_ALL=C sed -E 's#[^A-Za-z0-9._/-]#-#g')"
  s="$(printf '%s' "$s" | sed -E 's/-+/-/g')"
  # remove path traversal sequences
  s="$(printf '%s' "$s" | sed -E 's#\.\.##g')"
  # collapse multiple slashes
  s="$(printf '%s' "$s" | sed -E 's#/+#/#g')"
  # trim leading/trailing hyphens, dots, or slashes
  s="$(printf '%s' "$s" | sed -E 's/^[-_./]+//; s/[-_.]+$//')"
  if [[ -z "$s" ]]; then
    s="ref-unknown"
  fi
  printf '%s' "$s"
}

# sanitize_filename STRING
# Filename-safe string (no slashes, no traversal).
sanitize_filename() {
  local input="$1"
  local s
  s="$(sanitize_ref "$input")"
  s="${s//\//_}"
  printf '%s' "$s"
}

# safe_echo_for_summary STRING...
safe_echo_for_summary() {
  local joined="$*"
  sanitize_print "$joined"
  printf '\n'
}

# sanitizer_version
sanitizer_version() {
  printf 'xnuimagefuzzer-sanitizer-v1\n'
}
