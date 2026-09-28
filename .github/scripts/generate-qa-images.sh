#!/bin/bash
set -euo pipefail

repo_dir=$(cd "$(dirname "$0")/../.." && pwd)
output_dir=${1:-"$repo_dir/generated-images"}
icc_mode=${2:-both}
pixel_mode=${3:-both}
shift_count=3

case "$icc_mode" in
    none|with|both) ;;
    *)
        echo "usage: $0 [output-directory] [none|with|both] [clean|fuzzed|both] [--include-mutated] [--apple-roundtrip] [--seed N]" >&2
        exit 2
        ;;
esac
case "$pixel_mode" in
    clean|fuzzed|both) ;;
    *)
        echo "invalid pixel mode: $pixel_mode" >&2
        exit 2
        ;;
esac

include_mutated=0
apple_roundtrip=0
seed=1
while [ "$shift_count" -lt "$#" ]; do
    shift_count=$((shift_count + 1))
    value=${!shift_count}
    case "$value" in
        --include-mutated) include_mutated=1 ;;
        --apple-roundtrip) apple_roundtrip=1 ;;
        --seed)
            shift_count=$((shift_count + 1))
            [ "$shift_count" -le "$#" ] || { echo "--seed requires a value" >&2; exit 2; }
            seed=${!shift_count}
            ;;
        *) echo "unknown option: $value" >&2; exit 2 ;;
    esac
done
if [ "$apple_roundtrip" -eq 1 ] && [ "$include_mutated" -ne 1 ]; then
    echo "--apple-roundtrip requires --include-mutated" >&2
    exit 2
fi

build_dir=${BUILD_DIR:-/tmp/native-build}
binary="$build_dir/xnuimagefuzzer"
source_dir=$(mktemp -d /tmp/xnuimagefuzzer-sources.XXXXXX)
cleanup() {
    find "$source_dir" -mindepth 1 -delete 2>/dev/null || true
    rmdir "$source_dir" 2>/dev/null || true
}
trap cleanup EXIT

BUILD_DIR="$build_dir" "$repo_dir/.github/scripts/build-native.sh" --build-only
XNU_IMAGE_OUTPUT_DIR="$source_dir" "$binary" --clean

if [ "$pixel_mode" = "fuzzed" ] || [ "$pixel_mode" = "both" ]; then
    while IFS= read -r source; do
        extension=${source##*.}
        base=$(basename "$source")
        base=${base%.*}
        "$binary" --fuzz-image "$source" \
            --output "$source_dir/fuzzed-${base#clean-}.$extension" \
            --seed "$seed"
    done < <(find "$source_dir" -maxdepth 1 -type f -name 'clean-*' | sort)
fi
if [ "$pixel_mode" = "fuzzed" ]; then
    find "$source_dir" -maxdepth 1 -type f -name 'clean-*' -delete
fi

builder_args=(
    --input "$source_dir"
    --output "$output_dir"
    --icc-mode "$icc_mode"
    --seed "$seed"
)
if [ "$include_mutated" -eq 1 ]; then
    builder_args+=(--include-mutated)
fi
if [ "$apple_roundtrip" -eq 1 ]; then
    builder_args+=(--apple-roundtrip)
fi
python3 "$repo_dir/contrib/scripts/build_qa_corpus.py" "${builder_args[@]}"
python3 "$repo_dir/contrib/scripts/validate_qa_corpus.py" "$output_dir"
