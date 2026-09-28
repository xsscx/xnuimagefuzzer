# Build and run

Recommended end-to-end command:

    .github/scripts/generate-qa-images.sh /tmp/xnuimagefuzzer-qa both both --seed 1

Focused native commands:

    .github/scripts/build-native.sh --build-only
    XNU_IMAGE_OUTPUT_DIR=/tmp/clean /tmp/native-build/xnuimagefuzzer --clean
    /tmp/native-build/xnuimagefuzzer --fuzz-image input.png \
      --output output.png --seed 1

For malformed ICC behavior through macOS:

    .github/scripts/generate-qa-images.sh /tmp/qa-roundtrip both both \
      --include-mutated --apple-roundtrip --seed 7

Always run the validator before consuming or publishing a corpus. Set
RUN_LEGACY_FUZZ=1 only for explicit legacy sanitizer coverage; its output is
separate and is not validated corpus data.
