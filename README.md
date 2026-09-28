# XNU Image Fuzzer

XNU Image Fuzzer produces deterministic image and ICC-profile quality-assurance
corpora for Apple ImageIO and ColorSync testing. Clean image generation is the
default. Every mutation path is explicit, seeded, and recorded in a manifest.

## Quick start

Run the complete local path on macOS:

    .github/scripts/generate-qa-images.sh /tmp/xnuimagefuzzer-qa both both --seed 1

This builds the native helper, generates clean PNG, JPEG, and TIFF charts,
creates seeded pixel-fuzzed counterparts, adds exact ICC and no-ICC variants,
and validates all hashes and embedded profiles.

To exercise malformed ICC blobs and macOS processing:

    .github/scripts/generate-qa-images.sh /tmp/qa-roundtrip both both \
      --include-mutated --apple-roundtrip --seed 7

Revalidate or export trusted downstream seeds:

    python3 contrib/scripts/validate_qa_corpus.py /tmp/xnuimagefuzzer-qa
    python3 contrib/scripts/extract-icc-seeds.py \
      --input /tmp/xnuimagefuzzer-qa --output /tmp/verified-seeds

## Native modes

No arguments and --clean generate deterministic, ICC-free images. Use
--fuzz-image INPUT --output OUTPUT --seed N for one deterministic pixel
mutation and a valid output container. ICC insertion and mutation are handled
afterward by build_qa_corpus.py, which edits PNG iCCP, JPEG APP2, or TIFF tag
34675 directly and then extracts the bytes again.

The historic random generator and chained pipelines remain only under explicit
--legacy-default-fuzz, --legacy-chain, --legacy-input-dir, and
--legacy-pipeline switches. Their artifacts are outside the verified contract.

## ICC outcomes

The manifest distinguishes absent_expected, preserved_exact, dropped,
rewritten, substituted_system_profile, injected_without_input, and rejected.
Requested and observed blobs are retained under evidence when a requested
profile is not preserved exactly. A filename never establishes ICC presence.

## Validation

    python3 -m unittest contrib/scripts/test_icc_container.py
    bash -n .github/scripts/*.sh
    .github/scripts/build-native.sh

Generated corpora, coverage files, and crash artifacts are not source-controlled.
See AGENTS.md for repository rules.
