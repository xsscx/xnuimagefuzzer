# Repository agent instructions

## Scope

This repository produces deterministic image and ICC-profile QA data for Apple
ImageIO and ColorSync. Keep clean generation, pixel fuzzing, ICC mutation, and
macOS processing separate and observable.

## Required contract

- No arguments and --clean generate deterministic, decodable, ICC-free images.
- Pixel fuzzing is explicit through --fuzz-image and uses a recorded seed.
- Valid ICC insertion uses direct container editing and extracts byte-exact.
- Malformed ICC cases are opt-in and never enter clean or valid lanes.
- macOS drop, rewrite, injection, substitution, and rejection are logged with
  requested and observed evidence.
- Legacy random and multipass modes never qualify as verified artifacts.

## Validation

Run:

    python3 -m unittest contrib/scripts/test_icc_container.py
    bash -n .github/scripts/*.sh
    .github/scripts/generate-qa-images.sh /tmp/xnuimagefuzzer-qa both both --seed 1
    python3 contrib/scripts/validate_qa_corpus.py /tmp/xnuimagefuzzer-qa

For ICC processing changes, also exercise --include-mutated
--apple-roundtrip and report every outcome count.

Use 4-space indentation in Python and Objective-C, with tabs only in Makefiles.
Generated text files must be ASCII. Do not commit generated corpora, coverage,
crash artifacts, system profiles, or temporary build products. Preserve stable
sorting and JSON serialization. Update all consumers when a schema or command
changes. Do not create, reopen, push, or merge a pull request without explicit
user authorization.
