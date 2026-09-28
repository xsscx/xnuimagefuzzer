---
name: Generate and Validate QA Corpus
description: Build deterministic clean and fuzzed image and ICC pairs
---

# Generate and validate

Run:

    .github/scripts/generate-qa-images.sh /tmp/xnuimagefuzzer-qa both both --seed 1
    python3 contrib/scripts/validate_qa_corpus.py /tmp/xnuimagefuzzer-qa

For malformed ICC behavior through macOS, add --include-mutated and
--apple-roundtrip. Report counts for every outcome and preserve evidence for
dropped, rewritten, substituted, or rejected cases.

Do not call an artifact clean or ICC-bearing based on its name. Cite the
validator result, manifest entry, extracted ICC SHA-256, and requested SHA-256.
Do not use a legacy native mode as release or QA corpus input.
