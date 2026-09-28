---
name: xnuimagefuzzer-qa
description: Generate, validate, inspect, or export deterministic xnuimagefuzzer image and ICC QA corpora, including macOS profile substitution evidence.
---

# XNU Image Fuzzer QA

Use this workflow for corpus generation, ICC integration changes, artifact
inspection, and downstream seed export.

## Generate

    .github/scripts/generate-qa-images.sh /tmp/xnuimagefuzzer-qa both both --seed 1

Add --include-mutated --apple-roundtrip when testing malformed ICC handling or
macOS substitution. Never enable malformed cases implicitly.

## Verify

    python3 -m unittest contrib/scripts/test_icc_container.py
    python3 contrib/scripts/validate_qa_corpus.py /tmp/xnuimagefuzzer-qa

Read manifest.json for outcome totals. For any non-exact requested profile,
inspect evidence for the requested blob, observed blob when present, and
processor log when rejected. Do not infer ICC state from names or metadata.

## Export

    python3 contrib/scripts/extract-icc-seeds.py \
      --input /tmp/xnuimagefuzzer-qa --output /tmp/verified-seeds

The exporter accepts only a recognized manifest, verifies artifact and ICC
hashes, and exports only exact profiles. Treat failure as a corpus integrity
failure; do not bypass it.

When changing formats, fields, outcomes, or commands, update unit tests,
builder, validator, exporter, workflows, README, prompts, instructions, and
AGENTS.md together. Preserve ASCII output and deterministic ordering.
