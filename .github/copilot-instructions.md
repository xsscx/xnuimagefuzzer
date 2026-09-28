# XNU Image Fuzzer repository instructions

## Product contract

Keep clean image creation, pixel mutation, ICC mutation, and macOS processing as
separate stages. The no-argument native mode must generate deterministic clean
images. Fuzzing must require an explicit mode and seed.

Never infer ICC presence from a filename or framework metadata. Extract binary
ICC bytes from PNG iCCP, JPEG APP2 ICC_PROFILE chunks, or TIFF tag 34675 and
compare SHA-256 values. A valid-ICC case succeeds only when extracted bytes
exactly match the requested profile.

Classify macOS results as preserved exact, dropped, rewritten, substituted with
a known system profile, injected without input, or rejected. Retain requested
and observed blobs for non-exact results.

## Primary workflow

    .github/scripts/generate-qa-images.sh /tmp/xnuimagefuzzer-qa both both --seed 1
    python3 contrib/scripts/validate_qa_corpus.py /tmp/xnuimagefuzzer-qa
    python3 -m unittest contrib/scripts/test_icc_container.py

Use --include-mutated --apple-roundtrip only for malformed ICC handling. Legacy
native modes are explicit and never qualify as verified corpus output.

Preserve deterministic ordering and manifest serialization. Fail closed on
unsupported containers, invalid profiles, hash mismatch, missing evidence, or
unmanaged output directories. Keep generated files ASCII. Do not commit output,
coverage, crash artifacts, or system profiles. Update tests, workflows, docs,
prompts, and the QA skill when a contract changes.
