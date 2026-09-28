# Architecture

The supported pipeline is staged:

1. The native helper emits deterministic clean PNG, JPEG, and TIFF files.
2. It optionally performs seeded pixel fuzzing and valid encoding.
3. build_qa_corpus.py creates no-ICC and exact-ICC pairs by direct container
   editing; optional malformed cases use named deterministic strategies.
4. Optional sips round trips exercise macOS processing.
5. validate_qa_corpus.py independently verifies bytes, hashes, outcomes, and
   evidence.

icc_container.py owns PNG iCCP, JPEG APP2 ICC_PROFILE, and classic TIFF tag
34675 handling. Do not attach ICC payloads through undocumented UIImage
properties.

Historic random, batch, chained, and pipeline implementations remain only
behind --legacy-* switches and are outside the verified corpus contract.
