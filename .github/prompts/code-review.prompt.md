---
name: Code Review - XNU Image Fuzzer
description: Review deterministic image and ICC QA behavior
---

# Review contract

Review source, scripts, tests, docs, and workflows as one producer-consumer
chain. Confirm that clean generation is deterministic and ICC-free, image
fuzzing is explicit and seeded, valid profiles round-trip byte-for-byte, and
malformed profiles never enter valid lanes.

Check PNG CRC and iCCP handling, JPEG APP2 sequence/count handling, TIFF bounds
and tag 34675 handling, path safety, manifest completeness, evidence retention,
deterministic ordering, and fail-closed validation. Treat silent ICC drop,
rewrite, or system-profile substitution as a reported outcome. Treat unverified
artifacts labeled exact or clean as a blocker.
