# Native generator

The Objective-C helper has two supported QA operations:

- No arguments or --clean generates deterministic, decodable PNG, JPEG, and
  TIFF charts with no embedded binary ICC profile.
- --fuzz-image INPUT --output OUTPUT --seed N makes one deterministic pixel
  mutation and encodes a valid output container.

Set XNU_IMAGE_OUTPUT_DIR to select the clean output directory. The older
FUZZ_OUTPUT_DIR variable is accepted only as a compatibility fallback.

ICC profiles are intentionally not attached through UIImage metadata. Use
contrib/scripts/build_qa_corpus.py or .github/scripts/generate-qa-images.sh.
They insert and verify binary ICC payloads directly in PNG iCCP, JPEG APP2, and
TIFF tag 34675 containers.

Historic random and multipass modes are quarantined behind switches beginning
with --legacy-. They exist for coverage archaeology and do not produce verified
QA artifacts.
