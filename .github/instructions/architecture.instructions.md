# Architecture — XNU Image Fuzzer

## Entry Modes

`main()` supports five practical entry paths:

- no arguments: `performAllImagePermutations()`
- `<imagePath> <permutation>`: single-file legacy mode
- `--chain <imagePath> [--iterations N]`
- `--input-dir <directory> [--iterations N]`
- `--pipeline <directory> [--iterations N]`

At startup, `main()` also sets a group of CoreGraphics/ImageIO debug environment variables and, when present, hands `LLVM_PROFILE_FILE` to the runtime via `dlsym("__llvm_profile_set_filename")`.

## Default No-Argument Flow

```text
main()
  -> performAllImagePermutations()
     -> iterate 19 seed specs
        -> generateFuzzedImageData()
        -> write seed_perm##_###.png
        -> applyPostEncodingCorruption()
        -> write corrupted_perm##_###.png
        -> optionally embed a real ICC profile
        -> write seed_icc_perm##_<profile>_###.png
        -> processImage(image, permutation)
           -> dispatch to one of 17 createBitmapContext* functions
           -> saveFuzzedImage()
              -> write fixed-name fuzzed_image_<context>.<ext>
              -> for PNG/TIFF, also call saveFuzzedImageWithICCVariants()
        -> measureOutput()
        -> write *.metrics.json
  -> write fuzz_metrics_summary.csv
```

Important nuance: the default mode does not run all 17 permutations for every generated seed. It runs one selected permutation per seed spec.

## Batch, Chain, And Pipeline Modes

### Chained fuzzing

`performChainedFuzzing()`:

- loads one input file
- reprocesses it for `N` iterations
- cycles permutation numbers with `(iter % MAX_PERMUTATION) + 1`
- writes provenance-style outputs such as `input_perm06_inj03_sRGB2014_001.png`
- embeds a round-robin ICC profile when available
- keeps the regular chain output decodable
- writes any intentional final post-encoding corruption as a separate `corrupted_<input>_perm##_inj##_<icc>_###.<ext>` file
- writes per-output metrics JSON plus `fuzz_metrics_summary.csv`

### Batch fuzzing

`performBatchFuzzing()` scans a directory for supported images and calls chained fuzzing for each file.

### Pipeline fuzzing

`performPipelineFuzzing()` creates these subdirectories inside the output directory:

- `pipeline-clean`
- `pipeline-formats`
- `pipeline-fuzzed`
- `pipeline-icc`
- `pipeline-combo`
- `pipeline-chained`
- `pipeline-profiles`

Its phases are:

1. save the clean baseline and metrics
2. encode the clean image into every format returned by `encodeImageMultiFormat()`
3. fuzz the image through a curated subset of permutations and re-encode those results
4. embed clean ICC profiles into PNG and TIFF variants
5. combine mutated ICC profiles with fuzzed image data and post-encoding corruption
6. optionally start chained fuzzing from the clean baseline when `iterations > 1`

Current pipeline fuzz subset:

- `1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15`

That means the pipeline currently skips alpha-only, Display P3, and BT.2020 outputs in its fuzz phase.

## 17 Bitmap-Context Permutations

| # | Function | Notes |
|---|----------|-------|
| 1 | `createBitmapContextStandardRGB` | RGBA premultiplied last |
| 2 | `createBitmapContextPremultipliedFirstAlpha` | ARGB premultiplied first |
| 3 | `createBitmapContextNonPremultipliedAlpha` | straight alpha |
| 4 | `createBitmapContext16BitDepth` | 16-bit component handling |
| 5 | `createBitmapContextGrayscale` | grayscale path |
| 6 | `createBitmapContextHDRFloatComponents` | 32-bit float HDR |
| 7 | `createBitmapContextAlphaOnly` | alpha-only buffer |
| 8 | `createBitmapContext1BitMonochrome` | packed 1-bit path |
| 9 | `createBitmapContextBigEndian` | big-endian byte order |
| 10 | `createBitmapContextLittleEndian` | little-endian byte order |
| 11 | `createBitmapContext8BitInvertedColors` | inverted 8-bit path |
| 12 | `createBitmapContext32BitFloat4Component` | 128-bit float RGBA |
| 13 | `createBitmapContextCMYK` | CMYK with fallback handling |
| 14 | `createBitmapContextHDRFloat16` | half-float edge cases |
| 15 | `createBitmapContextIndexedColor` | indexed/palette path |
| 16 | `createBitmapContextDisplayP3` | wide-gamut Display P3 |
| 17 | `createBitmapContextBT2020` | wide-gamut BT.2020 |

## Post-Encoding Corruption

`applyPostEncodingCorruption()` mutates already-encoded image bytes to stress parser recovery logic. The current implementation uses six PNG-structure-oriented strategies such as dimension corruption, truncation, CRC damage, chunk mangling, extra-data injection, and chunk reordering.

## Output Naming

There are three naming schemes in active use.

### Fixed context outputs

Bitmap-context saves use fixed filenames:

```text
fuzzed_image_<context>.<ext>
fuzzed_image_<context>_no_icc.<ext>
fuzzed_image_<context>_icc_<profile>.<ext>
fuzzed_image_<context>_icc_mutated.<ext>
fuzzed_image_<context>_icc_mismatch.<ext>
```

These names are not collision-free. Repeated default runs overwrite earlier context outputs in the same directory.

### Provenance helper outputs

`provenanceFileName()` returns:

```text
<input>_perm##_inj##_<icc-or-none>_###.<ext>
```

Example:

```text
input_perm06_inj03_sRGB2014_001.png
```

This scheme is used for chained outputs and for default-mode seed and corrupted files.

Final chained corruption is published under the same provenance scheme with a `corrupted_` prefix on the input name, so intentionally malformed chain artifacts are no longer mixed into the normal `fuzzed_image_*` namespace.

### Pipeline outputs

Pipeline mode uses phase-specific names such as:

- `<source>_clean.<ext>`
- `<source>.<format-key>`
- `<source>_perm12.<format-key>`
- `<source>_icc-<profile>.<fmt>`
- `<source>_combo-mut2_<profile>.<fmt>`
- `<source>_chain-input.<ext>`

## Multi-Format Encoder

`encodeImageMultiFormat()` can emit up to 38 keys per source image, depending on platform UTType availability.

Core keys:

- `png`
- `jpg`
- `jpeg`
- `tiff`
- `gif`
- `bmp`
- `ico`

Additional encodes:

- `tiff-lzw.tiff`
- `thumb.tiff`
- `heic`
- `heif`
- `webp`
- `jp2`
- `exr`
- `dng`
- `pbm`
- `tga`
- `astc`
- `ktx`
- `pdf`
- `icns`
- `tiff-packbits.tiff`
- `tiff-jpeg.tiff`
- `tiff-deflate.tiff`
- `jpeg-exif.jpg`
- `heic-hq.heic`
- `heic-lq.heic`

ICC and color-space variants:

- `tiff-no-icc.tiff`
- `png-no-icc.png`
- `tiff-icc-mismatch.tiff`
- `png-icc-mismatch.png`
- `tiff-cs0.tiff` through `tiff-cs6.tiff`

## Metrics Artifacts

Every recorded metrics entry includes:

- `output_path`
- `output_size`
- `output_sha256`
- `output_entropy`
- `timestamp`

When an input file exists, the metrics also include:

- `input_size`
- `input_sha256`
- `input_entropy`
- `size_delta`

Metrics are written both as per-file JSON sidecars and as a run-level `fuzz_metrics_summary.csv`.

## Workflow Corpus Contract

The simulator `build-and-test` workflow now runs default mode with `FUZZ_ICC_DIR=/System/Library/ColorSync/Profiles` and validates an exact top-level corpus shape:

- 19 `seed_perm*.png`
- 19 `corrupted_perm*.png`
- 19 `seed_icc_perm*.png`
- 62 base `fuzzed_image_*` files
- 32 `_no_icc` files
- 32 `_icc_mismatch` files
- 32 real `_icc_<profile>` files
- 32 `_icc_mutated` files
- 1 `1Bit_Monochrome.png`
- 38 metrics JSON sidecars
- 1 `fuzz_metrics_summary.csv` with 39 lines

Regular outputs are expected to stay structurally decodable. Only `corrupted_*` outputs are allowed to be intentionally malformed.

## Other Behavior Worth Remembering

- `ViewController` is a lightweight gallery and only loads PNG/JPEG outputs from Documents.
- `saveFuzzedImageWithICCVariants()` is triggered automatically for PNG and TIFF saves.
- `loadICCProfilePaths()` scans `FUZZ_ICC_DIR` for `.icc` and `.icm` files and uses them round-robin.
