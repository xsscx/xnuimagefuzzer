# Architecture — XNU Image Fuzzer

## Core Fuzzing Pipeline
```
main() → performAllImagePermutations()
  → for each of 17 seed specs (8×8 to 4096×4096):
      createBitmapContext*() → fill with fuzz data
      → CGBitmapContextCreateImage()
      → saveFuzzedImage(seed) → FUZZ_OUTPUT_DIR/
        └→ saveFuzzedImageWithICCVariants() (TIFF/PNG only)
           ├→ encodeImageWithICCProfile()     — real ICC from FUZZ_ICC_DIR
           ├→ encodeImageStrippingColorSpace() — DeviceRGB, no ICC metadata
           ├→ encodeImageWithMismatchedProfile() — CMYK/Gray/Lab on RGB
           └→ mutateICCProfile() + encode      — corrupted ICC profile
      → applyPostEncodingCorruption(seed) → 6 PNG chunk-level mutations
      → saveFuzzedImage(corrupted) → FUZZ_OUTPUT_DIR/
      → processImage(seed, permutation) → save as PNG/JPEG/GIF/TIFF
  → __llvm_profile_write_file() (if instrumented)
```

## Post-Encoding Corruption (Structure-Aware)
6 PNG chunk mutation strategies applied after encoding:
1. IHDR dimension corruption (width/height = 0 or 0xFFFF)
2. IDAT stream truncation (50% of data removed)
3. CRC invalidation on random chunks
4. Chunk type mangling (swap chunk names)
5. Extra data injection between chunks
6. Chunk reordering (move IDAT before IHDR)

## 15 Bitmap Context Types
| # | Function | Format |
|---|----------|--------|
| 1 | createBitmapContextStandardRGB | RGBA premultiplied last |
| 2 | createBitmapContextPremultipliedFirstAlpha | ARGB premultiplied first |
| 3 | createBitmapContextNonPremultipliedAlpha | RGBA straight alpha |
| 4 | createBitmapContext16BitDepth | 16-bit per component |
| 5 | createBitmapContextGrayscale | 8-bit grayscale |
| 6 | createBitmapContextHDRFloatComponents | 32-bit float HDR |
| 7 | createBitmapContextAlphaOnly | Alpha channel only |
| 8 | createBitmapContext1BitMonochrome | 1-bit black/white |
| 9 | createBitmapContextBigEndian | Big-endian 32-bit |
| 10 | createBitmapContextLittleEndian | Little-endian 32-bit |
| 11 | createBitmapContext8BitInvertedColors | Inverted 8-bit |
| 12 | createBitmapContext32BitFloat4Component | RGBA 128-bit float |
| 13 | createBitmapContextCMYK | CMYK with RGB fallback |
| 14 | createBitmapContextHDRFloat16 | IEEE 754 half-precision edge cases |
| 15 | createBitmapContextIndexedColor | 5 palette variants with corruption |

## Output Formats
Images are saved as: PNG, JPEG, GIF, BMP, TIFF, HEIF
using `CGImageDestinationCreateWithURL` with the appropriate UTType.

### Filename Conventions

**xnuimagefuzzer outputs** use `xif-` prefix with SHA-256 hash suffix for collision-free naming:
```
xif-{source}-perm{N}[-{variant}]-{hash6}.{ext}
```
- `variant`: `icc_{name}`, `no_icc`, `mismatch`, `mutated`
- `hash6`: first 6 hex chars of SHA-256 of file content

**iOS Image Generator outputs** use `xig-` prefix:
```
xig-{context}-{WxH}[-icc_{profile}]-{hash6}.{ext}
```
- `context`: short name (stdrgb, premul, gray, 1bit, p3, srgb, adobergb, etc.)

Staged to `fuzz/xnuimagefuzzer/{format}/` and `fuzz/xnuimagegenerator/{format}/`.

## ICC Variant Generation

Every `saveFuzzedImage()` call for TIFF and PNG outputs automatically triggers
`saveFuzzedImageWithICCVariants()`, which produces up to 4 additional files per image:

| Variant | Function | Description |
|---------|----------|-------------|
| Real ICC | `encodeImageWithICCProfile()` | Re-renders through ICC color space via `CGColorSpaceCreateWithICCData()` |
| Stripped | `encodeImageStrippingColorSpace()` | Re-renders through DeviceRGB — no ICC metadata |
| Mismatched | `encodeImageWithMismatchedProfile()` | CMYK/Gray/Lab/truncated profile on RGB image |
| Mutated | `mutateICCProfile()` + encode | 6 corruption strategies on real ICC data |

**Mismatch strategies** (cycled per call):
1. CMYK output profile on RGB image (`prtr` + `CMYK` color space)
2. Gray display profile on RGB image (`mntr` + `GRAY` color space)
3. Abstract Lab profile on RGB image (`abst` + `Lab` + `Lab` PCS)
4. Truncated profile (header says 1024 bytes, only 132 present)

**API notes:**
- `kCGImagePropertyICCProfile` does NOT exist in Apple SDKs — do not use it
- Use `CGColorSpaceCreateWithICCData()` (iOS 10+/macOS 10.12+) to embed ICC profiles
- xnuimagetools is the source of truth for xnuimagefuzzer.m — always sync after changes

## Coding Conventions

### Objective-C Style
- Use `#pragma mark -` sections for code organization
- ANSI color macros for console output: `MAG`, `BLUE`, `RED`, `GRN`, `YEL`, `CYN`
- Guard all `CGContextRef` with NULL checks before use
- Always `CGContextRelease()` and `free()` bitmap data in error paths
- Use `os_log` and `os_signpost` for structured logging
- `static int verboseLogging = 0;` controls debug output

### Memory Management
- Manual retain/release patterns in Core Graphics code
- `@autoreleasepool` blocks around image generation loops
- Always pair `CGColorSpaceCreate*` with `CGColorSpaceRelease`
- Always pair `CGContextRef` creation with release in all code paths
- Check `malloc()` return values — never assume success

### CGBitmapInfo Correctness
- Always cast `CGImageAlphaInfo` to `CGBitmapInfo`: `(CGBitmapInfo)kCGImageAlphaPremultipliedLast`
- Combine with byte order using `|`: `(CGBitmapInfo)kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big`
- Never pass raw `kCGImageAlpha*` constants where `CGBitmapInfo` is expected
