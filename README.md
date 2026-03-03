# XNU Image Fuzzer

Image fuzzing framework for iOS/macOS targeting CoreGraphics, ImageIO, and ICC profile parsing across 15 bitmap context types and 22 output formats.

- **PermaLink**: https://srd.cx/xnu-image-fuzzer/
- **CVE Reference**: https://srd.cx/cve-2022-26730/
- **Author**: David Hoyt — https://xss.cx · https://srd.cx · https://hoyt.net

## Workflow

1. Generate baseline images with [xnuimagetools](https://github.com/xsscx/xnuimagetools) (iOS, watchOS, Mac Catalyst)
2. Fuzz with xnuimagefuzzer (`--pipeline`, `--chain`, `--input-dir`)
3. Embed ICC profiles (clean + [mutated](https://github.com/xsscx/research/tree/main/colorbleed_tools))
4. Encode to 22 formats (PNG, JPEG, TIFF×5, HEIC, WebP, JP2, PDF, BMP, GIF, EXR, ICNS, …)
5. Feed to target apps: Preview, Safari, iMessage, Mail, Notes
6. Collect crashes from `~/Library/Logs/DiagnosticReports/`

## Quick Start

```bash
# Xcode
open "XNU Image Fuzzer.xcodeproj"  # Update Team ID → Run

# CLI (Mac Catalyst, unsigned)
xcodebuild build \
  -scheme "XNU Image Fuzzer" \
  -destination 'platform=macOS,variant=Mac Catalyst' \
  -configuration Release \
  CODE_SIGN_IDENTITY="-" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO

# Pipeline fuzzing (generate → fuzz → ICC embed → measure)
./XNU\ Image\ Fuzzer --pipeline /path/to/input-images/
```

## Platform Support

| Platform | Status |
|----------|--------|
| macOS 15+ (arm64, x86_64) | ✅ |
| iOS / iPadOS 18+ | ✅ |
| visionOS 2.x | ✅ |

## Documentation

- [Copilot Instructions](.github/copilot-instructions.md) — build commands, architecture, debug env vars
- [API Docs](https://xss.cx/public/docs/xnuimagefuzzer/)
- [XNU Image Tools](https://github.com/xsscx/xnuimagetools) — multi-platform image generator
