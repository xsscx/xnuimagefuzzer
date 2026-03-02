---
name: Code Review — XNU Image Fuzzer
description: Review Objective-C fuzzer code for memory safety, correctness, and coverage
---

# Code Review — XNU Image Fuzzer

Review `xnuimagefuzzer.m` and related files for bugs, memory safety issues,
and opportunities to improve fuzzing coverage.

## Review Checklist

### Memory Safety (Critical)
- [ ] Every `CGContextRef` is checked for NULL before use
- [ ] Every `malloc()` / `calloc()` return is checked for NULL
- [ ] Every `CGColorSpaceCreate*` is paired with `CGColorSpaceRelease`
- [ ] Every `CGContextRef` is released in all code paths (including error paths)
- [ ] `free()` called on bitmap data in error paths before early return
- [ ] No use-after-free on `CGImageRef` objects
- [ ] Buffer sizes calculated correctly for each pixel format

### Type Safety
- [ ] `CGBitmapInfo` constructed with explicit casts from `CGImageAlphaInfo`
- [ ] No raw `kCGImageAlpha*` passed where `CGBitmapInfo` expected
- [ ] Byte order flags combined correctly with alpha info
- [ ] `size_t` used for buffer sizes (not `int`)

### Correctness
- [ ] 16-bit contexts use 2 bytes per component (not 1)
- [ ] HDR float contexts use 4 bytes per component
- [ ] Grayscale contexts use 1 component (not 3 or 4)
- [ ] Alpha-only contexts use `kCGImageAlphaOnly`
- [ ] Monochrome contexts handle 1-bit packing correctly
- [ ] Noise generation uses proper random distribution
- [ ] No duplicate `#define` macros

### Coverage Improvement
- [ ] All 12 bitmap context types are exercised
- [ ] Multiple output formats tested (PNG, JPEG, GIF, TIFF, HEIF, BMP)
- [ ] Edge cases: zero-size images, maximum-size images
- [ ] Color space variants: sRGB, Display P3, Generic RGB, Linear
- [ ] Error handling paths tested

## Key Files to Review
1. `XNU Image Fuzzer/xnuimagefuzzer.m` — Core fuzzer (~3200 lines)
2. `XNU Image Fuzzer/ViewController.m` — Image loading/display
3. `XNU Image Fuzzer/AppDelegate.m` — Exception handling
4. `XNU Image Fuzzer/CMakeLists.txt` — Build configuration

## Common Bug Patterns
```objc
// BAD: Missing NULL check
CGContextRef ctx = CGBitmapContextCreate(...);
CGContextSetRGBFillColor(ctx, ...);  // Crash if ctx is NULL

// GOOD: NULL check
CGContextRef ctx = CGBitmapContextCreate(...);
if (!ctx) { free(data); CGColorSpaceRelease(colorSpace); return; }

// BAD: Wrong cast
CGBitmapInfo info = kCGImageAlphaPremultipliedLast;  // -Wenum-conversion

// GOOD: Explicit cast
CGBitmapInfo info = (CGBitmapInfo)kCGImageAlphaPremultipliedLast;

// BAD: Memory leak on error path
CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
CGContextRef ctx = CGBitmapContextCreate(...);
if (!ctx) return;  // cs leaked!

// GOOD: Clean up all resources
if (!ctx) { CGColorSpaceRelease(cs); free(data); return; }
```
