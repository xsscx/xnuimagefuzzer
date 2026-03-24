"""
synth_test_images.py — Synthesize valid BeyondRGB input image sets.

Creates TIFF images matching the pipeline's exact expectations:
  - 16-bit unsigned, 3 channels (RGB), chunky interleaved
  - 1 row per strip (ROWSPERSTRIP=1)
  - Matching dimensions across art/white/dark triplets
  - Realistic pixel distributions for flat-field correction

Generates multiple test sets for different scenarios:
  Set 1: Normal 1024x768 — clean art with color patches, proper white/dark
  Set 2: Small 64x64    — minimal valid input, fast pipeline test
  Set 3: Large 4096x3072— stress test (larger buffers, ~72MB per image)
  Set 4: Edge cases     — near-black art, saturated white, hot-pixel dark
"""

import numpy as np
import tifffile
import os

OUT_DIR = r"E:\tmp\beyondrgb\test-images"


def write_tiff_16bit_rowperstrip(path, data):
    """Write 16-bit 3-channel TIFF with 1 row per strip (pipeline requirement)."""
    assert data.dtype == np.uint16
    assert data.ndim == 3 and data.shape[2] == 3
    h, w, c = data.shape
    tifffile.imwrite(
        path,
        data,
        photometric='rgb',
        planarconfig='contig',
        rowsperstrip=1,
        compression=None,
    )
    print(f"  {os.path.basename(path)}: {w}x{h}x{c} uint16 ({os.path.getsize(path):,} bytes)")


def make_color_patch_grid(h, w, rows=6, cols=4):
    """Create a synthetic color target grid (like a ColorChecker)."""
    img = np.zeros((h, w, 3), dtype=np.float64)

    # 24-patch colorchecker-like colors (approximate, 0-1 range)
    patches = [
        (0.45, 0.31, 0.26), (0.77, 0.58, 0.50), (0.35, 0.47, 0.61),
        (0.35, 0.42, 0.26), (0.51, 0.49, 0.73), (0.33, 0.69, 0.67),
        (0.83, 0.52, 0.16), (0.27, 0.34, 0.65), (0.72, 0.29, 0.33),
        (0.35, 0.22, 0.38), (0.59, 0.73, 0.24), (0.89, 0.65, 0.13),
        (0.17, 0.24, 0.56), (0.30, 0.58, 0.28), (0.60, 0.19, 0.22),
        (0.91, 0.82, 0.12), (0.67, 0.30, 0.55), (0.14, 0.48, 0.60),
        (0.95, 0.95, 0.95), (0.78, 0.78, 0.78), (0.59, 0.59, 0.59),
        (0.40, 0.40, 0.40), (0.20, 0.20, 0.20), (0.05, 0.05, 0.05),
    ]

    ph = h // rows
    pw = w // cols
    idx = 0
    for r in range(rows):
        for c in range(cols):
            if idx < len(patches):
                color = patches[idx]
            else:
                color = (np.random.rand(), np.random.rand(), np.random.rand())
            y0, y1 = r * ph, (r + 1) * ph
            x0, x1 = c * pw, (c + 1) * pw
            for ch in range(3):
                img[y0:y1, x0:x1, ch] = color[ch]
            idx += 1
    return img


def make_artwork(h, w):
    """Synthesize an artwork image with gradients, shapes, and a color target region."""
    img = np.zeros((h, w, 3), dtype=np.float64)

    # Background gradient (sky-like)
    for y in range(h):
        t = y / h
        img[y, :, 0] = 0.2 + 0.3 * t        # R
        img[y, :, 1] = 0.4 + 0.2 * (1 - t)  # G
        img[y, :, 2] = 0.7 - 0.3 * t         # B

    # Add some geometric "artwork" shapes
    cx, cy = w // 2, h // 2
    for y in range(h):
        for x in range(w):
            # Circle
            dist = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
            if dist < min(h, w) // 4:
                img[y, x] = [0.8, 0.6, 0.2]
            # Rectangle
            if abs(x - w // 4) < w // 8 and abs(y - h // 4) < h // 8:
                img[y, x] = [0.2, 0.7, 0.4]

    # Embed a small color target in bottom-right corner (10% of image)
    th, tw = h // 10, w // 10
    target = make_color_patch_grid(th, tw, rows=4, cols=6)
    y0 = h - th - 10
    x0 = w - tw - 10
    if y0 > 0 and x0 > 0:
        img[y0:y0 + th, x0:x0 + tw] = target

    return img


def make_artwork_fast(h, w):
    """Fast vectorized artwork for large images."""
    img = np.zeros((h, w, 3), dtype=np.float64)

    # Gradient background
    ys = np.linspace(0, 1, h).reshape(-1, 1)
    xs = np.linspace(0, 1, w).reshape(1, -1)
    img[:, :, 0] = 0.2 + 0.5 * ys * xs
    img[:, :, 1] = 0.3 + 0.4 * (1 - ys) * xs
    img[:, :, 2] = 0.6 - 0.3 * ys

    # Circular region
    cy, cx = h // 2, w // 2
    Y, X = np.ogrid[:h, :w]
    mask = (X - cx) ** 2 + (Y - cy) ** 2 < (min(h, w) // 4) ** 2
    img[mask] = [0.8, 0.55, 0.15]

    # Rect region
    ry, rx = h // 4, w // 4
    rh, rw = h // 6, w // 6
    img[ry:ry + rh, rx:rx + rw] = [0.15, 0.65, 0.35]

    # Color target strip at bottom
    th = max(h // 12, 4)
    tw = w
    target = make_color_patch_grid(th, tw, rows=4, cols=6)
    img[h - th:, :tw] = target

    return img


def to_uint16(img_float):
    """Convert [0,1] float to uint16."""
    return np.clip(img_float * 65535, 0, 65535).astype(np.uint16)


def add_noise(img, sigma=0.005):
    """Add Gaussian noise."""
    return img + np.random.normal(0, sigma, img.shape)


def generate_set(name, h, w, art_func, white_level=0.92, dark_level=0.002,
                 dark_noise=0.001, white_noise=0.01, art_noise=0.008):
    """Generate a complete art/white/dark triplet × 2 positions."""
    d = os.path.join(OUT_DIR, name)
    os.makedirs(d, exist_ok=True)
    print(f"\n=== Set: {name} ({w}x{h}) ===")

    # Art images (two slightly different "captures")
    art1 = np.clip(add_noise(art_func(h, w), art_noise), 0, 1)
    art2 = np.clip(add_noise(art_func(h, w), art_noise), 0, 1)

    # White reference (uniform bright field with slight vignetting)
    white_base = np.full((h, w, 3), white_level, dtype=np.float64)
    Y, X = np.ogrid[:h, :w]
    cy, cx = h / 2, w / 2
    vignette = 1.0 - 0.15 * (((X - cx) / cx) ** 2 + ((Y - cy) / cy) ** 2)
    for ch in range(3):
        white_base[:, :, ch] *= vignette
    white1 = np.clip(add_noise(white_base, white_noise), 0, 1)
    white2 = np.clip(add_noise(white_base, white_noise), 0, 1)

    # Dark reference (nearly black with some hot pixels)
    dark1 = np.clip(np.full((h, w, 3), dark_level) + np.random.normal(0, dark_noise, (h, w, 3)), 0, 1)
    dark2 = np.clip(np.full((h, w, 3), dark_level) + np.random.normal(0, dark_noise, (h, w, 3)), 0, 1)

    # Add a few "hot pixels" to dark frames
    for _ in range(max(1, (h * w) // 10000)):
        hy, hx = np.random.randint(0, h), np.random.randint(0, w)
        dark1[hy, hx] = [0.8, 0.02, 0.02]
        dark2[hy, hx] = [0.75, 0.03, 0.01]

    # Write all 6 images
    write_tiff_16bit_rowperstrip(os.path.join(d, "art1.tiff"), to_uint16(art1))
    write_tiff_16bit_rowperstrip(os.path.join(d, "white1.tiff"), to_uint16(white1))
    write_tiff_16bit_rowperstrip(os.path.join(d, "dark1.tiff"), to_uint16(dark1))
    write_tiff_16bit_rowperstrip(os.path.join(d, "art2.tiff"), to_uint16(art2))
    write_tiff_16bit_rowperstrip(os.path.join(d, "white2.tiff"), to_uint16(white2))
    write_tiff_16bit_rowperstrip(os.path.join(d, "dark2.tiff"), to_uint16(dark2))

    return d


def generate_edge_case_set():
    """Set 4: Edge-case images that stress validation paths."""
    d = os.path.join(OUT_DIR, "set4-edge-cases")
    os.makedirs(d, exist_ok=True)
    h, w = 256, 256
    print(f"\n=== Set: set4-edge-cases ({w}x{h}) ===")

    # Near-black art (all pixels close to 0 → division issues in normalization)
    art_black = np.clip(np.random.normal(0.001, 0.0005, (h, w, 3)), 0, 1)
    write_tiff_16bit_rowperstrip(os.path.join(d, "art_nearblack.tiff"), to_uint16(art_black))

    # Saturated white art (all pixels at max)
    art_saturated = np.full((h, w, 3), 0.999, dtype=np.float64)
    write_tiff_16bit_rowperstrip(os.path.join(d, "art_saturated.tiff"), to_uint16(art_saturated))

    # White ref = Dark ref (division by zero in flat field: white-dark=0)
    uniform = np.full((h, w, 3), 0.5, dtype=np.float64)
    write_tiff_16bit_rowperstrip(os.path.join(d, "white_equals_dark.tiff"), to_uint16(uniform))

    # Single-value image (all pixels identical)
    mono = np.full((h, w, 3), 0.42, dtype=np.float64)
    write_tiff_16bit_rowperstrip(os.path.join(d, "uniform_42pct.tiff"), to_uint16(mono))

    # Checkerboard (high frequency → stress registration)
    checker = np.zeros((h, w, 3), dtype=np.float64)
    for y in range(h):
        for x in range(w):
            if (y + x) % 2 == 0:
                checker[y, x] = [0.9, 0.9, 0.9]
            else:
                checker[y, x] = [0.1, 0.1, 0.1]
    write_tiff_16bit_rowperstrip(os.path.join(d, "checkerboard.tiff"), to_uint16(checker))

    # Gradient ramp (useful for bit depth detection)
    ramp = np.zeros((h, w, 3), dtype=np.float64)
    for x in range(w):
        val = x / (w - 1)
        ramp[:, x, :] = val
    write_tiff_16bit_rowperstrip(os.path.join(d, "gradient_ramp.tiff"), to_uint16(ramp))

    # Normal white/dark pair for pairing with edge-case arts
    white_norm = np.clip(np.full((h, w, 3), 0.90) + np.random.normal(0, 0.005, (h, w, 3)), 0, 1)
    dark_norm = np.clip(np.full((h, w, 3), 0.002) + np.random.normal(0, 0.001, (h, w, 3)), 0, 1)
    write_tiff_16bit_rowperstrip(os.path.join(d, "white_normal.tiff"), to_uint16(white_norm))
    write_tiff_16bit_rowperstrip(os.path.join(d, "dark_normal.tiff"), to_uint16(dark_norm))

    return d


def generate_8bit_set():
    """Bonus: 8-bit images to test bit depth scaling path."""
    d = os.path.join(OUT_DIR, "set5-8bit")
    os.makedirs(d, exist_ok=True)
    h, w = 256, 256
    print(f"\n=== Set: set5-8bit ({w}x{h}, 8-bit) ===")

    art = np.clip(np.random.rand(h, w, 3) * 0.7 + 0.1, 0, 1)
    white = np.clip(np.full((h, w, 3), 0.9) + np.random.normal(0, 0.02, (h, w, 3)), 0, 1)
    dark = np.clip(np.random.normal(0.01, 0.005, (h, w, 3)), 0, 1)

    for name, data in [("art1.tiff", art), ("white1.tiff", white), ("dark1.tiff", dark)]:
        data8 = np.clip(data * 255, 0, 255).astype(np.uint8)
        # Write as 8-bit but pipeline should still handle via bit depth detection
        # Need to write as uint16 with values in 0-255 range for LibTiffReader
        data16 = data8.astype(np.uint16)
        tifffile.imwrite(
            os.path.join(d, name),
            data16,
            photometric='rgb',
            planarconfig='contig',
            rowsperstrip=1,
            compression=None,
        )
        fsize = os.path.getsize(os.path.join(d, name))
        print(f"  {name}: {w}x{h}x3 uint16(8-bit range) ({fsize:,} bytes)")

    return d


if __name__ == "__main__":
    np.random.seed(42)

    # Set 1: Normal 1024x768
    generate_set("set1-normal", 768, 1024, make_artwork)

    # Set 2: Small 64x64 (fast pipeline test)
    generate_set("set2-small", 64, 64, make_artwork_fast)

    # Set 3: Large 4096x3072 (stress test)
    generate_set("set3-large", 3072, 4096, make_artwork_fast)

    # Set 4: Edge cases
    generate_edge_case_set()

    # Set 5: 8-bit range
    generate_8bit_set()

    # Summary
    print("\n=== All sets generated ===")
    total = 0
    for root, dirs, files in os.walk(OUT_DIR):
        for f in files:
            if f.endswith(".tiff"):
                total += 1
    print(f"Total images: {total}")
    print(f"Output: {OUT_DIR}")
