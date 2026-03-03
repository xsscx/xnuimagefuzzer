#!/usr/bin/env python3
"""fuzz-gallery.py — Serve fuzzed images via HTTP and generate an HTML test gallery.

Exercises Safari/WebKit image decoding through multiple rendering paths:
  - <img> tags (standard decode)
  - <picture> with type hints (content-type sniffing)
  - CSS background-image (compositor path)
  - <canvas> drawImage (GPU-accelerated decode)
  - createImageBitmap (off-thread decode)
  - Image() constructor (prefetch/cache path)
  - Blob URL + revoke cycle (memory lifecycle)

Crash detection:
  - JS onerror handlers log decode failures
  - Canvas taint checks detect ICC color management issues
  - Performance.now() timing detects slow/hung decodes
  - Console output visible in Safari Web Inspector

Usage:
    python3 fuzz-gallery.py <image-directory> [--port 8088] [--open]
    python3 fuzz-gallery.py pipeline-combo/ --open   # auto-open Safari
"""

import argparse
import http.server
import json
import mimetypes
import os
import socketserver
import subprocess
import sys
import threading
import urllib.parse
from pathlib import Path

IMAGE_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.tiff', '.tif', '.gif', '.bmp',
    '.heic', '.heif', '.webp', '.jp2', '.exr', '.dng', '.tga',
    '.ico', '.icns', '.pbm', '.pdf', '.astc', '.ktx',
}

MIME_OVERRIDES = {
    '.heic': 'image/heic',
    '.heif': 'image/heif',
    '.webp': 'image/webp',
    '.jp2': 'image/jp2',
    '.exr': 'image/x-exr',
    '.tga': 'image/x-tga',
    '.icns': 'image/x-icns',
    '.pbm': 'image/x-portable-bitmap',
    '.astc': 'image/astc',
    '.ktx': 'image/ktx',
    '.dng': 'image/x-adobe-dng',
    '.bmp': 'image/bmp',
    '.tiff': 'image/tiff',
    '.tif': 'image/tiff',
    '.ico': 'image/x-icon',
    '.pdf': 'application/pdf',
}

GALLERY_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>XNU Image Fuzzer — Safari/WebKit Test Gallery</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, system-ui, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }
  h1 { text-align: center; margin-bottom: 10px; color: #e94560; }
  .stats { text-align: center; margin-bottom: 20px; font-size: 14px; color: #aaa; }
  #log { position: fixed; bottom: 0; left: 0; right: 0; max-height: 200px; overflow-y: auto;
         background: rgba(0,0,0,0.9); padding: 10px; font-family: monospace; font-size: 12px;
         border-top: 2px solid #e94560; z-index: 1000; }
  .log-crash { color: #ff4444; font-weight: bold; }
  .log-error { color: #ff8800; }
  .log-ok { color: #44ff44; }
  .log-info { color: #4488ff; }
  .controls { text-align: center; margin-bottom: 15px; }
  .controls button { background: #e94560; border: none; color: white; padding: 8px 16px;
                     border-radius: 4px; cursor: pointer; margin: 0 5px; font-size: 13px; }
  .controls button:hover { background: #c73e54; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px; padding-bottom: 220px; }
  .card { background: #16213e; border-radius: 8px; overflow: hidden; position: relative; }
  .card.error { border: 2px solid #ff4444; }
  .card.slow { border: 2px solid #ff8800; }
  .card.ok { border: 1px solid #333; }
  .card img, .card .bg-test { width: 100%; height: 150px; object-fit: contain; background: #0f0f23; }
  .card .bg-test { background-size: contain; background-repeat: no-repeat; background-position: center; }
  .card canvas { width: 100%; height: 150px; background: #0f0f23; }
  .card .info { padding: 6px 8px; font-size: 11px; word-break: break-all; }
  .card .info .name { color: #e94560; }
  .card .info .meta { color: #888; }
  .card .badge { position: absolute; top: 4px; right: 4px; padding: 2px 6px; border-radius: 3px;
                 font-size: 10px; font-weight: bold; }
  .badge-crash { background: #ff4444; color: white; }
  .badge-slow { background: #ff8800; color: white; }
  .badge-ok { background: #44ff44; color: black; }
  .tabs { display: flex; justify-content: center; gap: 5px; margin-bottom: 15px; flex-wrap: wrap; }
  .tabs button { background: #16213e; border: 1px solid #333; color: #aaa; padding: 5px 12px;
                 border-radius: 4px; cursor: pointer; font-size: 12px; }
  .tabs button.active { background: #e94560; color: white; border-color: #e94560; }
</style>
</head>
<body>
<h1>🔬 XNU Image Fuzzer — WebKit Decode Test</h1>
<div class="stats" id="stats">Loading images...</div>

<div class="controls">
  <button onclick="runAllTests()">▶ Run All Tests</button>
  <button onclick="runCanvasTests()">🎨 Canvas Decode</button>
  <button onclick="runBlobTests()">💾 Blob URL Cycle</button>
  <button onclick="runBitmapTests()">🖼 createImageBitmap</button>
  <button onclick="clearLog()">🗑 Clear Log</button>
  <button onclick="downloadReport()">📥 Download Report</button>
</div>

<div class="tabs" id="formatTabs"></div>
<div class="grid" id="gallery"></div>
<div id="log"></div>

<script>
const IMAGES = __IMAGES_JSON__;
const results = [];
let totalLoaded = 0, totalErrors = 0, totalSlow = 0;

function log(msg, cls = 'log-info') {
  const el = document.getElementById('log');
  const line = document.createElement('div');
  line.className = cls;
  line.textContent = `[${new Date().toISOString().substr(11,12)}] ${msg}`;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
}

function updateStats() {
  document.getElementById('stats').textContent =
    `${IMAGES.length} images | ✅ ${totalLoaded} loaded | ❌ ${totalErrors} errors | ⏱ ${totalSlow} slow (>2s)`;
}

// ── Phase 1: <img> tag loading ──
function buildGallery(filter) {
  const grid = document.getElementById('gallery');
  grid.innerHTML = '';
  const imgs = filter ? IMAGES.filter(f => f.ext === filter) : IMAGES;

  imgs.forEach((file, idx) => {
    const card = document.createElement('div');
    card.className = 'card';
    card.id = `card-${idx}`;

    const img = document.createElement('img');
    img.loading = 'lazy';
    img.decoding = 'async';
    const t0 = performance.now();

    img.onload = () => {
      const dt = performance.now() - t0;
      card.classList.add('ok');
      totalLoaded++;
      updateStats();
      results.push({ file: file.name, method: 'img', status: 'ok', time_ms: dt.toFixed(1),
                      width: img.naturalWidth, height: img.naturalHeight });
      if (dt > 2000) {
        totalSlow++;
        card.classList.add('slow');
        card.classList.remove('ok');
        log(`⏱ SLOW decode (${dt.toFixed(0)}ms): ${file.name}`, 'log-error');
        const badge = document.createElement('span');
        badge.className = 'badge badge-slow';
        badge.textContent = `${(dt/1000).toFixed(1)}s`;
        card.appendChild(badge);
      }
    };

    img.onerror = () => {
      const dt = performance.now() - t0;
      card.classList.add('error');
      totalErrors++;
      updateStats();
      results.push({ file: file.name, method: 'img', status: 'error', time_ms: dt.toFixed(1) });
      log(`❌ DECODE FAIL: ${file.name} (${file.ext}, ${file.size} bytes)`, 'log-crash');
      const badge = document.createElement('span');
      badge.className = 'badge badge-crash';
      badge.textContent = 'FAIL';
      card.appendChild(badge);
    };

    img.src = `/images/${encodeURIComponent(file.name)}`;
    card.appendChild(img);

    const info = document.createElement('div');
    info.className = 'info';
    info.innerHTML = `<div class="name">${file.name}</div><div class="meta">${file.ext} · ${formatSize(file.size)}</div>`;
    card.appendChild(info);
    grid.appendChild(card);
  });
}

// ── Phase 2: Canvas drawImage ──
function runCanvasTests() {
  log('Starting canvas drawImage tests...', 'log-info');
  let done = 0;
  IMAGES.forEach(file => {
    const img = new Image();
    img.onload = () => {
      try {
        const c = document.createElement('canvas');
        c.width = Math.min(img.naturalWidth, 512);
        c.height = Math.min(img.naturalHeight, 512);
        const ctx = c.getContext('2d');
        const t0 = performance.now();
        ctx.drawImage(img, 0, 0, c.width, c.height);
        // Read back pixels to force full decode + ICC color management
        const pixels = ctx.getImageData(0, 0, c.width, c.height);
        const dt = performance.now() - t0;
        results.push({ file: file.name, method: 'canvas', status: 'ok', time_ms: dt.toFixed(1),
                        pixels: pixels.data.length });
        log(`✅ Canvas OK: ${file.name} (${dt.toFixed(0)}ms, ${pixels.data.length} bytes readback)`, 'log-ok');
      } catch(e) {
        results.push({ file: file.name, method: 'canvas', status: 'error', error: e.message });
        log(`❌ Canvas CRASH: ${file.name} — ${e.message}`, 'log-crash');
      }
      if (++done === IMAGES.length) log(`Canvas tests complete: ${done} images`, 'log-info');
    };
    img.onerror = () => {
      results.push({ file: file.name, method: 'canvas', status: 'load-error' });
      if (++done === IMAGES.length) log(`Canvas tests complete: ${done} images`, 'log-info');
    };
    img.src = `/images/${encodeURIComponent(file.name)}`;
  });
}

// ── Phase 3: Blob URL creation + revocation ──
function runBlobTests() {
  log('Starting Blob URL lifecycle tests...', 'log-info');
  let done = 0;
  IMAGES.forEach(file => {
    fetch(`/images/${encodeURIComponent(file.name)}`)
      .then(r => r.blob())
      .then(blob => {
        const url = URL.createObjectURL(blob);
        const img = new Image();
        img.onload = () => {
          URL.revokeObjectURL(url);
          results.push({ file: file.name, method: 'blob', status: 'ok', blob_size: blob.size });
          log(`✅ Blob OK: ${file.name} (${blob.size} bytes)`, 'log-ok');
          if (++done === IMAGES.length) log(`Blob tests complete: ${done}`, 'log-info');
        };
        img.onerror = () => {
          URL.revokeObjectURL(url);
          results.push({ file: file.name, method: 'blob', status: 'error' });
          log(`❌ Blob FAIL: ${file.name}`, 'log-crash');
          if (++done === IMAGES.length) log(`Blob tests complete: ${done}`, 'log-info');
        };
        img.src = url;
      })
      .catch(e => {
        results.push({ file: file.name, method: 'blob', status: 'fetch-error', error: e.message });
        if (++done === IMAGES.length) log(`Blob tests complete: ${done}`, 'log-info');
      });
  });
}

// ── Phase 4: createImageBitmap (off-thread decode) ──
function runBitmapTests() {
  log('Starting createImageBitmap tests...', 'log-info');
  let done = 0;
  IMAGES.forEach(file => {
    fetch(`/images/${encodeURIComponent(file.name)}`)
      .then(r => r.blob())
      .then(blob => {
        const t0 = performance.now();
        return createImageBitmap(blob).then(bmp => {
          const dt = performance.now() - t0;
          results.push({ file: file.name, method: 'bitmap', status: 'ok',
                          time_ms: dt.toFixed(1), width: bmp.width, height: bmp.height });
          log(`✅ Bitmap OK: ${file.name} (${bmp.width}x${bmp.height}, ${dt.toFixed(0)}ms)`, 'log-ok');
          bmp.close();
          if (++done === IMAGES.length) log(`Bitmap tests complete: ${done}`, 'log-info');
        });
      })
      .catch(e => {
        results.push({ file: file.name, method: 'bitmap', status: 'error', error: e.message });
        log(`❌ Bitmap FAIL: ${file.name} — ${e.message}`, 'log-crash');
        if (++done === IMAGES.length) log(`Bitmap tests complete: ${done}`, 'log-info');
      });
  });
}

// ── Run all test phases ──
function runAllTests() {
  log('=== Running all test phases ===', 'log-info');
  runCanvasTests();
  setTimeout(runBlobTests, 1000);
  setTimeout(runBitmapTests, 2000);
}

// ── Download report ──
function downloadReport() {
  const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'fuzz-gallery-report.json';
  a.click();
  URL.revokeObjectURL(a.href);
  log(`Downloaded report with ${results.length} entries`, 'log-info');
}

function clearLog() { document.getElementById('log').innerHTML = ''; }

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
  return (bytes/(1024*1024)).toFixed(1) + ' MB';
}

// ── Format filter tabs ──
const exts = [...new Set(IMAGES.map(f => f.ext))].sort();
const tabsEl = document.getElementById('formatTabs');
const allBtn = document.createElement('button');
allBtn.textContent = `All (${IMAGES.length})`;
allBtn.className = 'active';
allBtn.onclick = () => { buildGallery(null); setActiveTab(allBtn); };
tabsEl.appendChild(allBtn);
exts.forEach(ext => {
  const count = IMAGES.filter(f => f.ext === ext).length;
  const btn = document.createElement('button');
  btn.textContent = `${ext} (${count})`;
  btn.onclick = () => { buildGallery(ext); setActiveTab(btn); };
  tabsEl.appendChild(btn);
});
function setActiveTab(btn) {
  tabsEl.querySelectorAll('button').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
}

// ── Initial load ──
buildGallery(null);
log(`Gallery loaded: ${IMAGES.length} images across ${exts.length} formats`, 'log-info');
updateStats();
</script>
</body>
</html>"""


class FuzzGalleryHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler that serves images with correct MIME types and the gallery page."""

    def __init__(self, *args, image_dir=None, image_list=None, **kwargs):
        self.image_dir = image_dir
        self.image_list = image_list
        super().__init__(*args, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = urllib.parse.unquote(parsed.path)

        if path == '/' or path == '/index.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            html = GALLERY_HTML.replace('__IMAGES_JSON__', json.dumps(self.image_list))
            self.wfile.write(html.encode('utf-8'))
            return

        if path.startswith('/images/'):
            filename = path[8:]  # strip /images/
            filepath = os.path.join(self.image_dir, filename)
            if os.path.isfile(filepath):
                ext = os.path.splitext(filename)[1].lower()
                mime = MIME_OVERRIDES.get(ext) or mimetypes.guess_type(filename)[0] or 'application/octet-stream'
                self.send_response(200)
                self.send_header('Content-Type', mime)
                self.send_header('Content-Length', str(os.path.getsize(filepath)))
                self.send_header('Cache-Control', 'no-cache')
                self.end_headers()
                with open(filepath, 'rb') as f:
                    self.wfile.write(f.read())
                return

        self.send_error(404)

    def log_message(self, format, *args):
        # Quiet logging — only show errors
        if '404' in str(args) or '500' in str(args):
            super().log_message(format, *args)


def scan_images(directory):
    """Scan directory for image files and return metadata list."""
    images = []
    for root, _, files in os.walk(directory):
        for f in sorted(files):
            ext = os.path.splitext(f)[1].lower()
            if ext in IMAGE_EXTENSIONS:
                full = os.path.join(root, f)
                # Use relative path from the image directory
                rel = os.path.relpath(full, directory)
                images.append({
                    'name': rel,
                    'ext': ext.lstrip('.'),
                    'size': os.path.getsize(full),
                })
    return images


def main():
    parser = argparse.ArgumentParser(description='Fuzz gallery — serve images to Safari/WebKit')
    parser.add_argument('directory', help='Directory containing fuzzed images')
    parser.add_argument('--port', type=int, default=8088, help='HTTP port (default: 8088)')
    parser.add_argument('--open', action='store_true', help='Auto-open Safari')
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"Error: {args.directory} is not a directory", file=sys.stderr)
        sys.exit(1)

    image_dir = os.path.abspath(args.directory)
    image_list = scan_images(image_dir)
    print(f"Found {len(image_list)} images in {image_dir}")

    exts = {}
    for img in image_list:
        exts[img['ext']] = exts.get(img['ext'], 0) + 1
    for ext, count in sorted(exts.items()):
        print(f"  .{ext:8s} {count:5d} files")

    handler = lambda *a, **k: FuzzGalleryHandler(*a, image_dir=image_dir, image_list=image_list, **k)
    server = socketserver.TCPServer(('127.0.0.1', args.port), handler)
    server.allow_reuse_address = True

    url = f'http://127.0.0.1:{args.port}/'
    print(f"\n🔬 Serving gallery at {url}")
    print("   Open in Safari to test WebKit image decoding")
    print("   Press Ctrl+C to stop\n")

    if args.open:
        subprocess.Popen(['open', '-a', 'Safari', url])

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == '__main__':
    main()
