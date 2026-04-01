#!/usr/bin/env python3
import os
import importlib.util
import pathlib
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "fuzz-gallery.py"
SPEC = importlib.util.spec_from_file_location("fuzz_gallery", MODULE_PATH)
FUZZ_GALLERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FUZZ_GALLERY)


class FuzzGalleryHelpersTest(unittest.TestCase):
    def test_serialize_images_for_inline_script_escapes_script_terminator(self):
        payload = [{"name": "</script><script>alert(1)</script>/poc.jpg"}]

        serialized = FUZZ_GALLERY.serialize_images_for_inline_script(payload)

        self.assertIn("<\\/script><script>alert(1)<\\/script>", serialized)
        self.assertNotIn("</script><script>", serialized)

    def test_resolve_image_path_keeps_nested_files_inside_root(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            image_dir = pathlib.Path(tmpdir)
            nested = image_dir / "nested" / "poc.png"
            nested.parent.mkdir()
            nested.touch()

            resolved, filename = FUZZ_GALLERY.resolve_image_path(
                str(image_dir),
                "/images/nested/poc.png",
            )

            self.assertTrue(os.path.samefile(resolved, nested))
            self.assertEqual(filename, "nested/poc.png")

    def test_resolve_image_path_rejects_parent_traversal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            resolved, filename = FUZZ_GALLERY.resolve_image_path(
                tmpdir,
                "/images/../README.md",
            )

            self.assertIsNone(resolved)
            self.assertEqual(filename, "../README.md")


if __name__ == "__main__":
    unittest.main()
