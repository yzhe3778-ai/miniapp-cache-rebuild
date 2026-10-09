"""Behavior tests use only self-generated text; no real target cache."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile


SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "package_skill.py"
SPEC = importlib.util.spec_from_file_location("package_skill", SOURCE)
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "skill"
        self.root.mkdir()
        for name in PACKAGE.REQUIRED_FILES:
            (self.root / name).write_text("Synthetic public material\n", encoding="utf-8")
        (self.root / "scripts").mkdir()
        (self.root / "scripts" / "synthetic.py").write_text("API_KEY = '<redacted>'\n", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_deterministic_manifest_and_readback(self):
        first = self.base / "a.zip"
        second = self.base / "b.zip"
        a = PACKAGE.package_skill(self.root, first)
        b = PACKAGE.package_skill(self.root, second)
        self.assertEqual(a["archive_sha256"], b["archive_sha256"])
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with zipfile.ZipFile(first) as archive:
            manifest = json.loads(archive.read(PACKAGE.ARCHIVE_ROOT + "/distribution-manifest.json"))
            self.assertEqual(manifest["file_count"], len(PACKAGE.REQUIRED_FILES) + 1)
            for entry in manifest["files"]:
                data = archive.read(PACKAGE.ARCHIVE_ROOT + "/" + entry["path"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])

    def test_archive_repacking_excludes_its_generated_manifest(self):
        original = self.base / "original.zip"
        PACKAGE.package_skill(self.root, original)
        unpacked = self.base / "unpacked"
        with zipfile.ZipFile(original) as archive:
            archive.extractall(unpacked)
        rebuilt = self.base / "rebuilt.zip"
        PACKAGE.package_skill(unpacked / PACKAGE.ARCHIVE_ROOT, rebuilt)
        self.assertEqual(original.read_bytes(), rebuilt.read_bytes())

    def test_private_outputs_and_dependency_directories_excluded(self):
        baseline = self.base / "baseline.zip"
        PACKAGE.package_skill(self.root, baseline)
        for name in ["private-evidence", "node_modules", ".venv", "outputs"]:
            (self.root / name).mkdir()
            (self.root / name / "commercial.wxapkg").write_bytes(b"private binary")
        out = self.base / "out.zip"
        result = PACKAGE.package_skill(self.root, out)
        self.assertEqual(result["excluded_count"], 4)
        self.assertEqual(baseline.read_bytes(), out.read_bytes())
        with zipfile.ZipFile(out) as archive:
            self.assertFalse(any("commercial" in path for path in archive.namelist()))

    def test_secret_file_and_secret_value_refused(self):
        (self.root / ".env").write_text("private configuration\n", encoding="utf-8")
        with self.assertRaises(PACKAGE.PackageError):
            PACKAGE.package_skill(self.root, self.base / "secret-file.zip")
        (self.root / ".env").unlink()
        (self.root / "scripts" / "synthetic.py").write_text("API_KEY = '" + "sk-" + "a" * 40 + "'\n", encoding="utf-8")
        with self.assertRaises(PACKAGE.PackageError):
            PACKAGE.package_skill(self.root, self.base / "secret-value.zip")

    def test_personal_absolute_path_refused(self):
        personal = "/" + "Users/" + "person/private/report.md"
        (self.root / "README.md").write_text(personal, encoding="utf-8")
        with self.assertRaisesRegex(PACKAGE.PackageError, "Personal absolute path"):
            PACKAGE.package_skill(self.root, self.base / "personal.zip")

    def test_prefixed_credential_assignment_and_url_credentials_refused(self):
        source = self.root / "scripts" / "synthetic.py"
        source.write_text("RESET_RADAR_API_KEY = '" + "z" * 32 + "'\n", encoding="utf-8")
        with self.assertRaises(PACKAGE.PackageError):
            PACKAGE.package_skill(self.root, self.base / "prefixed.zip")
        source.write_text("endpoint = '" + "https://" + "name:private" + "@example.org/resource'\n", encoding="utf-8")
        with self.assertRaises(PACKAGE.PackageError):
            PACKAGE.package_skill(self.root, self.base / "url-credentials.zip")

    def test_symlink_and_unexpected_file_refused(self):
        linked = self.root / "scripts" / "link.py"
        try:
            linked.symlink_to(self.root / "README.md")
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation unavailable on this runner")
        with self.assertRaises(PACKAGE.PackageError):
            PACKAGE.package_skill(self.root, self.base / "link.zip")
        linked.unlink()
        (self.root / "commercial.wxapkg").write_bytes(b"source package")
        with self.assertRaises(PACKAGE.PackageError):
            PACKAGE.package_skill(self.root, self.base / "commercial.zip")

    def test_missing_required_binary_and_output_overwrite_refused(self):
        (self.root / "LICENSE").unlink()
        with self.assertRaises(PACKAGE.PackageError):
            PACKAGE.package_skill(self.root, self.base / "missing.zip")
        (self.root / "LICENSE").write_text("MIT\n", encoding="utf-8")
        binary = self.root / "scripts" / "binary.py"
        binary.write_bytes(b"\xff\x00")
        with self.assertRaises(PACKAGE.PackageError):
            PACKAGE.package_skill(self.root, self.base / "binary.zip")
        binary.unlink()
        existing = self.base / "existing.zip"
        existing.write_bytes(b"keep")
        with self.assertRaises(PACKAGE.PackageError):
            PACKAGE.package_skill(self.root, existing)
        self.assertEqual(existing.read_bytes(), b"keep")
        with self.assertRaises(PACKAGE.PackageError):
            PACKAGE.package_skill(self.root, self.root / "inside.zip")

    def test_size_limits_and_case_alias(self):
        old = PACKAGE.MAX_FILE_BYTES
        PACKAGE.MAX_FILE_BYTES = 2
        try:
            with self.assertRaises(PACKAGE.PackageError):
                PACKAGE.package_skill(self.root, self.base / "large.zip")
        finally:
            PACKAGE.MAX_FILE_BYTES = old
        # Alias behavior varies by filesystem, so test the policy on real aliases when supported.
        upper = self.root / "scripts" / "A.py"
        lower = self.root / "scripts" / "a.py"
        upper.write_text("first\n", encoding="utf-8")
        lower.write_text("second\n", encoding="utf-8")
        if upper.stat().st_ino == lower.stat().st_ino:
            self.skipTest("Case-insensitive filesystem cannot preserve both input names")
        with self.assertRaises(PACKAGE.PackageError):
            PACKAGE.package_skill(self.root, self.base / "alias.zip")


if __name__ == "__main__":
    unittest.main()
