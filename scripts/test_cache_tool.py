#!/usr/bin/env python3
"""Regression checks for package integrity and read-only incremental extraction."""

import argparse
import contextlib
import io
import json
import struct
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace

import cache_tool as tool


TARGET = "wx1234567890abcdef"


def package(files):
    names = [name.encode("utf-8") for name, _ in files]
    index_size = 4 + sum(12 + len(name) for name in names)
    cursor = 14 + index_size
    index = struct.pack(">I", len(files))
    for name, (_, data) in zip(names, files):
        index += struct.pack(">I", len(name)) + name + struct.pack(">II", cursor, len(data))
        cursor += len(data)
    body = b"".join(data for _, data in files)
    return b"\xbe" + struct.pack(">III", 0, index_size, len(body)) + b"\xed" + index + body


def quiet_extract(source, out, appid=TARGET):
    with contextlib.redirect_stdout(io.StringIO()):
        result = tool.extract(SimpleNamespace(source=str(source), out=str(out), appid=appid))
    return result, json.loads((out / "package-manifest.json").read_text())


class IntegrityTests(unittest.TestCase):
    def test_plain_unicode_and_empty_file(self):
        raw = package([("/页面/标题.txt", "课表".encode()), ("/empty", b"")])
        decoded, format_name = tool.decode(raw, TARGET)
        entries, shared = tool.parse_package(decoded)
        self.assertEqual(format_name, "plain-wxapkg")
        self.assertEqual(entries[0]["sha256"], tool.sha("课表".encode()))
        self.assertEqual(entries[1]["size"], 0)
        self.assertFalse(shared)

    def test_v1mmwx_and_wrong_appid(self):
        from Crypto.Cipher import AES
        raw = package([("/asset.bin", bytes(range(256)) * 8)])
        key = tool.hashlib.pbkdf2_hmac("sha1", TARGET.encode(), b"saltiest", 1000, 32)
        prefix = AES.new(key, AES.MODE_CBC, b"the iv: 16 bytes").encrypt(raw[:1023] + b"\x01")
        encoded = b"V1MMWX" + prefix + bytes(byte ^ ord(TARGET[-2]) for byte in raw[1023:])
        self.assertEqual(tool.decode(encoded, TARGET)[0], raw)
        with self.assertRaises(ValueError):
            tool.parse_package(tool.decode(encoded, "wx0000000000000000")[0])

    def test_shared_byte_ranges(self):
        raw = bytearray(package([("/container", b"abcd"), ("/inner", b"ab")]))
        first_offset = 18 + 4 + len("/container")
        second_offset = first_offset + 8 + 4 + len("/inner")
        body_start = 14 + struct.unpack_from(">I", raw, 5)[0]
        struct.pack_into(">II", raw, first_offset, body_start, 6)
        struct.pack_into(">II", raw, second_offset, body_start + 1, 2)
        entries, shared = tool.parse_package(raw)
        self.assertEqual(len(entries), 2)
        self.assertTrue(shared)

    def test_unsafe_paths(self):
        for name in ["/../escape", "/a/../../escape", "//absolute", "C:/escape", "/a\\escape", "/a\0b", "/a/./b", "/a//b"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                tool.parse_package(package([(name, b"content")]))

    def test_duplicate_alias_and_file_directory_collision(self):
        for files in [[("/a", b"1"), ("a", b"2")], [("/a", b"1"), ("/a/b", b"2")]]:
            with self.assertRaises(ValueError):
                tool.parse_package(package(files))

    def test_corrupt_header_and_length(self):
        raw = package([("/asset", b"abc")])
        for damaged in [b"", raw[:17], raw[:-1], raw + b"x", b"\x00" + raw[1:]]:
            with self.assertRaises(ValueError):
                tool.parse_package(damaged)

    def test_index_and_body_bounds(self):
        for offset, size in [(0, 1), (999999, 1), (34, 999999)]:
            damaged = bytearray(package([("/asset", b"abc")]))
            struct.pack_into(">II", damaged, 18 + 4 + len("/asset"), offset, size)
            with self.assertRaises(ValueError):
                tool.parse_package(damaged)

    def test_body_gap_rejected(self):
        damaged = bytearray(package([("/asset", b"abc")]))
        entry_offset = 18 + 4 + len("/asset")
        offset, size = struct.unpack_from(">II", damaged, entry_offset)
        struct.pack_into(">II", damaged, entry_offset, offset + 1, size - 1)
        with self.assertRaisesRegex(ValueError, "body gaps"):
            tool.parse_package(damaged)

    def test_unknown_snapshot_and_nonzero_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir()
            (source / "broken.wxapkg").write_bytes(b"unknown-version")
            result, manifest = quiet_extract(source, base / "evidence")
            self.assertEqual(result, 1)
            self.assertEqual(manifest["verified_package_count"], 0)
            self.assertEqual((base / "evidence" / manifest["packages"][0]["snapshot"]).read_bytes(), b"unknown-version")

    def test_incremental_and_tampered_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source, out = base / "source", base / "evidence"
            source.mkdir()
            original = package([("/asset", b"abc")])
            (source / "__APP__.wxapkg").write_bytes(original)
            self.assertEqual(quiet_extract(source, out)[0], 0)
            _, manifest = quiet_extract(source, out)
            self.assertTrue(manifest["packages"][0]["reused_decoded"])
            (source / "extra.wxapkg").write_bytes(package([("/extra", b"xyz")]))
            _, manifest = quiet_extract(source, out)
            self.assertEqual(manifest["package_count"], 2)
            item = next(item for item in manifest["packages"] if item["name"] == "__APP__.wxapkg")
            extracted = out / item["extracted_directory"] / "asset"
            extracted.write_bytes(b"user-edit")
            self.assertEqual(quiet_extract(source, out)[0], 1)
            self.assertEqual(extracted.read_bytes(), b"user-edit")
            self.assertEqual((source / "__APP__.wxapkg").read_bytes(), original)

    def test_source_and_output_separation(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            with self.assertRaises(ValueError):
                quiet_extract(source, source / "output")

    def test_other_appid_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "wx0000000000000000"
            source.mkdir()
            (source / "__APP__.wxapkg").write_bytes(package([("/asset", b"abc")]))
            with self.assertRaisesRegex(ValueError, "another AppID"):
                quiet_extract(source, base / "evidence")

    def test_portable_aliases_and_reserved_paths(self):
        for names in [("/A.txt", "/a.txt"), ("/é.txt", "/e\u0301.txt"), ("/A", "/a/b"), ("/CON.txt",), ("/x. ",), ("/a|b",)]:
            with self.subTest(names=names), self.assertRaises(ValueError):
                tool.parse_package(package([(name, b"x") for name in names]))

    def test_limits(self):
        raw = package([("/a", b"123"), ("/b", b"123")])
        for limits in ({"max_files": 1}, {"max_file_bytes": 2}, {"max_output_bytes": 5}):
            with self.subTest(limits=limits), self.assertRaisesRegex(ValueError, "resource limit"):
                tool.parse_package(raw, **limits)

    def test_scan_error_is_reported(self):
        errors = []
        def walk(root, followlinks, onerror):
            onerror(PermissionError(13, "Permission denied", str(root / "blocked")))
            yield str(root), [], ["one.wxapkg"]
        with patch.object(tool.os, "walk", walk):
            found = tool.find_packages(Path("synthetic"), errors)
        self.assertEqual(len(found), 1)
        self.assertEqual(errors[0]["kind"], "PermissionError")

    def test_manifest_escape_and_symlink_parent_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            source, out = base / "source", base / "evidence"
            source.mkdir()
            (source / "__APP__.wxapkg").write_bytes(package([("/asset", b"abc")]))
            quiet_extract(source, out)
            manifest = tool.load_manifest(out)
            manifest["packages"][0]["decoded"] = "../escape"
            tool.save_json(out / "package-manifest.json", manifest)
            with self.assertRaises(ValueError):
                tool.load_manifest(out)
            target = base / "outside"
            target.mkdir()
            try:
                (out / "link").symlink_to(target, target_is_directory=True)
            except OSError:
                self.skipTest("Symlink creation requires OS permission")
            with self.assertRaises(ValueError):
                tool.safe_path(out, "link/new")

    def test_lock_and_parser_fingerprint(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            source, out = base / "source", base / "evidence"
            source.mkdir()
            (source / "__APP__.wxapkg").write_bytes(package([("/asset", b"abc")]))
            quiet_extract(source, out)
            (out / ".extract.lock").write_text("synthetic-lock")
            with self.assertRaisesRegex(ValueError, "locked"):
                quiet_extract(source, out)
            (out / ".extract.lock").unlink()
            manifest = tool.load_manifest(out)
            manifest["packages"][0]["parser_fingerprint"] = "old"
            tool.save_json(out / "package-manifest.json", manifest)
            _, updated = quiet_extract(source, out)
            self.assertFalse(updated["packages"][0]["reused_decoded"])

    def test_image_dimensions(self):
        self.assertEqual(tool.image_size(b"GIF89a" + struct.pack("<HH", 30, 40), ".gif"), [30, 40])
        jpeg = b"\xff\xd8\xff\xc0" + struct.pack(">HBHH", 7, 8, 40, 30)
        self.assertEqual(tool.image_size(jpeg, ".jpg"), [30, 40])
        webp = b"RIFF" + b"\0" * 4 + b"WEBPVP8X" + b"\0" * 8 + (29).to_bytes(3, "little") + (39).to_bytes(3, "little")
        self.assertEqual(tool.image_size(webp, ".webp"), [30, 40])

    def test_source_changes_fail_and_partial_scan_nonzero(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            source = base / "source"
            source.mkdir()
            original = package([("/asset", b"abc")])
            target = source / "__APP__.wxapkg"
            target.write_bytes(original)
            read = tool.bounded_read
            hits = []
            def changing(path, limit=tool.MAX_PACKAGE_BYTES):
                if path == target:
                    hits.append(path)
                    if len(hits) == 2:
                        return b"changed-while-reading"
                return read(path, limit)
            with patch.object(tool, "bounded_read", changing):
                status, manifest = quiet_extract(source, base / "changed")
            self.assertEqual(status, 1)
            self.assertIn("Source changed", manifest["packages"][0]["error"])
            self.assertEqual(target.read_bytes(), original)
            finder = tool.find_packages
            def partial(root, errors=None):
                result = finder(root, errors)
                errors.append({"path": str(root / "blocked"), "error": "Permission denied"})
                return result
            with patch.object(tool, "find_packages", partial):
                status, manifest = quiet_extract(source, base / "partial")
            self.assertEqual(status, 1)
            self.assertFalse(manifest["scan_complete"])
            self.assertEqual(manifest["verified_package_count"], 1)

    def test_missing_route_is_not_masked_by_neighbor_asset(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            source, out = base / "source", base / "evidence"
            source.mkdir()
            config = {"pages": ["pages/example/index"], "subPackages": [{"root": "pages/example"}]}
            (source / "__APP__.wxapkg").write_bytes(package([("/app.json", json.dumps(config).encode()), ("/pages/example/icon.png", b"synthetic")]))
            quiet_extract(source, out)
            with contextlib.redirect_stdout(io.StringIO()):
                tool.inventory(SimpleNamespace(out=str(out), version="source"))
            summary = json.loads((out / "inventory/source/summary.json").read_text())
            self.assertTrue(summary["declared_subpackages"][0]["indexed_path_present"])
            self.assertFalse(summary["declared_routes"][0]["indexed_code_present"])

    def test_coordinated_decoded_and_manifest_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            source, out = base / "source", base / "evidence"
            source.mkdir()
            original = package([("/asset", b"original")])
            (source / "__APP__.wxapkg").write_bytes(original)
            quiet_extract(source, out)
            manifest = tool.load_manifest(out)
            item = manifest["packages"][0]
            forged = package([("/asset", b"forged!!")])
            (out / item["decoded"]).write_bytes(forged)
            (out / item["extracted_directory"] / "asset").write_bytes(b"forged!!")
            item["decoded_sha256"] = tool.sha(forged)
            item["files"][0]["sha256"] = tool.sha(b"forged!!")
            tool.save_json(out / "package-manifest.json", manifest)
            status, rejected = quiet_extract(source, out)
            self.assertEqual(status, 1)
            self.assertIn("does not match the original source", rejected["packages"][0]["error"])
            self.assertEqual((source / "__APP__.wxapkg").read_bytes(), original)


def real_regression(manifest_path, version=None, output=None):
    reference = json.loads(Path(manifest_path).read_text())
    source = Path(reference.get("source") or Path(reference["packages"][0]["source"]).parent.parent)
    selected = str(version or reference.get("latest_version") or reference.get("latest_numeric_version_candidate"))
    original_hashes = {item["source"]: item.get("source_sha256", item.get("sha256")) for item in reference["packages"]}
    manager = contextlib.nullcontext(str(output)) if output else tempfile.TemporaryDirectory(prefix="miniapp-cache-check-")
    with manager as temporary:
        out = Path(temporary).resolve() if output else Path(temporary) / "evidence"
        result, current = quiet_extract(source, out, reference["appid"])
        if result != 0 or current["package_count"] != reference["package_count"]:
            raise AssertionError("Real package verification or reference package count differs")
        by_source = {item["source"]: item for item in current["packages"]}
        for old in reference["packages"]:
            new = by_source[old["source"]]
            assert new["source_sha256"] == old.get("source_sha256", old.get("sha256"))
            assert new["decoded_sha256"] == old.get("decoded_sha256", old.get("decrypted_sha256"))
            assert {(item["path"], item["size"], item["sha256"]) for item in new["files"]} == {
                (item["path"], item["size"], item["sha256"]) for item in old["files"]}
        result, reused = quiet_extract(source, out, reference["appid"])
        assert result == 0 and all(item["reused_decoded"] for item in reused["packages"])
        with contextlib.redirect_stdout(io.StringIO()):
            tool.inventory(SimpleNamespace(out=str(out), version=selected))
        summary = json.loads((out / "inventory" / selected / "summary.json").read_text())
        expected = [item for item in reference["packages"] if str(item.get("version_directory", item.get("version"))) == selected]
        assert summary["packages"] == len(expected)
        assert summary["files"] == sum(item["file_count"] for item in expected)
        assert all(tool.sha(Path(path).read_bytes()) == digest for path, digest in original_hashes.items())
        return {"real_packages": current["package_count"], "real_files": current["file_count"],
                "all_reference_hashes_equal": True, "incremental_reused_packages": len(reused["packages"]),
                "source_hashes_unchanged": True, "latest_inventory": summary}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-manifest", help="Optional previously verified real package manifest")
    parser.add_argument("--version", help="Explicit version to inventory; never assumes subpackages complete")
    parser.add_argument("--out", help="Optional new private regression evidence directory")
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(IntegrityTests)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    report = {"integrity_tests": result.testsRun, "passed": True}
    if args.case_manifest:
        report.update(real_regression(args.case_manifest, args.version, args.out))
    tool.emit(report)
