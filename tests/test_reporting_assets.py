"""Synthetic report, opt-in download and file-readback tests; never access network."""

import hashlib
import io
import json
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import asset_tool
import report_tool
import verify_artifact


def png(width=2, height=2):
    def chunk(kind, payload):
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress((b"\0" + b"\0" * width * 3) * height)) + chunk(b"IEND", b"")


def public_dns(host, port, **kwargs):
    return [(2, 1, 6, "", ("93.184.216.34", port))]


class Response(io.BytesIO):
    def __init__(self, data=b"", status=200, headers=None):
        super().__init__(data)
        self.status = status
        self.headers = headers or {"Content-Type": "image/png", "Content-Length": str(len(data))}

    def getheader(self, name, default=None):
        return self.headers.get(name, default)


class Connection:
    def close(self):
        pass


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.manifest = {"schema": 2, "appid": "wx1111111111111111", "scan_complete": True, "scan_errors": [], "source": "/" + "Users/alice/SECRET/home",
                         "packages": [{"source": "/" + "Users/alice/secret.wxapkg", "version_directory": "57", "name": "main.wxapkg", "source_sha256": "a" * 64,
                                       "status": "verified", "file_count": 1, "extracted_directory": "packages/test/files", "files": [{"relative_path":"app.js", "size":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}], **{flag: True for flag in report_tool.CHECK_FLAGS}}]}
        report_tool.save_json(self.base / "package-manifest.json", self.manifest)
        self.inventory = self.base / "inventory" / "57"
        self.inventory.mkdir(parents=True)
        report_tool.save_json(self.inventory / "summary.json", {"declared_subpackages": [{"root": "/" + "Users/alice/SECRET", "indexed_path_present": False}]})
        report_tool.save_json(self.inventory / "assets.json", [{"path": "secret.png", "sha256": "b" * 64, "origin": "https://" + "alice:SECRET@cdn.example/a?token=SECRET"}])
        report_tool.save_json(self.inventory / "code-map.json", {"configs": [{"config": {"token": "SECRET", "user": "/" + "Users/alice"}}], "modules": [{"module": "SECRET.js"}]})
        report_tool.save_json(self.inventory / "clues.json", [{"host": "SECRET", "path": "/SECRET", "value": "SECRET"}])
        analysis = self.base / "analysis" / "57"
        analysis.mkdir(parents=True)
        report_tool.save_json(analysis / "analysis.json", {"endpoints": [{"url": "https://api.example?token=SECRET"}], "prompts": [{"text": "SECRET"}], "warnings": ["SECRET"], "coverage": {"missingPages": ["SECRET"]}})

    def tearDown(self):
        self.temp.cleanup()

    def test_public_allowlist_excludes_nested_secrets_in_all_outputs(self):
        annotations = {"identity": {"status": "verified", "secret": "SECRET"}, "navigation": [{"url": "SECRET"}],
                       "keyNames": ["API_KEY", "SECRET", "https://SECRET"], "viewport": {"width": 390, "note": "SECRET"},
                       "acceptance": [{"status": "passed", "category": "SECRET", "note": "SECRET"}]}
        report = report_tool.build_report(self.base, "57", annotations=annotations)
        target = self.base / "report"
        report_tool.write_report(report, target)
        for path in target.iterdir():
            text = path.read_text(encoding="utf-8-sig")
            self.assertNotIn("SECRET", text)
            self.assertNotIn("alice", text)
            self.assertNotIn("https://", text)
            self.assertNotIn("/Users", text)
        self.assertEqual(report["identity"]["status"], "unknown")
        self.assertEqual(report["acceptance"][0]["status"], "unverified")
        self.assertEqual(report["counts"]["endpoint_candidates"], 1)

    def test_declared_route_missing_despite_subpackage_asset(self):
        report_tool.save_json(self.inventory / "summary.json", {"declared_subpackages": [{"root":"sub", "indexed_path_present":True}], "declared_routes":[{"route":"sub/index", "indexed_code_present":False}]})
        report = report_tool.build_report(self.base, "57")
        self.assertEqual(report["counts"]["missing_indexed_pages"], 1)
        self.assertTrue(any(row["id"] == "page-001" and row["status"] == "missing" for row in report["gaps"]))

    def test_malformed_identity_annotations_rejected(self):
        with self.assertRaises(ValueError):
            report_tool.build_report(self.base, "57", annotations={"identity":"spoof"})

    def test_private_retains_evidence(self):
        report = report_tool.build_report(self.base, "57", "private")
        self.assertIn("SECRET", json.dumps(report["private_evidence"]))

    def test_four_levels_do_not_claim_product_complete(self):
        report = report_tool.build_report(self.base, "57")
        self.assertEqual(report["completeness"]["cache_scan"]["status"], "verified")
        self.assertEqual(report["completeness"]["package_contents"]["status"], "verified")
        self.assertEqual(report["completeness"]["dependency_coverage"]["status"], "partial")
        self.assertEqual(report["completeness"]["reconstructed_product"]["status"], "unknown")
        self.assertTrue(all(row["status"] == "unknown" for row in report["configuration_requirements"]))

    def test_partial_scan_and_hash_flags(self):
        self.manifest["scan_errors"] = [{"error": "SECRET permission"}]
        self.manifest["packages"][0]["body_bytes_covered"] = False
        self.manifest["packages"][0]["status"] = "failed"
        report_tool.save_json(self.base / "package-manifest.json", self.manifest)
        report = report_tool.build_report(self.base, "57")
        self.assertEqual(report["completeness"]["cache_scan"]["status"], "partial")
        self.assertEqual(report["completeness"]["package_contents"]["status"], "partial")

    def test_empty_manifest_not_complete(self):
        report_tool.save_json(self.base / "package-manifest.json", {"schema": 2, "appid": "wx1111111111111111", "packages": []})
        with self.assertRaisesRegex(ValueError, "absent"):
            report_tool.build_report(self.base, "57")

    def test_manual_acceptance_requires_real_readback(self):
        path = self.base / "proof.json"
        path.write_text('{"restored":true}')
        evidence = [{"path": "proof.json", "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}]
        report = report_tool.build_report(self.base, "57", annotations={"identity": {"status": "verified", "evidence": evidence}, "acceptance": [{"category": "reload_restore", "status": "passed", "evidence": evidence}]})
        self.assertEqual(report["identity"]["status"], "manual_verified")
        self.assertEqual(report["acceptance"][0]["status"], "manual_verified")
        self.assertEqual(report["completeness"]["reconstructed_product"]["status"], "partial")
        path.write_text("changed")
        changed = report_tool.build_report(self.base, "57", annotations={"acceptance": [{"status": "passed", "evidence": evidence}]})
        self.assertEqual(changed["acceptance"][0]["status"], "unverified")

    def test_acceptance_refuses_absolute_and_traversal_evidence(self):
        for rel in ("../proof", "/" + "Users/alice/SECRET", "a/../proof"):
            report = report_tool.build_report(self.base, "57", annotations={"acceptance": [{"status": "passed", "evidence": [{"path": rel, "sha256": "a" * 64}]}]})
            self.assertEqual(report["acceptance"][0]["status"], "unverified")

    def test_atomic_outputs_refuse_symlink_and_existing_temp(self):
        destination = self.base / "external"
        destination.mkdir()
        (self.base / "linked").symlink_to(destination, target_is_directory=True)
        with self.assertRaises(ValueError):
            report_tool.write_report(report_tool.build_report(self.base, "57"), self.base / "linked")
        (self.base / "x.json.tmp").write_text("do not replace")
        with self.assertRaises(ValueError):
            report_tool.save_json(self.base / "x.json", {})
        self.assertEqual((self.base / "x.json.tmp").read_text(), "do not replace")

    def test_report_preflights_nested_file_symlink(self):
        target = self.base / "reports"
        target.mkdir()
        (target / "report.md").symlink_to(self.base / "package-manifest.json")
        with self.assertRaises(ValueError):
            report_tool.write_report(report_tool.build_report(self.base, "57"), target)
        self.assertFalse((target / "report.json").exists())

    def test_snapshot_diff_preserves_missing_reason_without_raw_error(self):
        before = report_tool.snapshot(self.base)
        self.manifest["packages"][0]["source_sha256"] = "b" * 64
        self.manifest["scan_errors"] = [{"error": "SECRET"}]
        report_tool.save_json(self.base / "package-manifest.json", self.manifest)
        after = report_tool.snapshot(self.base)
        delta = report_tool.diff_snapshots(before, after)
        self.assertEqual(len(delta["changed"]), 1)
        self.assertEqual(delta["after_missing_reason"], "scan_failed")
        self.assertNotIn("SECRET", json.dumps(delta))
        self.assertNotIn("alice", json.dumps(after))

    def test_malicious_snapshot_identifiers_refused(self):
        with self.assertRaises(ValueError):
            report_tool.diff_snapshots({"schema": 1, "packages": [{"id": "SECRET"}]}, {"schema": 1, "packages": []})


class AssetTests(unittest.TestCase):
    def fetch(self, responses, url="https://cdn.example/a.png", **options):
        queue = list(responses)
        calls = []
        def opener(parts, address, timeout):
            calls.append((parts.hostname, address))
            return queue.pop(0), Connection()
        return asset_tool.fetch(url, {"cdn.example"}, resolver=public_dns, opener=opener, sleeper=lambda _: None, **options), calls

    def test_signature_mime_dimensions(self):
        (data, info, metrics), calls = self.fetch([Response(png())])
        self.assertEqual(info["dimensions"], [2, 2])
        self.assertEqual(info["mime"], "image/png")
        self.assertEqual(calls, [("cdn.example", "93.184.216.34")])

    def test_rejects_auth_signed_query_http_and_other_host(self):
        for url in ("https://" + "user:SECRET@cdn.example/a.png", "https://cdn.example/a.png?token=SECRET", "https://cdn.example/a.png#SECRET", "http://cdn.example/a.png", "https://other.example/a.png"):
            with self.assertRaises(asset_tool.AssetError):
                asset_tool.valid_url(url, {"cdn.example"}, public_dns)

    def test_private_dns_refused(self):
        def private_dns(host, port, **kwargs):
            return [(2, 1, 6, "", ("127.0.0.1", port))]
        with self.assertRaisesRegex(asset_tool.AssetError, "private_or_local"):
            asset_tool.valid_url("https://cdn.example/a.png", {"cdn.example"}, private_dns)

    def test_mixed_public_private_dns_refused(self):
        def mixed_dns(host, port, **kwargs):
            return public_dns(host, port) + [(2, 1, 6, "", ("10.0.0.1", port))]
        with self.assertRaises(asset_tool.AssetError):
            asset_tool.valid_url("https://cdn.example/a.png", {"cdn.example"}, mixed_dns)

    def test_redirect_revalidated(self):
        for location in ("https://other.example/b.png", "http://cdn.example/b.png", "https://cdn.example/b.png?signature=SECRET"):
            with self.assertRaises(asset_tool.AssetError):
                self.fetch([Response(status=302, headers={"Location": location})])
        (_, info, metrics), calls = self.fetch([Response(status=302, headers={"Location": "/b.png"}), Response(png())])
        self.assertEqual(metrics["redirects"], 1)
        self.assertEqual(len(calls), 2)

    def test_redirect_limit(self):
        responses = [Response(status=302, headers={"Location": "/b.png"}) for _ in range(4)]
        with self.assertRaisesRegex(asset_tool.AssetError, "redirect_limit"):
            self.fetch(responses)

    def test_wrong_mime_and_invalid_signature(self):
        for response in (Response(png(), headers={"Content-Type": "image/jpeg"}), Response(b"html", headers={"Content-Type": "image/png"}), Response(png(), headers={"Content-Type": "text/html"})):
            with self.assertRaises(asset_tool.AssetError):
                self.fetch([response])

    def test_declared_and_streaming_size_limits(self):
        for response in (Response(png()), Response(png(), headers={"Content-Type": "image/png"})):
            with self.assertRaises(asset_tool.AssetError):
                self.fetch([response], max_bytes=30)

    def test_retry_is_bounded(self):
        (_, _, metrics), calls = self.fetch([Response(status=503), Response(png())], retries=1)
        self.assertEqual(metrics["retries"], 1)
        self.assertEqual(len(calls), 2)
        with self.assertRaises(asset_tool.AssetError):
            self.fetch([Response(status=503), Response(status=503)], retries=1)

    def test_encoded_response_and_length_mismatch(self):
        for headers in ({"Content-Type": "image/png", "Content-Encoding": "gzip"}, {"Content-Type": "image/png", "Content-Length": "1"}):
            with self.assertRaises(asset_tool.AssetError):
                self.fetch([Response(png(), headers=headers)])

    def test_download_readback_and_failure_record(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            spec = {"allowed_hosts": ["cdn.example"], "assets": [{"url": "https://cdn.example/a.png", "expected_dimensions": [2, 2]}, {"url": "https://cdn.example/b.png?token=SECRET"}]}
            def fetcher(url, allowed, **kwargs):
                asset_tool.valid_url(url, allowed, public_dns)
                return png(), verify_artifact.image_info(png()), {"redirects": 0, "retries": 0}
            with patch("asset_tool.time.sleep"):
                records = asset_tool.download_list(spec, root / "new", fetcher=fetcher)
            self.assertEqual(records[0]["status"], "verified")
            self.assertEqual(hashlib.sha256((root / "new" / records[0]["file"]).read_bytes()).hexdigest(), records[0]["sha256"])
            self.assertEqual(records[1]["status"], "failed")
            self.assertNotIn("SECRET", (root / "new" / "asset-manifest.json").read_text())
            with self.assertRaises(asset_tool.AssetError):
                asset_tool.download_list(spec, root / "new", fetcher=fetcher)

    def test_download_hash_and_dimensions_mismatch(self):
        for expected in ({"expected_sha256": "f" * 64}, {"expected_dimensions": [10, 10]}):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve()
                spec = {"allowed_hosts": ["cdn.example"], "assets": [{"url": "https://cdn.example/a.png", **expected}]}
                def fetcher(url, allowed, **kwargs):
                    return png(), verify_artifact.image_info(png()), {"redirects": 0, "retries": 0}
                record = asset_tool.download_list(spec, root / "new", fetcher=fetcher)[0]
                self.assertEqual(record["status"], "failed")
                self.assertFalse(list((root / "new").glob("*.png")))


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()

    def tearDown(self):
        self.temp.cleanup()

    def test_json_real_readback_hash_and_required_fields(self):
        path = self.root / "backup.json"
        path.write_text('{"format":"study-backup","version":1,"votes":[]}')
        expected = hashlib.sha256(path.read_bytes()).hexdigest()
        schema = {"type": "object", "required": ["format", "version", "votes"], "properties": {"format": {"enum": ["study-backup"]}, "version": {"enum": [1]}, "votes": {"type": "array", "items": {"type": "object", "required": ["platform", "yes"], "properties": {"yes": {"type": "boolean"}}}}}}
        result = verify_artifact.verify(path, "json", expected, ["version"], schema=schema)
        self.assertTrue(result["restore_schema_checked"])
        self.assertIn("requires separate UI", result["scope"])
        path.write_text('{"format":"different","version":1,"votes":[]}')
        with self.assertRaises(verify_artifact.InvalidArtifact):
            verify_artifact.verify(path, "json", schema=schema)
        with self.assertRaises(verify_artifact.InvalidArtifact):
            verify_artifact.verify(path, "json", expected)

    def test_restore_schema_rejects_bad_nested_field_and_unknown_keyword(self):
        path = self.root / "backup.json"
        path.write_text('{"votes":[{"yes":"true"}]}')
        with self.assertRaises(verify_artifact.InvalidArtifact):
            verify_artifact.verify(path, "json", schema={"type": "object", "properties": {"votes": {"type": "array", "items": {"type": "object", "properties": {"yes": {"type": "boolean"}}}}}})
        with self.assertRaises(verify_artifact.InvalidArtifact):
            verify_artifact.verify(path, "json", schema={"$ref": "https://SECRET"})

    def test_invalid_json_nonfinite_and_missing_key(self):
        path = self.root / "x.json"
        for content in ('{"x":NaN}', '{"x":Infinity}', '{"x":1e400}', '{"x":1,"x":2}', '{}'):
            path.write_text(content)
            with self.assertRaises(ValueError):
                verify_artifact.verify(path, "json", required_fields=["required"])

    def test_csv_readback_and_schema(self):
        path = self.root / "export.csv"
        path.write_text("platform,score\nCodex,8\n")
        result = verify_artifact.verify(path, "csv", required_fields=["platform", "score"])
        self.assertEqual(result["row_count"], 1)
        for content in ("score,score\n1,2\n", "platform,score\nCodex\n", "platform,score\nCodex,8,extra\n"):
            path.write_text(content)
            with self.assertRaises(verify_artifact.InvalidArtifact):
                verify_artifact.verify(path, "csv", required_fields=["score"])

    def test_image_dimensions_and_hash(self):
        path = self.root / "export.png"
        path.write_bytes(png(3, 4))
        result = verify_artifact.verify(path, "image", expected_dimensions=[3, 4])
        self.assertEqual(result["dimensions"], [3, 4])
        with self.assertRaises(verify_artifact.InvalidArtifact):
            verify_artifact.verify(path, "image", expected_dimensions=[4, 3])

    def test_tmp_system_alias_supported_but_nested_symlink_refused(self):
        path = self.root / "a.json"
        path.write_text('{}')
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(verify_artifact.InvalidArtifact):
            verify_artifact.verify(alias / "a.json", "json")
        self.assertEqual(verify_artifact.verify(path, "json")["status"], "verified")

    def test_truncated_or_corrupt_png_refused(self):
        path = self.root / "bad.png"
        for data in (png()[:33], png()[:-12], png()[:29] + b"bad!" + png()[33:]):
            path.write_bytes(data)
            with self.assertRaises(verify_artifact.InvalidArtifact):
                verify_artifact.verify(path, "image")

    def test_symlink_and_size_refused(self):
        path = self.root / "x.json"
        path.write_text('{}')
        linked = self.root / "linked"
        linked.symlink_to(path)
        with self.assertRaises(verify_artifact.InvalidArtifact):
            verify_artifact.verify(linked, "json")
        with self.assertRaises(verify_artifact.InvalidArtifact):
            verify_artifact.verify(path, "json", max_bytes=1)


if __name__ == "__main__":
    unittest.main()
