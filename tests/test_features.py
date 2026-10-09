"""Synthetic feature dossiers; no original miniapp actions or network requests."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import feature_tool as tool
from report_tool import CHECK_FLAGS, digest


class FeatureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.source = self.base / "packages/main/files/app-service.js"
        self.source.parent.mkdir(parents=True)
        self.source.write_text("define('pages/home.js',function(){wx.setStorageSync('schedule',[]);});")
        self.manifest = {"schema": 2, "appid": "wx0000000000000000", "packages": [
            {"name": "main.wxapkg", "version_directory": "1", "status": "verified", "source_sha256": "a" * 64,
             "extracted_directory": "packages/main/files", "file_count": 1,
             "files": [{"relative_path": "app-service.js", "size": self.source.stat().st_size,
                        "sha256": digest(self.source.read_bytes())}], **{flag: True for flag in CHECK_FLAGS}}]}
        self.write("package-manifest.json", self.manifest)
        self.origin = {"package": "main.wxapkg", "packageId": "a" * 64, "version": "1",
                       "relativePath": "app-service.js", "fileSha256": digest(self.source.read_bytes()), "line": 1}
        self.code = self.base / "analysis/1/modules/example.js"
        self.code.parent.mkdir(parents=True)
        self.code.write_text(self.source.read_text())
        self.analysis = {"schema": 1, "analyzerVersion": "synthetic-1.1.0", "appid": self.manifest["appid"], "version": "1",
                         "sourceManifestSha256": digest((self.base / "package-manifest.json").read_bytes()),
                         "modules": [{"name": "pages/home.js", "sources": [self.origin], "sha256": digest(self.code.read_bytes()),
                                      "extractedFile": "modules/example.js"}],
                         "styles": [], "configExpressions": [], "endpoints": [], "prompts": [], "timers": [],
                         "behaviors": [{"source": self.origin, "module": "pages/home.js", "kind": "storage",
                                        "callee": "wx.setStorageSync", "owner": "persistEntry"}], "warnings": []}
        self.write_analysis()

    def tearDown(self):
        self.temp.cleanup()

    def write(self, relative, value):
        path = self.base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def write_analysis(self):
        self.write("analysis/1/analysis.json", self.analysis)

    def build(self, query="schedule", **kwargs):
        return tool.build_feature(self.base, "1", query, **kwargs)

    def observations(self, origin="original-miniapp", outcome="observed"):
        proof = self.base / "proof.json"
        proof.write_text('{"synthetic":true}')
        return {"schema": 1, "appid": self.manifest["appid"], "version": "1", "observations": [
            {"id": "save-original", "query": "schedule", "origin": origin, "outcome": outcome,
             "action": "Synthetic observation fixture; no actual miniapp action", "result": "Fixture attachment only",
             "observed_at": "2026-10-09T15:00:00+08:00", "static_evidence_ids": [self.build()["candidates"][0]["evidence_id"]],
             "evidence": [{"path": "proof.json", "sha256": digest(proof.read_bytes())}]}]}

    def test_literal_match_related_module_and_stable_bound_identifiers(self):
        first = self.build()
        self.assertEqual(first, self.build())
        self.assertEqual([r["category"] for r in first["candidates"]], ["modules", "behaviors"])
        self.assertEqual(first["candidates"][1]["match_basis"], "same-module-name-candidate")
        self.assertTrue(all(r["runtime_execution"] == "unverified" for r in first["candidates"]))
        self.assertNotIn("wx.setStorageSync('schedule'", json.dumps(first))
        self.assertEqual(first["binding"]["analysisSha256"], digest((self.base / "analysis/1/analysis.json").read_bytes()))
        self.analysis["warnings"].append({"code": "new-warning"})
        self.write_analysis()
        self.assertNotEqual(first["evidence_id"], self.build()["evidence_id"])

    def test_stale_manifest_and_modified_original_source_fail(self):
        self.source.write_text("modified")
        with self.assertRaisesRegex(ValueError, "mismatch"):
            self.build()
        self.write("package-manifest.json", {**self.manifest, "new": True})
        with self.assertRaisesRegex(ValueError, "stale"):
            self.build()

    def test_generated_module_modified_fails(self):
        self.code.write_text("modified")
        with self.assertRaisesRegex(ValueError, "mismatch"):
            self.build()

    def test_wrong_scope_and_unverified_source_cannot_enter_dossier(self):
        for field, value in (("appid", "wx1111111111111111"), ("version", "2")):
            original = self.analysis[field]
            self.analysis[field] = value
            self.write_analysis()
            with self.assertRaisesRegex(ValueError, "scope"):
                self.build()
            self.analysis[field] = original
        self.origin["relativePath"] = "missing.js"
        self.write_analysis()
        with self.assertRaisesRegex(ValueError, "verified selected manifest"):
            self.build()

    def test_no_match_is_unknown_not_feature_absent(self):
        result = self.build("never-present-feature")
        self.assertEqual(result["coverage"]["matching_candidates"], 0)
        self.assertEqual(result["coverage"]["product_equivalence"], "unverified")
        self.assertIn("no-literal-match-in-analyzed-scope", [row["reason"] for row in result["unknowns"]])

    def test_explicit_omissions_and_distinct_same_name_variants(self):
        self.analysis["modules"].append({**copy.deepcopy(self.analysis["modules"][0]), "classification": "different-variant-fixture"})
        self.write_analysis()
        result = self.build(limit=1)
        self.assertEqual(result["coverage"]["matching_candidates"], 3)
        self.assertEqual(result["coverage"]["omitted_candidates"], 2)
        self.assertEqual(result["coverage"]["static"], "partial")
        identifiers = [r["evidence_id"] for r in self.build()["candidates"]]
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_unresolved_and_backend_boundary_are_preserved(self):
        self.analysis["endpoints"] = [{"source": self.origin, "module": "pages/home.js", "method": {"unresolved": "unknown-method"},
                                       "url": {"unresolved": "dynamic-host", "expression": "secretRawExpression"}}]
        self.write_analysis()
        row = next(r for r in self.build()["candidates"] if r["category"] == "endpoints")
        self.assertEqual(row["summary"]["serverImplementation"], "not-recovered")
        self.assertIn("dynamic-host", [u["reason"] for u in row["unknowns"]])
        self.assertNotIn("secretRawExpression", json.dumps(row))

    def test_original_rebuild_and_failed_observations_remain_separate(self):
        supplied = self.observations()
        rebuilt = copy.deepcopy(supplied["observations"][0])
        rebuilt.update(id="save-rebuild", origin="local-rebuild", outcome="failed")
        supplied["observations"].append(rebuilt)
        result = self.build(observations=supplied)
        self.assertEqual([r["origin"] for r in result["observations"]], ["original-miniapp", "local-rebuild"])
        self.assertEqual(result["observations"][1]["outcome"], "failed")
        self.assertEqual(result["coverage"]["product_equivalence"], "unverified")
        self.assertEqual(result["observations"][0]["relationship"], "manual-link-not-proven")

    def test_observation_hash_scope_and_reference_are_checked(self):
        supplied = self.observations()
        variants = []
        for field, value in (("appid", "wx1111111111111111"), ("version", "2")):
            variant = copy.deepcopy(supplied)
            variant[field] = value
            variants.append(variant)
        variant = copy.deepcopy(supplied)
        variant["observations"][0]["static_evidence_ids"] = ["forged"]
        variants.append(variant)
        variant = copy.deepcopy(supplied)
        variant["observations"][0]["evidence"][0]["sha256"] = "b" * 64
        variants.append(variant)
        for variant in variants:
            with self.assertRaises(ValueError):
                self.build(observations=variant)

    def test_observation_paths_symlinks_and_naive_timestamp_fail(self):
        supplied = self.observations()
        (self.base / "linked.json").symlink_to(self.base / "proof.json")
        for path in ("../proof.json", "/absolute/proof.json", "linked.json"):
            variant = copy.deepcopy(supplied)
            variant["observations"][0]["evidence"][0]["path"] = path
            with self.assertRaises(ValueError):
                self.build(observations=variant)
        supplied["observations"][0]["observed_at"] = "2026-10-09T15:00:00"
        with self.assertRaisesRegex(ValueError, "timezone"):
            self.build(observations=supplied)

    def test_legacy_analysis_is_partial_and_limit_is_bounded(self):
        del self.analysis["behaviors"]
        self.write_analysis()
        self.assertEqual(self.build()["coverage"]["static"], "partial")
        for limit in (0, 501, True):
            with self.assertRaises(ValueError):
                self.build(limit=limit)

    def test_cli_reuses_identical_output_and_preserves_modified_output(self):
        script = Path(tool.__file__)
        command = [sys.executable, str(script), "--out", str(self.base), "--version", "1", "--query", "schedule"]
        first = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(subprocess.run(command, capture_output=True, timeout=20).returncode, 0)
        output = self.base / json.loads(first.stdout)["path"]
        output.write_text("user edit")
        failed = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(output.read_text(), "user edit")


if __name__ == "__main__":
    unittest.main()
