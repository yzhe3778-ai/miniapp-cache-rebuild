#!/usr/bin/env python3
"""Build a focused, private WeChat feature dossier from verified static evidence."""

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import sys

from cache_tool import load_manifest
from report_tool import atomic_write, digest, load_optional, safe_path


VERSION = "1.1.0"
MAX_BYTES = 64 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
GROUPS = ("modules", "styles", "configExpressions", "endpoints", "prompts", "timers", "behaviors")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def read_bounded(base, relative):
    path = safe_path(base, relative)
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("Missing or oversized evidence JSON")
    with path.open("rb") as handle:
        data = handle.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Evidence JSON exceeds size limit")
    return data


def read_verified(base, relative, expected, size=None):
    path = safe_path(base, relative)
    if not re.fullmatch(r"[a-f0-9]{64}", str(expected)):
        raise ValueError("Missing source digest")
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("Missing or oversized source artifact")
    with path.open("rb") as handle:
        data = handle.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES or digest(data) != expected or (size is not None and len(data) != size):
        raise ValueError("Source artifact hash or size mismatch")
    return data


def unresolved(value, pointer="", depth=0):
    if depth > 50:
        return [{"pointer": pointer, "reason": "inspection-depth-limit"}]
    result = []
    if isinstance(value, dict):
        if isinstance(value.get("unresolved"), str):
            result.append({"pointer": pointer, "reason": value["unresolved"]})
        for key, child in value.items():
            if key != "expression":
                result.extend(unresolved(child, pointer + "/" + str(key), depth + 1))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            result.extend(unresolved(child, pointer + "/" + str(index), depth + 1))
    return result


def summarize(group, item):
    """Keep bodies, prompt texts, URLs and credential values in original evidence."""
    if group == "modules":
        return {key: item.get(key) for key in ("name", "sha256", "extractedFile", "classification")}
    if group == "styles":
        return {key: item.get(key) for key in ("name", "kind", "rawFile", "browserFile", "adaptation")}
    if group == "configExpressions":
        return {"name": item.get("name"), "value_type": type(item.get("value")).__name__,
                "finalLength": item.get("finalLength"), "evaluation": item.get("evaluation")}
    if group == "endpoints":
        method = item.get("method")
        return {"evidence": item.get("evidence"),
                "method": method if method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "GET-default") else "unresolved",
                "headerNames": item.get("headerNames", []), "inputFieldNames": item.get("inputFieldNames", []),
                "serverImplementation": "not-recovered"}
    if group == "prompts":
        return {key: item.get(key) for key in ("kind", "purpose", "textSha256", "serverPromptRecovered")}
    if group == "timers":
        interval = item.get("intervalMilliseconds")
        return {"kind": item.get("kind"), "intervalMilliseconds": interval if isinstance(interval, (int, float)) else "unresolved"}
    return {key: item.get(key) for key in ("kind", "callee", "owner", "limitation")}


def observation_records(base, supplied, appid, version, query, known_ids):
    if supplied is None:
        return []
    if not isinstance(supplied, dict) or supplied.get("schema") != 1:
        raise ValueError("Expected observation schema 1")
    if supplied.get("appid") != appid or supplied.get("version") != version:
        raise ValueError("Observation AppID/version differs from selected scope")
    rows = supplied.get("observations")
    if not isinstance(rows, list) or len(rows) > 200:
        raise ValueError("Invalid observation list")
    result, seen, total = [], set(), 0
    for row in rows:
        if not isinstance(row, dict) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", str(row.get("id", ""))):
            raise ValueError("Invalid observation identifier")
        if row["id"] in seen:
            raise ValueError("Duplicate observation identifier")
        seen.add(row["id"])
        if row.get("query") != query:
            continue
        if row.get("origin") not in {"original-miniapp", "local-rebuild"}:
            raise ValueError("Observation origin must distinguish original and rebuild")
        if row.get("outcome") not in {"observed", "failed", "not-observed"}:
            raise ValueError("Invalid observation outcome")
        for field, maximum in (("action", 1000), ("result", 2000)):
            if not isinstance(row.get(field), str) or not row[field].strip() or len(row[field]) > maximum:
                raise ValueError("Observation requires bounded action and result descriptions")
        stamp = row.get("observed_at")
        if not isinstance(stamp, str) or datetime.fromisoformat(stamp.replace("Z", "+00:00")).utcoffset() is None:
            raise ValueError("Observation requires a timezone-aware timestamp")
        refs = row.get("static_evidence_ids", [])
        if not isinstance(refs, list) or any(not isinstance(ref, str) or ref not in known_ids for ref in refs):
            raise ValueError("Unknown static evidence reference")
        attachments = row.get("evidence")
        if not isinstance(attachments, list) or not attachments or len(attachments) > 20:
            raise ValueError("Observation requires bounded artifact attachments")
        verified = []
        for entry in attachments:
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                raise ValueError("Invalid observation attachment")
            total += len(read_verified(base, entry["path"], entry.get("sha256")))
            if total > MAX_TOTAL:
                raise ValueError("Observation attachments exceed byte limit")
            verified.append({"path": entry["path"], "sha256": entry["sha256"]})
        result.append({"id": row["id"], "origin": row["origin"], "outcome": row["outcome"],
                       "action": row["action"], "result": row["result"],
                       "observed_at": stamp, "authority": "manual-observation-with-artifact-readback",
                       "evidence": verified, "static_evidence_ids": refs,
                       "relationship": "manual-link-not-proven" if refs else "unlinked",
                       "limitation": "Attachment bytes and supplied linkage checked; action, screenshot semantics and equivalence require review."})
    return result


def build_feature(base, version, query, limit=40, observations=None):
    base = Path(base).expanduser().absolute()
    if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", version):
        raise ValueError("Invalid explicit version")
    if not isinstance(query, str) or not query.strip() or len(query) > 200:
        raise ValueError("Query must be a nonempty literal of at most 200 characters")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
        raise ValueError("Limit must be between 1 and 500")
    manifest_path = safe_path(base, "package-manifest.json")
    manifest_bytes = read_bounded(base, "package-manifest.json")
    manifest = load_manifest(base)
    if digest(manifest_path.read_bytes()) != digest(manifest_bytes):
        raise ValueError("Manifest changed during feature inspection")
    analysis_bytes = read_bounded(base, f"analysis/{version}/analysis.json")
    analysis = json.loads(analysis_bytes)
    if not isinstance(analysis, dict) or analysis.get("schema") != 1:
        raise ValueError("Run static analysis first")
    manifest_hash = digest(manifest_bytes)
    if analysis.get("sourceManifestSha256") != manifest_hash:
        raise ValueError("Analysis is stale: manifest changed; rerun analyze.cjs")
    if analysis.get("appid") != manifest["appid"] or analysis.get("version") != version:
        raise ValueError("Analysis AppID/version differs from selected scope")
    packages = [p for p in manifest["packages"] if p["version_directory"] == version]
    if not packages:
        raise ValueError("Selected version is absent")
    sources, total = {}, 0
    for pkg in packages:
        if pkg.get("status") != "verified":
            continue
        for entry in pkg["files"]:
            data = read_verified(base, pkg["extracted_directory"] + "/" + entry["relative_path"], entry["sha256"], entry["size"])
            total += len(data)
            if total > MAX_TOTAL:
                raise ValueError("Feature input exceeds byte limit")
            sources[(pkg["name"], entry["relative_path"], entry["sha256"])] = pkg
    binding = {"appid": manifest["appid"], "version": version, "sourceManifestSha256": manifest_hash,
               "analysisSha256": digest(analysis_bytes),
               "analyzerVersion": analysis.get("analyzerVersion")}
    needle, records, matches = query.strip().casefold(), [], set()
    for group in GROUPS:
        items = analysis.get(group, [])
        if not isinstance(items, list):
            raise ValueError("Invalid analysis collection")
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise ValueError("Invalid analysis record")
            origins = item.get("sources", []) if group == "modules" else [item.get("source")]
            if not isinstance(origins, list) or not origins:
                raise ValueError("Static record lacks provenance")
            for origin in origins:
                if not isinstance(origin, dict) or origin.get("version") != version:
                    raise ValueError("Invalid static source scope")
                key = (origin.get("package"), origin.get("relativePath"), origin.get("fileSha256"))
                if key not in sources:
                    raise ValueError("Static source is not in verified selected manifest")
                if origin.get("packageId") is not None and origin["packageId"] != sources[key].get("source_sha256"):
                    raise ValueError("Static source package digest mismatch")
            matched = needle in canonical(item).casefold()
            if group == "modules":
                code = read_verified(base, f"analysis/{version}/" + item["extractedFile"], item["sha256"])
                total += len(code)
                if total > MAX_TOTAL:
                    raise ValueError("Feature input exceeds byte limit")
                matched = matched or needle in code.decode("utf-8").casefold()
            identifier = digest(canonical({"binding": binding, "group": group, "record": item}).encode())
            row = {"evidence_id": identifier, "category": group, "record_pointer": f"/{group}/{index}",
                   "authority": "static-inference" if group in {"configExpressions", "endpoints"} else "static-observation",
                   "module": item.get("name") if group == "modules" else item.get("module"),
                   "sources": origins, "summary": summarize(group, item),
                   "unknowns": unresolved(item), "runtime_execution": "unverified"}
            records.append((row, matched))
            if matched and row["module"]:
                matches.add(row["module"])
    candidates = []
    for row, matched in records:
        if matched or row["module"] in matches:
            row["match_basis"] = "literal" if matched else "same-module-name-candidate"
            candidates.append(row)
    observed = observation_records(base, observations, manifest["appid"], version, query,
                                   {r["evidence_id"] for r in candidates})
    selected = candidates[:limit]
    warnings = analysis.get("warnings", [])
    if not isinstance(warnings, list):
        raise ValueError("Invalid analysis warning collection")
    unknowns = [{"reason": "original-runtime-unverified", "next": "Observe the selected action in the original miniapp."},
                {"reason": "backend-not-recovered", "next": "Record client contracts; request server materials only if needed."},
                {"reason": "original-wxml-not-recovered", "next": "Review compiled views and same-state screenshots."}]
    if any(r["origin"] == "original-miniapp" for r in observed):
        unknowns[0] = {"reason": "original-observation-semantics-unverified", "next": "Review the supplied original action and attachments."}
    if not candidates:
        unknowns.append({"reason": "no-literal-match-in-analyzed-scope", "next": "Try actual page/module/function names; inspect missing packages. Feature absence is unknown."})
    if "behaviors" not in analysis:
        unknowns.append({"reason": "legacy-analysis-without-behavior-index", "next": "Rerun the current analyze.cjs to index storage, export, navigation and state calls."})
    core = {"schema": 1, "toolVersion": VERSION, "visibility": "private", "binding": binding, "query": query,
            "candidates": selected, "observations": observed, "unknowns": unknowns,
            "coverage": {"matching_candidates": len(candidates), "returned_candidates": len(selected),
                         "omitted_candidates": len(candidates) - len(selected), "analysis_warning_count": len(warnings),
                         "static": "partial" if warnings or "behaviors" not in analysis or len(selected) < len(candidates) or any(p.get("status") != "verified" for p in packages) else "complete-within-literal-matches",
                         "product_equivalence": "unverified"},
            "limitations": ["Literal and module-name matches are navigation aids, not an executed call graph.",
                            "Same-name module variants stay separate; attachment hashes do not prove original or rebuild behavior.",
                            "Private dossier only; raw code, prompt text and URL values stay in referenced source evidence."]}
    return {"evidence_id": digest(canonical(core).encode()), **core}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="Verified evidence root")
    parser.add_argument("--version", required=True)
    parser.add_argument("--query", required=True, help="Literal page, function or feature search")
    parser.add_argument("--limit", type=int, default=40)
    parser.add_argument("--observations", help="Optional observation JSON relative to evidence root")
    args = parser.parse_args()
    try:
        observations = load_optional(args.out, args.observations, None) if args.observations else None
        if args.observations and observations is None:
            raise ValueError("Observation file missing")
        result = build_feature(args.out, args.version, args.query, args.limit, observations)
        relative = f"features/{args.version}/{result['evidence_id']}.json"
        target = safe_path(args.out, relative)
        data = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode()
        if target.exists():
            if target.read_bytes() != data:
                raise ValueError("Existing feature output was modified; preserve it")
        else:
            atomic_write(target, data)
        print(json.dumps({"status": "recorded", "path": relative, "evidence_id": result["evidence_id"], "coverage": result["coverage"]}))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"status": "error", "message": str(error)}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
