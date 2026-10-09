#!/usr/bin/env python3
"""Generate conservative private/public reports from local miniapp evidence."""

import argparse
import csv
import hashlib
import io
import json
import re
import sys
from pathlib import Path


STATES = {"verified", "partial", "unknown", "missing", "failed", "manual_verified", "unverified"}
KEY_NAMES = {"APPID", "APPSECRET", "API_BASE_URL", "API_KEY", "MEMBER_API_KEY",
             "SESSION_SECRET", "DATABASE_URL", "MODEL_API_KEY", "MODEL_NAME", "SUBSCRIPTION_TEMPLATE_ID",
             "AD_UNIT_ID", "PAYMENT_SECRET", "PAYMENT_PRODUCT_ID", "ALLOWED_ORIGINS"}
CHECK_FLAGS = ("index_bytes_consumed", "body_bytes_covered", "source_unchanged", "extracted_hashes_verified")
CATEGORIES = [
    ("frontend", "UI / pages / states", "Missing packages, reference screenshots and source-state matrix", "Local cache and supplied materials"),
    ("assets", "Original and remote assets", "Original dimensions, font licenses, explicit asset URL list", "Package or authorized asset owner"),
    ("live_data", "Live read API", "Read-only API contract, API_BASE_URL, authorized API key", "Service owner or authorized account"),
    ("identity", "Login and session", "Session contract, test account; own AppID/AppSecret for native delivery", "Own platform console and service owner"),
    ("business", "Business write API", "Votes, ratings and other write permissions plus test environment", "Service owner"),
    ("backend", "Backend implementation", "Server source, collector, reset confirmation rules, scheduler", "Original server project or independent implementation"),
    ("database", "Data and history", "Data schema, migrations and authorized fixtures", "Service owner"),
    ("ai", "AI inference", "Actual prompts, runner, model, weights and configuration", "Original inference project"),
    ("subscriptions", "Native notifications", "Own template identifiers, user authorization and send service", "Own platform console"),
    ("advertising", "Native advertising", "Own ad units, eligibility and completion callback", "Own platform console"),
    ("payments", "Membership and payment", "Own products, signing configuration, order and entitlement service", "Own payment console and backend"),
    ("tools", "MCP / Skills dependencies", "Confirmed dependency list; no dependency inferred from keyword alone", "Original server project"),
    ("platform", "Delivery environment", "Target runtime, capability adapters and local startup instructions", "Project maintainer"),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(base, relative):
    original_base = Path(base).expanduser().absolute()
    if original_base.is_symlink():
        raise ValueError("Refusing symlink evidence root")
    base = original_base.resolve()
    rel = Path(relative)
    if rel.is_absolute() or not rel.parts or any(p in {".", ".."} or "\\" in p or "\x00" in p for p in rel.parts):
        raise ValueError("Expected a safe relative path")
    if base.is_symlink():
        raise ValueError("Refusing symlink evidence root")
    for parent in [base, *base.parents]:
        if parent.is_symlink():
            raise ValueError("Refusing symlink ancestor")
    result = base / rel
    for parent in [result, *result.parents]:
        if parent == base.parent:
            break
        if parent.is_symlink():
            raise ValueError("Refusing symlink path")
    if not result.resolve().is_relative_to(base.resolve()):
        raise ValueError("Path outside evidence root")
    return result


def atomic_write(path, data):
    path = Path(path).absolute()
    safe_path(path.parent, path.name)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("Temporary output already exists")
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
        temporary.replace(path)
    finally:
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()


def save_json(path, value):
    atomic_write(path, (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode())


def load_optional(base, relative, default):
    path = safe_path(base, relative)
    if not path.exists():
        return default
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("Evidence JSON exceeds size limit")
    with path.open("rb") as handle:
        data = handle.read(64 * 1024 * 1024 + 1)
    if len(data) > 64 * 1024 * 1024:
        raise ValueError("Evidence JSON exceeds size limit")
    return json.loads(data.decode("utf-8"))


def manifest_at(base):
    try:
        from cache_tool import load_manifest
    except ImportError:
        result = load_optional(base, "package-manifest.json", {})
    else:
        result = load_manifest(Path(base))
    if not isinstance(result, dict) or not isinstance(result.get("packages", []), list):
        raise ValueError("Invalid manifest object")
    return result


def nonnegative(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def version_id(value):
    return value if isinstance(value, str) and re.fullmatch(r"[0-9]{1,16}", value) else "version-" + digest(str(value).encode())[:12]


def annotation_evidence(base, item):
    """Validate files, never interpret a screenshot as proof of its UI contents."""
    evidence = item.get("evidence", []) if isinstance(item, dict) else []
    if not isinstance(evidence, list) or not evidence:
        return False, 0
    checked = 0
    for entry in evidence:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            return False, checked
        expected = entry.get("sha256")
        if not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
            return False, checked
        try:
            path = safe_path(base, entry["path"])
            if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024 or digest(path.read_bytes()) != expected:
                return False, checked
        except (OSError, ValueError):
            return False, checked
        checked += 1
    return True, checked


def acceptance_rows(base, annotations):
    supplied = annotations.get("acceptance", [])
    if not isinstance(supplied, list):
        raise ValueError("annotations.acceptance must be an array")
    if not supplied:
        return [{"id": f"acceptance-{index:03d}", "category": category, "status": "unknown", "evidence_files_readback": 0,
                 "verification": "No supplied UI acceptance evidence"}
                for index, category in enumerate(("visual", "core_flow", "save", "reload_restore", "export_readback", "errors"), 1)]
    result = []
    for index, item in enumerate(supplied, 1):
        if not isinstance(item, dict):
            raise ValueError("Acceptance item must be an object")
        category = item.get("category")
        if category not in {"visual", "core_flow", "save", "reload_restore", "export_readback", "errors", "other"}:
            category = "other"
        valid, count = annotation_evidence(base, item)
        requested = item.get("status")
        status = "manual_verified" if requested in {"verified", "passed", "manual_verified"} and valid else (
            requested if requested in {"failed", "partial", "missing"} else "unverified")
        result.append({"id": f"acceptance-{index:03d}", "category": category, "status": status,
                       "evidence_files_readback": count,
                       "verification": "Human supplied result; artifact hash readback passed" if status == "manual_verified" else
                       "Acceptance not verified by this tool"})
    return result


def dependency_gaps(summary, analysis):
    result = []
    roots = summary.get("declared_subpackages", [])
    if not isinstance(roots, list):
        roots = []
    for index, root in enumerate(roots, 1):
        if not isinstance(root, dict):
            continue
        present = root.get("indexed_path_present") is True
        result.append({"id": f"subpackage-{index:03d}", "category": "subpackage",
                       "status": "partial" if present else "missing",
                       "reason": "Indexed files present; runtime visit and dependency review required" if present else "Declared package has no indexed files"})
    routes = summary.get("declared_routes", [])
    for index, route in enumerate(routes if isinstance(routes, list) else [], 1):
        if not isinstance(route, dict):
            continue
        present = route.get("indexed_code_present") is True
        result.append({"id": f"page-{index:03d}", "category": "page",
                       "status": "partial" if present else "missing",
                       "reason": "Indexed page code present; runtime states remain unverified" if present else "Declared page has no indexed page code"})
    coverage = analysis.get("coverage", {})
    if isinstance(coverage, dict):
        for key in ("missingPages", "missingSubpackages", "missingAssets", "unresolvedImports", "unsupportedStyles"):
            values = coverage.get(key, [])
            count = len(values) if isinstance(values, list) else nonnegative(values)
            if count:
                result.append({"id": key, "category": "dependency", "status": "missing", "count": count,
                               "reason": "Static analysis reports missing or unsupported dependencies"})
    result.extend([
        {"id": "remote-assets", "category": "assets", "status": "unknown", "reason": "Package scan cannot prove all remote or high-resolution assets exist"},
        {"id": "server-implementation", "category": "backend", "status": "unknown", "reason": "Client package does not establish backend source availability"},
        {"id": "server-prompts", "category": "ai", "status": "unknown", "reason": "Client prompt candidates do not establish server inference prompts"},
    ])
    return result


def build_report(base, version, visibility="public", annotations=None):
    base = Path(base).expanduser().resolve()
    if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", version):
        raise ValueError("Version must be a single safe directory identifier")
    annotations = annotations or {}
    if not isinstance(annotations, dict):
        raise ValueError("Annotations must be an object")
    if not isinstance(annotations.get("identity", {}), dict):
        raise ValueError("annotations.identity must be an object")
    manifest = manifest_at(base)
    prefix = f"inventory/{version}/"
    summary = load_optional(base, prefix + "summary.json", {})
    assets = load_optional(base, prefix + "assets.json", [])
    code_map = load_optional(base, prefix + "code-map.json", {})
    clues = load_optional(base, prefix + "clues.json", [])
    analysis = load_optional(base, f"analysis/{version}/analysis.json", {})
    if not all(isinstance(obj, typ) for obj, typ in [(summary, dict), (assets, list), (code_map, dict), (clues, list), (analysis, dict)]):
        raise ValueError("Invalid inventory or analysis data structure")
    chosen = [pkg for pkg in manifest.get("packages", []) if isinstance(pkg, dict) and pkg.get("version_directory") == version]
    if not chosen:
        raise ValueError("Selected version is absent from manifest")
    scan_errors = manifest.get("scan_errors", manifest.get("errors", []))
    if not isinstance(scan_errors, list):
        raise ValueError("Manifest scan errors must be an array")
    scanned = manifest.get("scan_complete") is True and not scan_errors
    checked = sum(pkg.get("status") == "verified" and all(pkg.get(flag) is True for flag in CHECK_FLAGS) for pkg in chosen)
    identity_valid, identity_files = annotation_evidence(base, annotations.get("identity", {}))
    identity_status = "manual_verified" if annotations.get("identity", {}).get("status") == "verified" and identity_valid else "unknown"
    acceptance = acceptance_rows(base, annotations)
    gaps = dependency_gaps(summary, analysis)
    keys = annotations.get("keyNames", [])
    keys = sorted(set(key for key in keys if isinstance(key, str) and key in KEY_NAMES)) if isinstance(keys, list) else []
    requirements = [{"id": category, "capability": capability, "status": "unknown", "required_material": material,
                     "provided_by": owner, "key_names": ", ".join(keys) if category in {"live_data", "identity", "ai", "payments"} else "",
                     "acceptance": "Contract and authorized real behavior must be independently validated"}
                    for category, capability, material, owner in CATEGORIES]
    counts = {
        "packages_selected": len(chosen), "packages_integrity_verified": checked,
        "indexed_files": sum(nonnegative(pkg.get("file_count")) for pkg in chosen),
        "asset_entries": len(assets), "unique_asset_hashes": len({a.get("sha256") for a in assets if isinstance(a, dict) and re.fullmatch(r"[a-f0-9]{64}", str(a.get("sha256", "")))}),
        "module_definitions": len(code_map.get("modules", [])) if isinstance(code_map.get("modules"), list) else 0,
        "style_entries": len(analysis.get("styles", [])) if isinstance(analysis.get("styles"), list) else 0,
        "endpoint_candidates": len(analysis.get("endpoints", [])) if isinstance(analysis.get("endpoints"), list) else 0,
        "prompt_candidates": len(analysis.get("prompts", [])) if isinstance(analysis.get("prompts"), list) else 0,
        "declared_pages": len(summary.get("declared_routes", [])) if isinstance(summary.get("declared_routes"), list) else 0,
        "missing_indexed_pages": sum(gap["category"] == "page" and gap["status"] == "missing" for gap in gaps),
        "unique_business_modules": nonnegative(summary.get("unique_business_modules")),
        "scan_errors": len(scan_errors), "annotation_evidence_files": identity_files,
        "visit_records": len(annotations.get("visits", [])) if isinstance(annotations.get("visits"), list) else 0,
    }
    report = {"schema": 1, "visibility": visibility, "version": version_id(version), "identity": {"status": identity_status},
              "counts": counts, "analysis_status": "available" if analysis else "not_run",
              "completeness": {
                  "cache_scan": {"status": "verified" if scanned else "partial" if scan_errors else "unknown", "scope": "Declared local roots only; absence is not proof of all online content"},
                  "package_contents": {"status": "verified" if chosen and checked == len(chosen) else "partial" if chosen else "unknown", "scope": "Recorded extraction integrity flags, not a fresh re-extraction"},
                  "dependency_coverage": {"status": "partial" if chosen else "unknown", "scope": "Static package presence, remote dependencies and backend remain unresolved"},
                  "reconstructed_product": {"status": "partial" if any(a["status"] == "manual_verified" for a in acceptance) else "unknown", "scope": "Manual acceptance applies only to supplied states; no automatic 1:1 claim"},
              },
              "gaps": gaps, "acceptance": acceptance, "configuration_requirements": requirements,
              "viewport": {key: value for key, value in annotations.get("viewport", {}).items() if key in {"width", "height", "dpr", "hostZoom"} and isinstance(value, (int, float)) and not isinstance(value, bool) and 0 < value <= 20000} if isinstance(annotations.get("viewport"), dict) else {},
              "privacy": "Public output uses a fixed aggregate allowlist; no raw strings, source locations, endpoints or prompt text are published",
              "limits": ["No backend source recovery inferred", "No UI behavior is automatically proved by file existence", "Prompt and URL candidates require semantic review"]}
    if visibility == "private":
        report["private_evidence"] = {"manifest": manifest, "summary": summary, "assets": assets, "code_map": code_map, "clues": clues, "analysis": analysis, "annotations": annotations}
    return report


def csv_bytes(rows):
    if not rows:
        return b""
    fields = list(dict.fromkeys(key for row in rows for key in row))
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fields)
    writer.writeheader()
    for row in rows:
        # Prevent spreadsheet formula evaluation for private strings too.
        writer.writerow({key: "'" + value if isinstance(value, str) and value.startswith(("=", "+", "-", "@")) else value for key, value in row.items()})
    return stream.getvalue().encode("utf-8-sig")


def markdown(report):
    lines = ["# Miniapp evidence report", "", f"Visibility: {report['visibility']}; logical version: {report['version']}", "",
             "## Four independent completeness levels", "", "| Level | Status | Scope |", "| --- | --- | --- |"]
    lines += [f"| {level} | {item['status']} | {item['scope']} |" for level, item in report["completeness"].items()]
    lines += ["", "## Counts", ""] + [f"- {key}: {value}" for key, value in report["counts"].items()]
    lines += ["", "## Missing materials", "", "| ID | State | Reason |", "| --- | --- | --- |"]
    lines += [f"| {item['id']} | {item['status']} | {item['reason']} |" for item in report["gaps"]]
    lines += ["", "## Acceptance", "", "| ID | Category | State | Artifact readback |", "| --- | --- | --- | --- |"]
    lines += [f"| {item['id']} | {item['category']} | {item['status']} | {item['evidence_files_readback']} |" for item in report["acceptance"]]
    lines += ["", "Configuration inputs and providers are listed in config-requirements.csv. Secret values must stay in private server configuration.", "", report["privacy"], ""]
    return "\n".join(lines)


def write_report(report, target):
    target = Path(target).absolute()
    safe_path(target.parent, target.name)
    target.mkdir(parents=True, exist_ok=True)
    for name in ("report.json", "report.md", "gaps.csv", "acceptance.csv", "config-requirements.csv"):
        safe_path(target, name)
    save_json(target / "report.json", report)
    atomic_write(target / "report.md", markdown(report).encode())
    for name, rows in [("gaps.csv", report["gaps"]), ("acceptance.csv", report["acceptance"]), ("config-requirements.csv", report["configuration_requirements"])]:
        atomic_write(target / name, csv_bytes(rows))


def snapshot(base):
    manifest = manifest_at(base)
    packages = []
    for pkg in manifest.get("packages", []):
        if not isinstance(pkg, dict):
            continue
        identifier = digest((str(pkg.get("version_directory")) + "/" + str(pkg.get("name"))).encode())[:20]
        packages.append({"id": identifier, "sha256": pkg.get("source_sha256") if re.fullmatch(r"[a-f0-9]{64}", str(pkg.get("source_sha256", ""))) else None,
                         "status": "verified" if pkg.get("status") == "verified" else "unverified"})
    return {"schema": 1, "packages": packages, "scan_complete": manifest.get("scan_complete") is True,
            "scan_error_count": len(manifest.get("scan_errors", [])) if isinstance(manifest.get("scan_errors", []), list) else 0,
            "missing_reason": "scan_failed" if manifest.get("scan_errors") else "scope_not_confirmed" if manifest.get("scan_complete") is not True else "local_snapshot_only"}


def diff_snapshots(before, after):
    for snap in (before, after):
        if not isinstance(snap, dict) or snap.get("schema") != 1 or not isinstance(snap.get("packages"), list):
            raise ValueError("Expected a report_tool evidence snapshot")
        for pkg in snap["packages"]:
            if not isinstance(pkg, dict) or not re.fullmatch(r"[a-f0-9]{20}", str(pkg.get("id", ""))):
                raise ValueError("Invalid snapshot package identifier")
            if pkg.get("sha256") is not None and not re.fullmatch(r"[a-f0-9]{64}", str(pkg["sha256"])):
                raise ValueError("Invalid snapshot package hash")
    old = {pkg["id"]: pkg for pkg in before["packages"]}
    new = {pkg["id"]: pkg for pkg in after["packages"]}
    valid_reasons = {"scan_failed", "scope_not_confirmed", "local_snapshot_only"}
    return {"schema": 1, "added": sorted(new.keys() - old.keys()), "removed": sorted(old.keys() - new.keys()),
            "changed": sorted(key for key in new.keys() & old.keys() if new[key].get("sha256") != old[key].get("sha256")),
            "before_missing_reason": before.get("missing_reason") if before.get("missing_reason") in valid_reasons else "unknown",
            "after_missing_reason": after.get("missing_reason") if after.get("missing_reason") in valid_reasons else "unknown",
            "scope": "Changes in known local snapshots do not prove online package completeness"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="Evidence directory (diff: result JSON path)")
    parser.add_argument("--version")
    parser.add_argument("--visibility", choices=["private", "public"], default="public")
    parser.add_argument("--annotations")
    parser.add_argument("--report-out")
    parser.add_argument("--snapshot-out", help="Create sanitized snapshot instead of report")
    parser.add_argument("--before", help="Snapshot JSON before cache visits")
    parser.add_argument("--after", help="Snapshot JSON after cache visits")
    args = parser.parse_args()
    try:
        if args.before or args.after:
            if not args.before or not args.after:
                raise ValueError("Both before and after snapshots are required")
            result = diff_snapshots(json.loads(Path(args.before).read_text()), json.loads(Path(args.after).read_text()))
            save_json(Path(args.out), result)
        elif args.snapshot_out:
            result = snapshot(Path(args.out))
            save_json(Path(args.snapshot_out), result)
        else:
            if not args.version:
                raise ValueError("Report requires --version")
            annotations = json.loads(Path(args.annotations).read_text()) if args.annotations else {}
            result = build_report(args.out, args.version, args.visibility, annotations)
            target = Path(args.report_out) if args.report_out else safe_path(Path(args.out), f"reports/{args.version}/{args.visibility}")
            write_report(result, target)
        print(json.dumps({"status": "written", "visibility": args.visibility, "scope": "Evidence report only; no original application or API executed"}))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"status": "failed", "error": type(error).__name__}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
