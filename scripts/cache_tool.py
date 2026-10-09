#!/usr/bin/env python3
"""Read-only cache discovery, verified wxapkg extraction, and static inventory."""

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
import unicodedata
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit


APPID = re.compile(r"wx[0-9a-f]{16}")
VERSION = "1.0.0"
SCHEMA = 2
PARSER_FINGERPRINT = "wxapkg-v2-portable-paths-full-coverage"
MAX_PACKAGE_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024 * 1024
MAX_FILES = 100000
RESERVED = re.compile(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$", re.I)
MEDIA = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".avif", ".bmp", ".mp3", ".mp4", ".wav"}
FONTS = {".ttf", ".otf", ".woff", ".woff2"}
TEXT = {".js", ".json", ".wxml", ".wxss", ".css", ".html"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def emit(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def save_json(path, value):
    path = Path(path)
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise ValueError(f"Refusing symlink output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".json-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def relative_name(value):
    if not isinstance(value, str) or not value or value.startswith("/"):
        raise ValueError(f"Expected relative POSIX path: {value!r}")
    parts = value.split("/")
    if any(char in value for char in '\\:<>"|?*') or any(ord(char) < 32 for char in value):
        raise ValueError(f"Unsafe portable path: {value!r}")
    if any(part in {"", ".", ".."} or part.endswith((".", " ")) or RESERVED.fullmatch(part) for part in parts):
        raise ValueError(f"Unsafe portable path component: {value!r}")
    return value


def safe_path(base, relative):
    base = Path(base).resolve()
    relative_name(relative)
    candidate = base
    for part in relative.split("/"):
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError(f"Refusing symlink in evidence path: {relative}")
    if not candidate.resolve().is_relative_to(base):
        raise ValueError(f"Path escapes evidence root: {relative}")
    return candidate


def bounded_read(path, limit=MAX_PACKAGE_BYTES):
    if path.is_symlink() or path.stat().st_size > limit:
        raise ValueError(f"Symlink or resource limit exceeded: {path}")
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"Resource limit exceeded: {path}")
    return data


def write_verified(path, data, base):
    if not path.is_relative_to(base):
        raise ValueError(f"Unsafe output path: {path}")
    path = safe_path(base, path.relative_to(base).as_posix())
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if not path.is_file() or sha(path.read_bytes()) != sha(data):
            raise ValueError(f"Existing output differs; use a new output directory: {path}")
    else:
        with path.open("xb") as handle:
            handle.write(data)
    if sha(path.read_bytes()) != sha(data):
        raise ValueError(f"Readback hash mismatch: {path}")


def find_packages(root, errors=None):
    root = Path(root)
    errors = errors if errors is not None else []
    if root.is_symlink():
        errors.append({"path": str(root), "error": "Symlink root skipped"})
        return []
    if root.is_file():
        return [root] if root.suffix == ".wxapkg" and not root.is_symlink() else []
    result = []
    def failed(error):
        errors.append({"path": str(error.filename or root), "error": str(error), "kind": type(error).__name__})
    for directory, subdirs, files in os.walk(root, followlinks=False, onerror=failed):
        for name in subdirs + files:
            child = Path(directory) / name
            if child.is_symlink():
                errors.append({"path": str(child), "error": "Symlink skipped"})
        subdirs[:] = [name for name in subdirs if not (Path(directory) / name).is_symlink()]
        result.extend(Path(directory) / name for name in files
                      if name.endswith(".wxapkg") and not (Path(directory) / name).is_symlink())
    return sorted(result)


def default_roots():
    home = Path.home()
    roots = list((home / "Library/Containers").glob(
        "com.tencent.xinWeChat*/Data/Documents/app_data/radium/users/*/applet/packages"))
    if os.environ.get("APPDATA"):
        roots.extend((Path(os.environ["APPDATA"]) / "Tencent/xwechat/radium/users").glob("*/applet/packages"))
    old = home / "Documents/WeChat Files/Applet"
    if old.is_dir():
        roots.append(old)
    return sorted(set(path.resolve() for path in roots if path.is_dir()))


def discover(args):
    roots = [Path(path).expanduser().resolve() for path in args.root] if args.root else default_roots()
    packages, errors, seen = [], [], set()
    for root in roots:
        if not root.exists():
            errors.append({"root": str(root), "error": "Root does not exist"})
            continue
        for path in find_packages(root, errors):
            appid = next((part for part in reversed(path.parts) if APPID.fullmatch(part)), None)
            if args.appid and appid != args.appid:
                continue
            if path in seen:
                continue
            seen.add(path)
            try:
                stat = path.stat()
                with path.open("rb") as handle:
                    header = handle.read(14)
                packages.append({"appid": appid, "version_directory": path.parent.name,
                                 "path": str(path), "bytes": stat.st_size,
                                 "mtime_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                                 "format_hint": "V1MMWX" if header.startswith(b"V1MMWX") else
                                 "plain-wxapkg" if len(header) == 14 and header[0] == 190 and header[13] == 237 else "unknown"})
            except OSError as error:
                errors.append({"path": str(path), "error": str(error)})
    emit({"roots_checked": [str(root) for root in roots], "packages": packages, "errors": errors,
          "scan_complete": bool(roots) and not errors, "status": "partial" if errors else "complete" if roots else "no-roots",
          "scope": "Package metadata only; identity and cache completeness still require verification."})
    return 1 if errors or not roots else 0


def decode(data, appid):
    if data.startswith(b"V1MMWX"):
        if len(data) < 1030:
            raise ValueError("Truncated V1MMWX package")
        try:
            from Crypto.Cipher import AES
        except ImportError as error:
            raise ValueError("V1MMWX requires the existing pycryptodome dependency (Crypto.Cipher.AES)") from error
        key = hashlib.pbkdf2_hmac("sha1", appid.encode("ascii"), b"saltiest", 1000, 32)
        prefix = AES.new(key, AES.MODE_CBC, b"the iv: 16 bytes").decrypt(data[6:1030])
        return prefix[:1023] + bytes(byte ^ ord(appid[-2]) for byte in data[1030:]), "V1MMWX"
    if len(data) >= 14 and data[0] == 190 and data[13] == 237:
        return data, "plain-wxapkg"
    raise ValueError("Unsupported package format; snapshot retained")


def parse_package(raw, max_files=MAX_FILES, max_file_bytes=MAX_FILE_BYTES, max_output_bytes=MAX_OUTPUT_BYTES):
    if len(raw) < 18 or raw[0] != 190 or raw[13] != 237:
        raise ValueError("Invalid decoded header; verify AppID and format")
    _, index_size, body_size = struct.unpack_from(">III", raw, 1)
    body_start = 14 + index_size
    if index_size < 4 or len(raw) != body_start + body_size:
        raise ValueError("Invalid declared index/body length")
    count = struct.unpack_from(">I", raw, 14)[0]
    if count > max_files:
        raise ValueError("File count resource limit exceeded")
    if count > (index_size - 4) // 13:
        raise ValueError("Impossible file count")
    cursor, entries, names = 18, [], set()
    for _ in range(count):
        if cursor + 4 > body_start:
            raise ValueError("Truncated file index")
        length = struct.unpack_from(">I", raw, cursor)[0]
        cursor += 4
        if not length or cursor + length + 8 > body_start:
            raise ValueError("Index entry exceeds boundary")
        name = raw[cursor:cursor + length].decode("utf-8")
        cursor += length
        offset, size = struct.unpack_from(">II", raw, cursor)
        cursor += 8
        cleaned = name[1:] if name.startswith("/") else name
        relative_name(cleaned)
        canonical = unicodedata.normalize("NFC", cleaned).casefold()
        if canonical in names:
            raise ValueError(f"Duplicate normalized archive path: {name}")
        names.add(canonical)
        if size > max_file_bytes:
            raise ValueError(f"File resource limit exceeded: {name}")
        if offset < body_start or offset + size > len(raw):
            raise ValueError(f"Invalid file bounds: {name}")
        entries.append({"path": name, "relative_path": cleaned, "offset": offset,
                        "size": size, "sha256": sha(raw[offset:offset + size])})
    if cursor != body_start:
        raise ValueError("Unconsumed index bytes")
    if sum(entry["size"] for entry in entries) > max_output_bytes:
        raise ValueError("Expanded output resource limit exceeded")
    for name in names:
        if any(str(parent) in names for parent in PurePosixPath(name).parents if str(parent) != "."):
            raise ValueError(f"Archive file/directory collision: {name}")
    position, shared, gaps = body_start, [], []
    for entry in sorted(entries, key=lambda item: item["offset"]):
        if entry["offset"] > position:
            gaps.append([position, entry["offset"]])
        elif entry["offset"] < position and entry["size"]:
            shared.append(entry["path"])
        position = max(position, entry["offset"] + entry["size"])
    if position < len(raw):
        gaps.append([position, len(raw)])
    if gaps:
        raise ValueError(f"Unexplained body gaps: {gaps[:10]}; full extraction not verified")
    return entries, shared


def load_manifest(out):
    out = Path(out).expanduser().resolve()
    manifest = json.loads(bounded_read(safe_path(out, "package-manifest.json"), 64 * 1024 * 1024))
    if manifest.get("schema") not in {1, 2} or not APPID.fullmatch(str(manifest.get("appid", ""))):
        raise ValueError("Unsupported manifest schema or invalid AppID; legacy case manifests are test references only")
    if not isinstance(manifest.get("packages"), list):
        raise ValueError("Invalid manifest packages")
    scope_path = safe_path(out, "scope.json")
    if scope_path.exists():
        scope = json.loads(bounded_read(scope_path))
        if scope.get("appid") != manifest["appid"] or scope.get("source") != manifest.get("source"):
            raise ValueError("Manifest identity differs from scope marker")
    package_keys = set()
    for item in manifest["packages"]:
        relative_name(item["version_directory"])
        relative_name(item["name"])
        key = (item["version_directory"], item["name"])
        if key in package_keys:
            raise ValueError("Duplicate version/package identity; select one coherent cache root")
        package_keys.add(key)
        for field in ("snapshot", "decoded", "extracted_directory"):
            if field in item:
                safe_path(out, item[field])
        for field in ("source_sha256", "decoded_sha256"):
            if field in item and not re.fullmatch(r"[0-9a-f]{64}", str(item[field])):
                raise ValueError(f"Invalid digest: {field}")
        if item.get("status") == "verified":
            if not all(item.get(field) is True for field in ("index_bytes_consumed", "body_bytes_covered", "extracted_hashes_verified", "source_unchanged")):
                raise ValueError("Verified package lacks integrity evidence")
            if not isinstance(item.get("files"), list) or len(item["files"]) > MAX_FILES:
                raise ValueError("Invalid manifest file list")
            names = set()
            total = 0
            for entry in item["files"]:
                relative_name(entry["relative_path"])
                canonical = unicodedata.normalize("NFC", entry["relative_path"]).casefold()
                if canonical in names:
                    raise ValueError("Portable manifest path collision")
                names.add(canonical)
                if not isinstance(entry["size"], int) or isinstance(entry["size"], bool) or entry["size"] < 0 or entry["size"] > MAX_FILE_BYTES:
                    raise ValueError("Invalid manifest file size")
                if not re.fullmatch(r"[0-9a-f]{64}", str(entry["sha256"])):
                    raise ValueError("Invalid manifest file digest")
                total += entry["size"]
                safe_path(out, item["extracted_directory"] + "/" + entry["relative_path"])
            if total > MAX_OUTPUT_BYTES or len(names) > MAX_FILES or len(names) != item["file_count"]:
                raise ValueError("Invalid manifest count or resource limit")
            for name in names:
                if any(str(parent) in names for parent in PurePosixPath(name).parents if str(parent) != "."):
                    raise ValueError("Manifest file/directory collision")
    return manifest


def extract(args):
    if not APPID.fullmatch(str(args.appid)):
        raise ValueError("Invalid AppID")
    source, out = Path(args.source).expanduser().resolve(), Path(args.out).expanduser().resolve()
    if not source.exists():
        raise ValueError("Source does not exist")
    if out.is_relative_to(source) or source.is_relative_to(out):
        raise ValueError("Source and output must be separate, non-nested locations")
    errors = []
    files = find_packages(source, errors)
    if not files:
        raise ValueError("No wxapkg files found" + ("; scan errors: " + json.dumps(errors, ensure_ascii=False) if errors else ""))
    for file in files:
        relative_name(file.parent.name)
        relative_name(file.name)
        ancestor_id = next((part for part in reversed(file.parts) if APPID.fullmatch(part)), None)
        if ancestor_id and ancestor_id != args.appid:
            raise ValueError("Source contains another AppID; select a target-only source directory")
    if len({(file.parent.name, file.name) for file in files}) != len(files):
        raise ValueError("Ambiguous duplicate version/package names; select one account/cache root")
    marker = out / "scope.json"
    identity = {"appid": args.appid, "source": str(source), "schema": SCHEMA}
    if out.exists() and any(out.iterdir()):
        existing = json.loads(bounded_read(marker)) if marker.is_file() and not marker.is_symlink() else {}
        if existing.get("appid") != args.appid or existing.get("source") != str(source) or existing.get("schema") not in {1, 2}:
            raise ValueError("Output belongs to another task; choose an empty directory")
    out.mkdir(parents=True, exist_ok=True)
    lock = safe_path(out, ".extract.lock")
    try:
        with lock.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps({"pid": os.getpid(), "started_at_utc": datetime.now(timezone.utc).isoformat()}))
    except FileExistsError as error:
        raise ValueError("Output is locked; inspect the owner and resume in a new directory or remove only a confirmed stale lock") from error
    try:
        save_json(marker, identity)
        return extract_locked(args, source, out, files, errors, identity)
    finally:
        lock.unlink(missing_ok=True)


def extract_locked(args, source, out, files, errors, identity):
    previous_path = out / "package-manifest.json"
    previous = load_manifest(out) if previous_path.exists() else {"packages": []}
    old = {(item["source"], item["source_sha256"]): item for item in previous["packages"] if item["status"] == "verified"}
    results = []
    total_output = 0
    for file in files:
        item = {"source": str(file), "version_directory": file.parent.name, "name": file.name, "status": "failed"}
        try:
            data = bounded_read(file, getattr(args, "max_package_bytes", MAX_PACKAGE_BYTES))
            digest = sha(data)
            folder = out / "packages" / (sha(str(file).encode())[:16] + "-" + digest[:16])
            item.update(source_sha256=digest, source_bytes=len(data),
                        mtime_utc=datetime.fromtimestamp(file.stat().st_mtime, timezone.utc).isoformat(),
                        snapshot=str((folder / "original.wxapkg").relative_to(out)))
            write_verified(folder / "original.wxapkg", data, out)
            cached = old.get((str(file), digest))
            if cached and cached.get("parser_fingerprint") == PARSER_FINGERPRINT:
                raw = bounded_read(safe_path(out, cached["decoded"]), getattr(args, "max_package_bytes", MAX_PACKAGE_BYTES))
                if sha(raw) != cached["decoded_sha256"]:
                    raise ValueError("Cached decoded package was modified; use a new output directory")
                canonical, format_name = decode(data, args.appid)
                if raw != canonical:
                    raise ValueError("Cached decoded package does not match the original source; use a new output directory")
            else:
                raw, format_name = decode(data, args.appid)
                cached = None
            write_verified(folder / "decoded.wxapkg", raw, out)
            entries, shared = parse_package(raw, getattr(args, "max_files", MAX_FILES),
                                            getattr(args, "max_file_bytes", MAX_FILE_BYTES),
                                            getattr(args, "max_output_bytes", MAX_OUTPUT_BYTES) - total_output)
            total_output += sum(entry["size"] for entry in entries)
            for entry in entries:
                write_verified(folder / "files" / entry["relative_path"], raw[entry["offset"]:entry["offset"] + entry["size"]], out)
            if sha(bounded_read(file, getattr(args, "max_package_bytes", MAX_PACKAGE_BYTES))) != digest:
                raise ValueError("Source changed during extraction; rerun after cache settles")
            item.update(status="verified", format=format_name, reused_decoded=bool(cached), parser_fingerprint=PARSER_FINGERPRINT,
                        decoded=str((folder / "decoded.wxapkg").relative_to(out)), decoded_sha256=sha(raw),
                        decoded_bytes=len(raw), extracted_directory=str((folder / "files").relative_to(out)),
                        file_count=len(entries), index_bytes_consumed=True, body_bytes_covered=True,
                        source_unchanged=True, extracted_hashes_verified=True,
                        shared_byte_range_entries=shared, files=entries)
        except (OSError, ValueError, struct.error) as error:
            item["error"] = str(error)
        results.append(item)
    versions = sorted({item["version_directory"] for item in results})
    manifest = {**identity, "audited_at_utc": datetime.now(timezone.utc).isoformat(),
                "package_count": len(results), "verified_package_count": sum(item["status"] == "verified" for item in results),
                "file_count": sum(item.get("file_count", 0) for item in results), "versions": versions,
                "latest_numeric_version_candidate": max(versions, key=int) if all(version.isdigit() for version in versions) else None,
                "tool_version": VERSION, "parser_fingerprint": PARSER_FINGERPRINT,
                "scan_complete": not errors, "scan_errors": errors,
                "scope": "Discovered local packages only; declared subpackages and remote assets require separate checks.",
                "packages": results}
    save_json(previous_path, manifest)
    emit({key: value for key, value in manifest.items() if key != "packages"})
    return 0 if not errors and manifest["verified_package_count"] == len(results) else 1


def image_size(data, extension):
    if extension == ".png" and data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) >= 24:
        return list(struct.unpack_from(">II", data, 16))
    if extension == ".gif" and data[:6] in {b"GIF87a", b"GIF89a"} and len(data) >= 10:
        return list(struct.unpack_from("<HH", data, 6))
    if extension in {".jpg", ".jpeg"} and data[:2] == b"\xff\xd8":
        cursor = 2
        while cursor + 4 <= len(data):
            if data[cursor] != 255:
                break
            marker = data[cursor + 1]
            cursor += 2
            if marker == 255:
                cursor -= 1
                continue
            if marker in {0xd8, 0xd9} or 0xd0 <= marker <= 0xd7:
                continue
            length = int.from_bytes(data[cursor:cursor + 2], "big")
            if length < 2 or cursor + length > len(data):
                break
            if marker in {0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf} and length >= 7:
                height, width = struct.unpack_from(">HH", data, cursor + 3)
                return [width, height]
            cursor += length
    if extension == ".webp" and len(data) >= 30 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        if data[12:16] == b"VP8X":
            return [1 + int.from_bytes(data[24:27], "little"), 1 + int.from_bytes(data[27:30], "little")]
        if data[12:16] == b"VP8L" and data[20] == 0x2f:
            bits = int.from_bytes(data[21:25], "little")
            return [(bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1]
        if data[12:16] == b"VP8 " and data[23:26] == b"\x9d\x01\x2a":
            return [int.from_bytes(data[26:28], "little") & 0x3fff, int.from_bytes(data[28:30], "little") & 0x3fff]
    return None


def inventory(args):
    out = Path(args.out).expanduser().resolve()
    relative_name(args.version)
    manifest = load_manifest(out)
    chosen = [item for item in manifest["packages"] if item["version_directory"] == args.version]
    if not chosen or any(item["status"] != "verified" for item in chosen):
        raise ValueError("Version is absent or contains unverified packages")
    assets, configs, modules, clues = [], [], [], []
    for package in chosen:
        base = safe_path(out, package["extracted_directory"])
        for entry in package["files"]:
            path = safe_path(base, entry["relative_path"])
            data = bounded_read(path, MAX_FILE_BYTES)
            if len(data) != entry["size"] or sha(data) != entry["sha256"]:
                raise ValueError(f"Extracted file modified: {path}")
            evidence = {"package": package["name"], "source": str(path.relative_to(out)), "sha256": entry["sha256"]}
            suffix = path.suffix.lower()
            if suffix in MEDIA | FONTS:
                assets.append({**evidence, "path": entry["path"], "bytes": len(data),
                               "category": "font" if suffix in FONTS else "media", "format": suffix.lstrip("."), "dimensions": image_size(data, suffix),
                               "origin": "package", "resolution_role": "requires semantic review"})
            if suffix not in TEXT:
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                clues.append({**evidence, "kind": "non-utf8-text", "needs_review": True})
                continue
            if path.name in {"app.json", "app-config.json"}:
                try:
                    config = json.loads(text)
                    if isinstance(config, dict):
                        configs.append({**evidence, "config": config})
                    else:
                        clues.append({**evidence, "kind": "non-object-config", "needs_review": True})
                except json.JSONDecodeError:
                    clues.append({**evidence, "kind": "non-json-config", "needs_review": True})
            for match in re.finditer(r"\bdefine\(\s*['\"]([^'\"]+)['\"]", text):
                modules.append({**evidence, "module": match[1], "char_offset": match.start(),
                                "runtime": match[1].startswith("@babel/")})
            patterns = [("cloud-function", r"\bcallFunction\(\s*\{\s*name\s*:\s*['\"]([^'\"]+)['\"]"),
                        ("prompt-keyword", r"提示词|系统提示|人设|systemPrompt|system_prompt|promptTemplate"),
                        ("dynamic-config", r"\.push\.apply\(|\bloadSubpackage\b")]
            for kind, pattern in patterns:
                for match in re.finditer(pattern, text):
                    clues.append({**evidence, "kind": kind, "char_offset": match.start(),
                                  "value": match.group(1) if match.lastindex else match.group(0), "needs_review": True})
            for match in re.finditer(r"https?://[^\s'\"<>\\]+", text):
                try:
                    url = urlsplit(match.group(0))
                    # Query strings and credentials are deliberately omitted from derivative inventories.
                    clues.append({**evidence, "kind": "url-reference", "char_offset": match.start(),
                                  "host": url.hostname, "path": url.path, "query_omitted": bool(url.query), "needs_review": True})
                except ValueError:
                    continue
    roots = set()
    declared_routes = []
    for item in configs:
        declared = item["config"].get("subPackages", item["config"].get("subpackages", []))
        if isinstance(declared, list):
            roots.update(str(sub.get("root", "")).strip("/") for sub in declared if isinstance(sub, dict))
            for sub in declared:
                if isinstance(sub, dict) and isinstance(sub.get("pages"), list):
                    declared_routes.extend({"route": str(sub.get("root", "")).strip("/") + "/" + str(page).strip("/"), "root": str(sub.get("root", "")).strip("/")} for page in sub["pages"])
        if isinstance(item["config"].get("pages"), list):
            declared_routes.extend({"route": str(page).strip("/"), "root": ""} for page in item["config"]["pages"])
    roots = sorted(roots)
    paths = {entry["relative_path"] for package in chosen for entry in package["files"]}
    module_names = {item["module"].lstrip("/") for item in modules}
    for route in declared_routes:
        name = route["route"]
        if not route["root"]:
            route["root"] = next((root for root in sorted(roots, key=len, reverse=True) if name.startswith(root + "/")), "")
        matches = sorted(candidate for candidate in paths | module_names if candidate in {name + ext for ext in (".js", ".wxml", ".wxss", ".json")} or candidate == name)
        route.update(indexed_code_present=bool(matches), evidence_paths=matches,
                     page_visit="not_verified", state_coverage="not_verified",
                     missing_reason=None if matches else "not_cached_or_mapping_unresolved")
    subpackages = [{"root": root, "indexed_path_present": any(path.startswith(root + "/") for path in paths | module_names),
                    "routes": [route for route in declared_routes if route["root"] == root],
                    "status": "code-evidence-only; actual page visits required"} for root in roots if root]
    summary = {"appid": manifest["appid"], "version_directory": args.version, "packages": len(chosen),
               "files": sum(package["file_count"] for package in chosen), "asset_entries": len(assets),
               "unique_asset_hashes": len({item["sha256"] for item in assets}),
               "media_entries": sum(item["category"] == "media" for item in assets),
               "font_entries": sum(item["category"] == "font" for item in assets),
               "config_files": len(configs), "module_definitions": len(modules),
               "business_module_definitions": sum(not item["runtime"] for item in modules),
               "unique_business_modules": len({item["module"] for item in modules if not item["runtime"]}),
               "declared_subpackages": subpackages,
               "declared_routes": declared_routes, "scan_complete": manifest.get("scan_complete", "unknown-legacy-manifest"),
               "scope": "Static package inventory; regex clues are not a complete protocol, prompt library, or asset dependency graph."}
    inventory_dir = safe_path(out, "inventory/" + args.version)
    inventory_dir.mkdir(parents=True, exist_ok=True)
    for name, value in [("assets.json", assets), ("code-map.json", {"configs": configs, "modules": modules}),
                        ("clues.json", clues), ("summary.json", summary)]:
        save_json(inventory_dir / name, value)
    emit(summary)
    return 0


def doctor(args):
    try:
        import Crypto
        crypto = Crypto.__version__
    except ImportError:
        crypto = None
    script = Path(__file__).resolve()
    node = None
    try:
        result = subprocess.run(["node", "-e", "console.log(JSON.stringify({version:process.version,parser:require('@babel/parser/package.json').version,traverse:require('@babel/traverse/package.json').version,generator:require('@babel/generator/package.json').version}))"],
                                cwd=script.parent.parent, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            node = json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    emit({"tool_version": VERSION, "python": platform.python_version(), "platform": platform.system(),
          "pycryptodome": crypto, "node_dependencies": node,
          "default_package_roots_found": len(default_roots()),
          "formats": ["plain-wxapkg", "V1MMWX"], "other_formats": "unsupported; retain snapshot",
          "ready": bool(crypto and node), "cache_access": "not probed; discover reports actual scan errors"})
    return 0 if crypto and node else 1


def diff(args):
    before, after = load_manifest(args.before), load_manifest(args.after)
    if before["appid"] != after["appid"]:
        raise ValueError("Cannot compare different AppIDs")
    def keyed(manifest):
        return {(p["version_directory"], p["name"]): p for p in manifest["packages"]}
    old, new = keyed(before), keyed(after)
    output = {"schema": 1, "appid": before["appid"], "added": [list(k) for k in sorted(new.keys() - old.keys())],
              "removed": [list(k) for k in sorted(old.keys() - new.keys())],
              "changed": [list(k) for k in sorted(old.keys() & new.keys()) if old[k].get("source_sha256") != new[k].get("source_sha256")],
              "scan_complete_before": before.get("scan_complete", "unknown"), "scan_complete_after": after.get("scan_complete", "unknown"),
              "scope": "Local package changes only; no causal assertion about visits or remote assets"}
    if args.report:
        save_json(Path(args.report).expanduser().resolve(), output)
    emit(output)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("doctor", help="Check local dependencies and supported formats")
    check.set_defaults(handler=doctor)
    scan = sub.add_parser("discover", help="List package metadata; read no account storage")
    scan.add_argument("--root", action="append", default=[], help="Repeatable package directory root")
    scan.add_argument("--appid")
    scan.set_defaults(handler=discover)
    unpack = sub.add_parser("extract", help="Snapshot, decode, unpack and verify all packages below one target root")
    unpack.add_argument("--appid", required=True)
    unpack.add_argument("--source", required=True)
    unpack.add_argument("--out", required=True)
    unpack.add_argument("--max-package-bytes", type=int, default=MAX_PACKAGE_BYTES)
    unpack.add_argument("--max-file-bytes", type=int, default=MAX_FILE_BYTES)
    unpack.add_argument("--max-output-bytes", type=int, default=MAX_OUTPUT_BYTES)
    unpack.add_argument("--max-files", type=int, default=MAX_FILES)
    unpack.set_defaults(handler=extract)
    index = sub.add_parser("inventory", help="Read one verified version and generate static inventories")
    index.add_argument("--out", required=True)
    index.add_argument("--version", required=True)
    index.set_defaults(handler=inventory)
    compare = sub.add_parser("diff", help="Compare two evidence directories for one AppID")
    compare.add_argument("--before", required=True)
    compare.add_argument("--after", required=True)
    compare.add_argument("--report")
    compare.set_defaults(handler=diff)
    args = parser.parse_args()
    for field in ("max_package_bytes", "max_file_bytes", "max_output_bytes", "max_files"):
        if getattr(args, field, 1) < 1:
            parser.error("Resource limits must be positive")
    if getattr(args, "appid", None) and not APPID.fullmatch(args.appid):
        parser.error("AppID must be wx followed by 16 lowercase hexadecimal characters")
    if getattr(args, "version", None) and (args.version in {".", ".."} or any(char in args.version for char in "/\\:")):
        parser.error("Version must be a single directory name")
    try:
        return args.handler(args)
    except (OSError, ValueError, KeyError, struct.error) as error:
        emit({"status": "failed", "error": str(error)})
        return 1


if __name__ == "__main__":
    sys.exit(main())
