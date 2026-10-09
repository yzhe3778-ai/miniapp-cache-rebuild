#!/usr/bin/env python3
"""Build a deterministic, self-contained skill archive without private evidence."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import unicodedata
import zipfile


ARCHIVE_ROOT = "miniapp-cache-rebuild"
ROOT_FILES = {
    "SKILL.md", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.md",
    "CHANGELOG.md", "CONTRIBUTING.md", "requirements.txt", "pyproject.toml",
    "package.json", "package-lock.json", ".gitignore", ".env.example",
}
PUBLIC_DIRS = {"scripts", "tests", "references", "templates", "agents", ".github"}
IGNORED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
    "output", "outputs", "evidence", "private-evidence", "packages", "inventory",
    "analysis", "reports", "exports", "dist", "build", "qa", "coverage",
}
IGNORED_FILES = {".DS_Store", "distribution-manifest.json"}
TEXT_SUFFIXES = {".py", ".cjs", ".mjs", ".js", ".md", ".json", ".yaml", ".yml", ".toml", ".txt", ".csv"}
REQUIRED_FILES = {"SKILL.md", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "requirements.txt"}
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024

# Split static markers so the scanner can inspect its own source and tests.
PERSONAL_PATHS = [
    re.compile(r"/" + r"Users/[A-Za-z0-9._-]+(?:/|$)"),
    re.compile(r"/" + r"home/[A-Za-z0-9._-]+(?:/|$)"),
    re.compile(r"[A-Za-z]:[\\/]" + r"Users[\\/][A-Za-z0-9._-]+(?:[\\/]|$)", re.I),
]
SECRET_MARKERS = [
    re.compile(r"\b" + r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b" + r"AKIA[A-Z0-9]{16}\b"),
    re.compile(r"-----BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\b"),
    re.compile(r"https?://[^\s/@:]+:[^\s/@]+@", re.I),
]
SECRET_ASSIGNMENT = re.compile(
    r"\b(?:[A-Za-z_][A-Za-z0-9_]*(?:API_KEY|TOKEN|PASSWORD|SECRET)|api[_-]?key|apiKey|token|password|secret|access[_-]?token|authorization)"
    r"\s*[\"']?\s*[:=]\s*[\"']([^\"'\r\n]{12,})[\"']",
    re.I,
)
PLACEHOLDER_MARKERS = ("<", "${", "YOUR_", "your_", "example", "EXAMPLE", "redacted", "REDACTED", "placeholder", "process.env", "os.environ")


class PackageError(ValueError):
    """A source folder is unsafe or cannot be distributed."""


def inspect_text(relative, data):
    """Reject personal path and credential values, not harmless field names."""
    try:
        body = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PackageError("Non-UTF-8/binary input is not distributable: " + relative) from exc
    if "\x00" in body:
        raise PackageError("Binary input is not distributable: " + relative)
    if any(pattern.search(body) for pattern in PERSONAL_PATHS):
        raise PackageError("Personal absolute path detected: " + relative)
    if any(pattern.search(body) for pattern in SECRET_MARKERS):
        raise PackageError("Credential/private-key marker detected: " + relative)
    for match in SECRET_ASSIGNMENT.finditer(body):
        value = match.group(1).strip()
        if not any(marker in value for marker in PLACEHOLDER_MARKERS):
            raise PackageError("Credential-looking assigned value detected: " + relative)


def collect_files(root):
    """Collect only allowed text files; never follow a symlink."""
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise PackageError("--root must be a skill directory")
    result = []
    excluded_count = 0
    total_bytes = 0
    aliases = set()
    def walk_error(error):
        raise PackageError("Cannot scan source directory") from error
    for directory, subdirectories, files in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
        base = Path(directory)
        for name in list(subdirectories):
            path = base / name
            if name in IGNORED_DIRS:
                subdirectories.remove(name)
                excluded_count += 1
                continue
            if path.is_symlink():
                raise PackageError("Symlink directory refused: " + path.relative_to(root).as_posix())
            relative = path.relative_to(root)
            if relative.parts[0] not in PUBLIC_DIRS:
                raise PackageError("Unexpected directory refused: " + relative.as_posix())
        for name in sorted(files):
            path = base / name
            relative = path.relative_to(root).as_posix()
            parts = PurePosixPath(relative).parts
            if name in IGNORED_FILES or name.endswith((".pyc", ".pyo")):
                excluded_count += 1
                continue
            if path.is_symlink():
                raise PackageError("Symlink file refused: " + relative)
            allowed = relative in ROOT_FILES or (parts[0] in PUBLIC_DIRS and path.suffix in TEXT_SUFFIXES)
            if not allowed:
                raise PackageError("Unexpected or binary file refused: " + relative)
            if name in {".env", ".npmrc", ".pypirc"} or (name.startswith(".env.") and name != ".env.example"):
                raise PackageError("Credential configuration refused: " + relative)
            alias = unicodedata.normalize("NFC", relative).casefold()
            if alias in aliases:
                raise PackageError("Portable path collision: " + relative)
            aliases.add(alias)
            stat = path.stat()
            if stat.st_size > MAX_FILE_BYTES:
                raise PackageError("File exceeds distribution limit: " + relative)
            data = path.read_bytes()
            current = path.stat()
            if (stat.st_size, stat.st_mtime_ns, stat.st_ino) != (current.st_size, current.st_mtime_ns, current.st_ino):
                raise PackageError("File changed while packaging: " + relative)
            total_bytes += len(data)
            if total_bytes > MAX_TOTAL_BYTES:
                raise PackageError("Archive input exceeds distribution limit")
            inspect_text(relative, data)
            result.append((relative, data))
    present = {name for name, _ in result}
    missing = REQUIRED_FILES - present
    if missing:
        raise PackageError("Missing required distribution files: " + ", ".join(sorted(missing)))
    return sorted(result), excluded_count


def package_skill(root, output):
    """Build an archive exclusively outside the source tree; do not overwrite."""
    root = Path(root).resolve(strict=True)
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise PackageError("Output already exists; use a new archive path")
    if output.suffix.lower() != ".zip":
        raise PackageError("Output must have a .zip extension")
    parent = output.parent.resolve(strict=True)
    if parent == root or root in parent.parents:
        raise PackageError("Output must be outside the skill source directory")
    output = parent / output.name
    files, excluded_count = collect_files(root)
    entries = [
        {"path": name, "byte_length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for name, data in files
    ]
    manifest = {
        "schema_version": 1,
        "skill": ARCHIVE_ROOT,
        "file_count": len(entries),
        "files": entries,
        "scope": "Tool/docs/templates/tests only; no commercial packages or private evidence.",
    }
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with zipfile.ZipFile(output, mode="x", compression=zipfile.ZIP_STORED) as archive:
        for name, data in files + [("distribution-manifest.json", manifest_bytes)]:
            info = zipfile.ZipInfo(ARCHIVE_ROOT + "/" + name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, data)
    # Read back all entries rather than only trusting the writer return value.
    with zipfile.ZipFile(output) as archive:
        for entry in entries:
            data = archive.read(ARCHIVE_ROOT + "/" + entry["path"])
            if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise PackageError("Archive readback mismatch")
        if archive.read(ARCHIVE_ROOT + "/distribution-manifest.json") != manifest_bytes:
            raise PackageError("Archive manifest readback mismatch")
    return {
        "status": "verified",
        "file_count": len(files),
        "excluded_count": excluded_count,
        "archive_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "archive": str(output),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = package_skill(args.root, args.out)
    except (PackageError, OSError, zipfile.BadZipFile) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
