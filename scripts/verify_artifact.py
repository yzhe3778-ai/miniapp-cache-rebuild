#!/usr/bin/env python3
"""Read back exported files; artifact validation never claims browser restoration."""

import argparse
import csv
import hashlib
import io
import json
import math
import zlib
import struct
import sys
from pathlib import Path


class InvalidArtifact(ValueError):
    pass


def image_info(data):
    """Identify supported raster formats and encoded dimensions without execution."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        if len(data) < 33 or data[8:16] != b"\x00\x00\x00\rIHDR":
            raise InvalidArtifact("Invalid PNG header")
        width, height = struct.unpack(">II", data[16:24])
        offset, kinds = 8, []
        while offset < len(data):
            if offset + 12 > len(data):
                raise InvalidArtifact("Truncated PNG chunk")
            length = struct.unpack(">I", data[offset:offset + 4])[0]
            if offset + length + 12 > len(data):
                raise InvalidArtifact("Invalid PNG chunk bounds")
            chunk_kind = data[offset + 4:offset + 8]
            payload = data[offset + 8:offset + 8 + length]
            actual_crc = struct.unpack(">I", data[offset + 8 + length:offset + 12 + length])[0]
            if zlib.crc32(chunk_kind + payload) & 0xFFFFFFFF != actual_crc:
                raise InvalidArtifact("PNG chunk CRC mismatch")
            kinds.append(chunk_kind)
            offset += length + 12
            if chunk_kind == b"IEND":
                if length or offset != len(data):
                    raise InvalidArtifact("Invalid PNG ending")
                break
        if not kinds or kinds[-1] != b"IEND" or b"IDAT" not in kinds:
            raise InvalidArtifact("PNG image data or ending missing")
        kind, mime = "png", "image/png"
    elif data[:6] in {b"GIF87a", b"GIF89a"}:
        if len(data) < 14 or data[-1:] != b";":
            raise InvalidArtifact("Invalid GIF header or trailer")
        width, height = struct.unpack("<HH", data[6:10])
        kind, mime = "gif", "image/gif"
    elif data.startswith(b"\xff\xd8"):
        if not data.endswith(b"\xff\xd9"):
            raise InvalidArtifact("Invalid JPEG trailer")
        offset, dimensions = 2, None
        while offset < len(data) - 2:
            if data[offset] != 255:
                raise InvalidArtifact("Invalid JPEG marker")
            while offset < len(data) and data[offset] == 255:
                offset += 1
            marker = data[offset]
            offset += 1
            if marker in {0xD8, 0xD9} or 0xD0 <= marker <= 0xD7:
                continue
            if offset + 2 > len(data):
                raise InvalidArtifact("Truncated JPEG segment")
            size = struct.unpack(">H", data[offset:offset + 2])[0]
            if size < 2 or offset + size > len(data):
                raise InvalidArtifact("Invalid JPEG segment bounds")
            if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
                if size < 8:
                    raise InvalidArtifact("Invalid JPEG size segment")
                height, width = struct.unpack(">HH", data[offset + 3:offset + 7])
                dimensions = (width, height)
                break
            if marker == 0xDA:
                break
            offset += size
        if dimensions is None:
            raise InvalidArtifact("JPEG dimensions not found")
        width, height = dimensions
        kind, mime = "jpeg", "image/jpeg"
    elif data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        if len(data) < 30 or struct.unpack("<I", data[4:8])[0] != len(data) - 8:
            raise InvalidArtifact("Invalid WebP container")
        chunk = data[12:16]
        if chunk == b"VP8X":
            width = 1 + int.from_bytes(data[24:27], "little")
            height = 1 + int.from_bytes(data[27:30], "little")
        elif chunk == b"VP8L" and data[20] == 0x2F:
            packed = int.from_bytes(data[21:25], "little")
            width, height = 1 + (packed & 0x3FFF), 1 + ((packed >> 14) & 0x3FFF)
        elif chunk == b"VP8 " and data[23:26] == b"\x9d\x01\x2a":
            width, height = struct.unpack("<HH", data[26:30])
            width, height = width & 0x3FFF, height & 0x3FFF
        else:
            raise InvalidArtifact("Unsupported WebP size header")
        kind, mime = "webp", "image/webp"
    elif data.startswith(b"BM"):
        if len(data) < 54 or struct.unpack("<I", data[2:6])[0] != len(data):
            raise InvalidArtifact("Invalid BMP header")
        width, height = struct.unpack("<ii", data[18:26])
        height = abs(height)
        kind, mime = "bmp", "image/bmp"
    else:
        raise InvalidArtifact("Unsupported raster image signature")
    if width <= 0 or height <= 0 or width * height > 250_000_000:
        raise InvalidArtifact("Invalid or excessive image dimensions")
    return {"format": kind, "mime": mime, "dimensions": [width, height], "image_validation": "encoded_signature_dimensions_and_container_checks"}


def validate_schema(value, schema, path="$", depth=0):
    """A strict documented JSON-schema subset; unsupported keywords fail closed."""
    allowed = {"type", "required", "properties", "items", "additionalProperties", "enum", "minItems", "maxItems", "minLength", "maxLength", "minimum", "maximum", "description", "title"}
    if depth > 64 or not isinstance(schema, dict) or set(schema) - allowed:
        raise InvalidArtifact("Invalid or unsupported restore schema")
    declared = schema.get("type")
    types = {"object": isinstance(value, dict), "array": isinstance(value, list), "string": isinstance(value, str),
             "number": isinstance(value, (int, float)) and not isinstance(value, bool),
             "integer": isinstance(value, int) and not isinstance(value, bool), "boolean": isinstance(value, bool), "null": value is None}
    if declared is not None and (declared not in types or not types[declared]):
        raise InvalidArtifact(f"Restore schema type mismatch at {path}")
    if "enum" in schema and value not in schema["enum"]:
        raise InvalidArtifact(f"Restore schema enum mismatch at {path}")
    if isinstance(value, dict):
        required = schema.get("required", [])
        properties = schema.get("properties", {})
        if not isinstance(required, list) or not all(isinstance(key, str) for key in required) or not isinstance(properties, dict):
            raise InvalidArtifact("Invalid object schema")
        if any(key not in value for key in required):
            raise InvalidArtifact(f"Required restore field missing at {path}")
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            raise InvalidArtifact(f"Unexpected restore field at {path}")
        for key, child in properties.items():
            if key in value:
                validate_schema(value[key], child, path + "." + key, depth + 1)
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", float("inf")):
            raise InvalidArtifact(f"Restore array length mismatch at {path}")
        if "items" in schema:
            for index, child in enumerate(value):
                validate_schema(child, schema["items"], path + f"[{index}]", depth + 1)
    if isinstance(value, str) and (len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", float("inf"))):
        raise InvalidArtifact(f"Restore string length mismatch at {path}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < schema.get("minimum", -float("inf")) or value > schema.get("maximum", float("inf")):
            raise InvalidArtifact(f"Restore numeric bounds mismatch at {path}")


def finite_float(text):
    number = float(text)
    if not math.isfinite(number):
        raise InvalidArtifact("Non-finite JSON number")
    return number


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidArtifact("Duplicate JSON object key")
        result[key] = value
    return result


def verify(path, kind, expected_hash=None, required_fields=(), expected_dimensions=None, schema=None, max_bytes=64 * 1024 * 1024):
    path = Path(path).expanduser().absolute()
    trusted_os_aliases = {Path("/tmp"), Path("/var")}
    if path.is_symlink() or any(item.is_symlink() and item not in trusted_os_aliases for item in path.parents):
        raise InvalidArtifact("Symlink artifact path refused")
    path = path.resolve()
    if not path.is_file() or path.stat().st_size > max_bytes:
        raise InvalidArtifact("Artifact missing, not a file or exceeds size limit")
    data = path.read_bytes()
    if len(data) > max_bytes:
        raise InvalidArtifact("Artifact changed or exceeds size limit")
    actual_hash = hashlib.sha256(data).hexdigest()
    if expected_hash and actual_hash != expected_hash:
        raise InvalidArtifact("Artifact readback hash mismatch")
    result = {"status": "verified", "type": kind, "bytes": len(data), "sha256": actual_hash,
              "scope": "Real file readback; browser save/restore behavior requires separate UI acceptance"}
    if kind == "json":
        value = json.loads(data.decode("utf-8-sig"), object_pairs_hook=unique_keys, parse_float=finite_float, parse_constant=lambda _: (_ for _ in ()).throw(InvalidArtifact("Non-finite JSON number")))
        if required_fields and (not isinstance(value, dict) or any(field not in value for field in required_fields)):
            raise InvalidArtifact("Required JSON export fields missing")
        if schema is not None:
            validate_schema(value, schema)
        result.update(root_type=type(value).__name__, restore_schema_checked=schema is not None)
    elif kind == "csv":
        reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig")))
        fields = reader.fieldnames
        if fields is None or len(fields) != len(set(fields)) or any(field not in fields for field in required_fields):
            raise InvalidArtifact("CSV header absent, duplicated or required fields missing")
        count = 0
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise InvalidArtifact("CSV row does not match header")
            count += 1
        result.update(field_count=len(fields), row_count=count)
    elif kind == "image":
        info = image_info(data)
        if expected_dimensions and list(expected_dimensions) != info["dimensions"]:
            raise InvalidArtifact("Exported image dimensions mismatch")
        result.update(info)
    else:
        raise InvalidArtifact("Unknown artifact type")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True)
    parser.add_argument("--type", required=True, choices=["json", "csv", "image"])
    parser.add_argument("--sha256")
    parser.add_argument("--required-field", "--required-key", action="append", default=[])
    parser.add_argument("--dimensions", type=int, nargs=2)
    parser.add_argument("--schema", help="JSON restore schema, using the documented strict subset")
    parser.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)
    args = parser.parse_args()
    try:
        if not 1 <= args.max_bytes <= 256 * 1024 * 1024:
            raise InvalidArtifact("Invalid size limit")
        schema = json.loads(Path(args.schema).read_text()) if args.schema else None
        print(json.dumps(verify(args.path, args.type, args.sha256, args.required_field, args.dimensions, schema, args.max_bytes), ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError, struct.error, csv.Error, RecursionError) as error:
        print(json.dumps({"status": "failed", "error": type(error).__name__, "scope": "File validation only"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
