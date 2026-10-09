#!/usr/bin/env python3
"""Opt-in, bounded HTTPS raster asset downloads from an explicit host allowlist."""

import argparse
import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from report_tool import atomic_write, safe_path, save_json
from verify_artifact import image_info


class AssetError(ValueError):
    """Errors carry fixed codes; rejected URL credentials never appear in output."""


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname, address, timeout):
        super().__init__(hostname, port=443, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        sock = socket.create_connection((self.address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except (OSError, ssl.SSLError):
            sock.close()
            raise


def valid_url(url, allowed_hosts, resolver=socket.getaddrinfo):
    if not isinstance(url, str) or len(url) > 4096 or any(ord(char) <= 32 for char in url):
        raise AssetError("invalid_url")
    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        port = parts.port
    except ValueError as error:
        raise AssetError("invalid_url") from error
    if parts.scheme != "https" or not hostname or port not in {None, 443}:
        raise AssetError("https_default_port_required")
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise AssetError("credential_signed_or_query_url_refused")
    hostname = hostname.lower()
    if hostname not in allowed_hosts:
        raise AssetError("host_not_allowed")
    if hostname.endswith(".") or hostname in {"localhost", "localhost.localdomain"} or hostname.endswith((".localhost", ".local", ".internal")):
        raise AssetError("local_host_refused")
    try:
        answers = resolver(hostname, 443, type=socket.SOCK_STREAM)
    except OSError as error:
        raise AssetError("dns_failed") from error
    addresses = sorted(set(answer[4][0] for answer in answers))
    if not addresses:
        raise AssetError("dns_empty")
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as error:
            raise AssetError("invalid_dns_address") from error
        if not parsed.is_global:
            raise AssetError("private_or_local_address_refused")
    # The exact validated address is pinned for TLS connection; hostname verifies certificate.
    return parts, addresses[0]


def open_response(parts, address, timeout):
    connection = PinnedHTTPSConnection(parts.hostname, address, timeout)
    target = parts.path or "/"
    try:
        connection.request("GET", target, headers={"Accept": "image/png,image/jpeg,image/webp,image/gif,image/bmp", "User-Agent": "miniapp-cache-rebuild-assets/1", "Connection": "close"})
        response = connection.getresponse()
        return response, connection
    except (OSError, http.client.HTTPException):
        connection.close()
        raise


def fetch(url, allowed_hosts, *, timeout=15, max_bytes=10 * 1024 * 1024, retries=1, interval=1,
          resolver=socket.getaddrinfo, opener=open_response, sleeper=time.sleep):
    if not 0 < timeout <= 30 or not 1 <= max_bytes <= 64 * 1024 * 1024 or not 0 <= retries <= 2 or not 0 <= interval <= 10:
        raise AssetError("invalid_limits")
    current, redirects, attempts = url, 0, 0
    while True:
        parts, address = valid_url(current, allowed_hosts, resolver)
        if attempts or redirects:
            sleeper(interval)
        response = connection = None
        try:
            response, connection = opener(parts, address, timeout)
            status = response.status
            if status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                if not location or redirects >= 3:
                    raise AssetError("redirect_limit_or_missing_location")
                current = urljoin(current, location)
                # Revalidate before issuing redirected request. Nothing bypasses the allowlist.
                valid_url(current, allowed_hosts, resolver)
                redirects += 1
                continue
            if status in {429, 500, 502, 503, 504} and attempts < retries:
                attempts += 1
                continue
            if status != 200:
                raise AssetError("http_status_failed")
            if response.getheader("Content-Encoding", "identity").lower() not in {"identity", ""}:
                raise AssetError("encoded_response_refused")
            declared = response.getheader("Content-Length")
            if declared is not None:
                if not declared.isdigit() or int(declared) > max_bytes:
                    raise AssetError("declared_size_invalid_or_exceeded")
            mime = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            if mime not in {"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp"}:
                raise AssetError("unsupported_mime")
            chunks, count = [], 0
            while True:
                chunk = response.read(min(65536, max_bytes + 1 - count))
                if not chunk:
                    break
                chunks.append(chunk)
                count += len(chunk)
                if count > max_bytes:
                    raise AssetError("download_size_exceeded")
            data = b"".join(chunks)
            if declared is not None and len(data) != int(declared):
                raise AssetError("content_length_mismatch")
            try:
                info = image_info(data)
            except ValueError as error:
                raise AssetError("invalid_image_signature_or_dimensions") from error
            if info["mime"] != mime:
                raise AssetError("mime_signature_mismatch")
            return data, info, {"redirects": redirects, "retries": attempts}
        except (OSError, http.client.HTTPException) as error:
            if attempts >= retries:
                raise AssetError("network_failed") from error
            attempts += 1
        finally:
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()


def download_list(spec, out, *, timeout=15, max_bytes=10 * 1024 * 1024, retries=1, interval=1, fetcher=fetch):
    if not isinstance(spec, dict) or not isinstance(spec.get("assets"), list) or not isinstance(spec.get("allowed_hosts"), list):
        raise AssetError("expected_assets_and_allowed_hosts")
    if not 0 < timeout <= 30 or not 1 <= max_bytes <= 64 * 1024 * 1024 or not 0 <= retries <= 2 or not 0 <= interval <= 10:
        raise AssetError("invalid_limits")
    hosts = spec["allowed_hosts"]
    if not hosts or not all(isinstance(host, str) and host == host.lower() and ":" not in host and "/" not in host and "@" not in host and "?" not in host for host in hosts):
        raise AssetError("invalid_allowlist")
    if len(spec["assets"]) > 500:
        raise AssetError("asset_list_exceeds_limit")
    out = Path(out).absolute()
    safe_path(out.parent, out.name)
    if out.exists():
        raise AssetError("new_output_directory_required")
    out.mkdir(parents=True)
    records = []
    for index, entry in enumerate(spec["assets"], 1):
        record = {"id": f"asset-{index:04d}", "status": "failed"}
        if isinstance(entry, dict) and isinstance(entry.get("url"), str):
            record["request_sha256"] = hashlib.sha256(entry["url"].encode()).hexdigest()
        try:
            if not isinstance(entry, dict) or not isinstance(entry.get("url"), str):
                raise AssetError("invalid_asset_entry")
            if index > 1:
                time.sleep(interval)
            data, info, metrics = fetcher(entry["url"], set(hosts), timeout=timeout, max_bytes=max_bytes, retries=retries, interval=interval)
            actual_hash = hashlib.sha256(data).hexdigest()
            if entry.get("expected_sha256") and entry["expected_sha256"] != actual_hash:
                raise AssetError("expected_hash_mismatch")
            if entry.get("expected_dimensions") and entry["expected_dimensions"] != info["dimensions"]:
                raise AssetError("expected_dimensions_mismatch")
            filename = actual_hash + "." + info["format"]
            path = safe_path(out, filename)
            if not path.exists():
                atomic_write(path, data)
            if hashlib.sha256(path.read_bytes()).hexdigest() != actual_hash:
                raise AssetError("file_readback_hash_mismatch")
            record.update(status="verified", file=filename, bytes=len(data), sha256=actual_hash, **info, **metrics,
                          resolution_role="requires semantic review; dimensions do not prove original quality")
        except (AssetError, OSError) as error:
            record["reason"] = str(error) if isinstance(error, AssetError) else "output_io_failed"
        records.append(record)
        save_json(out / "asset-manifest.json", {"schema": 1, "records": records,
                                               "scope": "Explicit opted-in raster URLs only; no API, font, vector, signed or authenticated downloads"})
    if not records:
        save_json(out / "asset-manifest.json", {"schema": 1, "records": [], "scope": "No requested assets"})
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", required=True, help="JSON {allowed_hosts:[...],assets:[{url,...}]}")
    parser.add_argument("--out", required=True, help="New directory only")
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--max-bytes", type=int, default=10 * 1024 * 1024)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--interval", type=float, default=1, help="Seconds between requests; minimum 0.25")
    args = parser.parse_args()
    try:
        if not 0.25 <= args.interval <= 10:
            raise AssetError("invalid_rate_interval")
        records = download_list(json.loads(Path(args.list).read_text()), args.out, timeout=args.timeout, max_bytes=args.max_bytes, retries=args.retries, interval=args.interval)
        passed = sum(item["status"] == "verified" for item in records)
        print(json.dumps({"status": "verified" if passed == len(records) else "partial", "requested": len(records), "verified": passed, "failed": len(records) - passed}))
        return 0 if passed == len(records) else 1
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps({"status": "failed", "reason": str(error) if isinstance(error, AssetError) else type(error).__name__}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
