#!/usr/bin/env python3
"""Security-focused helpers shared by the Jeeb reusable workflow tools."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Mapping


API_VERSION = "olivium.dev/jeeb-ephemeral/v1"
BUILD_INTENT_VERSION = "olivium.dev/build-intent/v1"
LOCK_VERSION = "olivium.dev/deployment-lock/v1"
SOURCE_BROKER_VERSION = "olivium.dev/source-broker/v1"
MANAGER_URL = "https://ephemeral.fds-8.space"
MANAGER_AUDIENCE = f"{MANAGER_URL}/api/automation/v1"
SAFE_ID = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


class ContractError(RuntimeError):
    """Raised when an owner-reviewed contract fails closed."""


class TransientRequestError(ContractError):
    """Raised when a trusted request may be retried within an explicit deadline."""


class HttpRequestError(ContractError):
    """Raised when a trusted endpoint returns a non-success HTTP status."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status

    @property
    def retryable(self) -> bool:
        return self.status == 409 or self.status == 429 or self.status >= 500


class OidcHttpRequestError(HttpRequestError):
    """Raised for an OIDC endpoint status with OIDC-specific retry rules."""

    @property
    def retryable(self) -> bool:
        return self.status == 429 or self.status >= 500


def _curl_quote(value: str) -> str:
    require("\x00" not in value and "\r" not in value and "\n" not in value, "curl option contains control characters")
    return f'"{value.replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"'


def _write_private(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)


def _parse_curl_headers(raw: bytes) -> dict[str, str]:
    require(len(raw) <= 131_072, "trusted endpoint response headers exceeded the size limit")
    headers: dict[str, str] = {}
    for line in raw.replace(b"\r\n", b"\n").split(b"\n"):
        if line.startswith(b"HTTP/"):
            headers = {}
            continue
        if not line or b":" not in line:
            continue
        key, value = line.split(b":", 1)
        headers[key.decode("iso-8859-1").strip()] = value.decode("iso-8859-1").strip()
    return headers


def bounded_request(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str],
    data: bytes | None,
    timeout: float,
    max_response_bytes: int,
) -> tuple[int, Mapping[str, str], bytes]:
    require(timeout > 0.05, "trusted endpoint request deadline exhausted")
    require(0 < max_response_bytes <= 4_194_304, "trusted endpoint response limit is invalid")
    deadline = time.monotonic() + timeout
    require(re.fullmatch(r"[A-Z]{1,16}", method) is not None, "trusted endpoint method is invalid")
    require(isinstance(url, str) and 0 < len(url) <= 4096, "trusted endpoint URL is invalid")
    _curl_quote(url)
    curl = shutil.which("curl")
    require(curl is not None, "curl is required for trusted endpoint requests")

    with tempfile.TemporaryDirectory(prefix="olivium-trusted-request-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        request_path = root / "request.bin"
        response_path = root / "response.bin"
        headers_path = root / "response.headers"
        config_path = root / "curl.conf"
        _write_private(response_path, b"")
        _write_private(headers_path, b"")
        if data is not None:
            require(isinstance(data, bytes), "trusted endpoint request body is invalid")
            _write_private(request_path, data)

        termination_grace = min(0.1, timeout / 4)
        remaining = deadline - time.monotonic() - termination_grace
        if remaining <= 0.001:
            raise TransientRequestError("trusted endpoint request exceeded its absolute deadline")
        config = [
            "silent",
            "show-error",
            "fail",
            f"request = {_curl_quote(method)}",
            f"url = {_curl_quote(url)}",
            'proto = "=http,https"',
            f"max-time = {_curl_quote(f'{remaining:.6f}')}",
            f"max-filesize = {_curl_quote(str(max_response_bytes))}",
            f"output = {_curl_quote(str(response_path))}",
            f"dump-header = {_curl_quote(str(headers_path))}",
            'write-out = "%{http_code}"',
        ]
        for key, value in headers.items():
            require(
                isinstance(key, str) and re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}", key) is not None,
                "trusted endpoint header name is invalid",
            )
            require(isinstance(value, str) and len(value) <= 8192, "trusted endpoint header value is invalid")
            config.append(f"header = {_curl_quote(f'{key}: {value}')}")
        config.append('header = "Expect:"')
        if data is not None:
            config.append(f"data-binary = {_curl_quote(f'@{request_path}')}")
        _write_private(config_path, ("\n".join(config) + "\n").encode("utf-8"))

        process_timeout = deadline - time.monotonic()
        if process_timeout <= 0.001:
            raise TransientRequestError("trusted endpoint request exceeded its absolute deadline")
        try:
            result = subprocess.run(
                [curl, "--disable", "--config", str(config_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={"LC_ALL": "C"},
                timeout=process_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TransientRequestError("trusted endpoint request exceeded its absolute deadline") from exc
        except OSError as exc:
            raise TransientRequestError("trusted endpoint request transport could not start") from exc

        status_text = result.stdout.decode("ascii", errors="ignore").strip()
        status = int(status_text) if re.fullmatch(r"[0-9]{3}", status_text) else 0
        if result.returncode == 22 and 400 <= status <= 599:
            raise HttpRequestError(status, f"HTTP {status} from trusted endpoint")
        if result.returncode == 28:
            raise TransientRequestError("trusted endpoint request exceeded its absolute deadline")
        if result.returncode == 63:
            raise ContractError("trusted endpoint response exceeded the size limit")
        if result.returncode != 0:
            raise TransientRequestError(f"trusted endpoint request transport failed with exit {result.returncode}")
        require(100 <= status <= 599, "trusted endpoint returned an invalid HTTP status")
        require(response_path.stat().st_size <= max_response_bytes, "trusted endpoint response exceeded the size limit")
        raw = response_path.read_bytes()
        response_headers = _parse_curl_headers(headers_path.read_bytes())
        return status, response_headers, raw


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read JSON contract {path}: {exc}") from exc


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json(value) + b"\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def strict_keys(value: Mapping[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(value) - allowed)
    require(not unknown, f"{context} contains unsupported fields: {', '.join(unknown)}")


def nonempty_string(value: Any, context: str, max_length: int = 512) -> str:
    require(isinstance(value, str), f"{context} must be a string")
    require(value == value.strip() and 0 < len(value) <= max_length, f"{context} is invalid")
    require("\x00" not in value and "\n" not in value and "\r" not in value, f"{context} contains control characters")
    return value


def safe_relative_path(value: Any, context: str) -> str:
    candidate = nonempty_string(value, context, 240)
    path = PurePosixPath(candidate)
    require(not path.is_absolute(), f"{context} must be relative")
    require(".." not in path.parts and "." not in path.parts, f"{context} must not traverse directories")
    require(all(part and not part.startswith("~") for part in path.parts), f"{context} is invalid")
    return str(path)


def https_url(value: Any, context: str, allow_http: bool = False) -> str:
    url = nonempty_string(value, context, 2048).rstrip("/")
    parsed = urllib.parse.urlsplit(url)
    allowed_schemes = {"https"}
    if allow_http:
        allowed_schemes.add("http")
    require(parsed.scheme in allowed_schemes, f"{context} must use HTTPS")
    require(bool(parsed.hostname), f"{context} must include a hostname")
    require(not parsed.username and not parsed.password, f"{context} must not contain credentials")
    require(not parsed.query and not parsed.fragment, f"{context} must not contain a query or fragment")
    if parsed.scheme == "http":
        require(parsed.hostname in {"127.0.0.1", "localhost"}, f"{context} test HTTP is loopback-only")
    return url


def safe_tar_members(archive: tarfile.TarFile, *, max_files: int = 100_000, max_bytes: int = 2_000_000_000) -> list[tarfile.TarInfo]:
    members = archive.getmembers()
    require(len(members) <= max_files, "archive contains too many entries")
    total = 0
    for member in members:
        path = PurePosixPath(member.name)
        require(member.name and not path.is_absolute(), f"unsafe archive path: {member.name!r}")
        require(".." not in path.parts, f"archive path traversal: {member.name!r}")
        require(not member.issym() and not member.islnk(), f"archive links are prohibited: {member.name!r}")
        require(member.isfile() or member.isdir(), f"unsupported archive entry: {member.name!r}")
        if member.isfile():
            require(member.size >= 0, f"invalid archive size: {member.name!r}")
            total += member.size
            require(total <= max_bytes, "archive exceeds the uncompressed size limit")
    return members


def extract_tar_safely(source: Path, destination: Path, *, max_bytes: int = 2_000_000_000) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(source, "r:*") as archive:
        members = safe_tar_members(archive, max_bytes=max_bytes)
        archive.extractall(destination, members=members, filter="data")


def oidc_token(audience: str, *, static_env: str | None = None, timeout: float = 20.0) -> str:
    if static_env:
        token = os.environ.get(static_env, "")
        require(bool(token), f"{static_env} is required")
        return token

    request_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    require(bool(request_url and request_token), "GitHub OIDC request variables are unavailable")
    separator = "&" if "?" in request_url else "?"
    url = f"{request_url}{separator}{urllib.parse.urlencode({'audience': audience})}"
    request_headers = {"Authorization": f"Bearer {request_token}", "Accept": "application/json"}
    try:
        status, _, raw = bounded_request(
            "GET",
            url,
            headers=request_headers,
            data=None,
            timeout=timeout,
            max_response_bytes=65_536,
        )
        require(status == 200, f"GitHub OIDC endpoint returned unexpected HTTP {status}")
        payload = json.loads(raw)
    except HttpRequestError as exc:
        raise OidcHttpRequestError(
            exc.status,
            f"GitHub OIDC token request failed: {exc}",
        ) from exc
    except json.JSONDecodeError as exc:
        raise ContractError("GitHub OIDC response is invalid JSON") from exc
    require(isinstance(payload, dict) and isinstance(payload.get("value"), str), "GitHub OIDC response is invalid")
    return payload["value"]


def request_json(
    method: str,
    url: str,
    *,
    bearer: str | None = None,
    body: Any | None = None,
    expected: tuple[int, ...] = (200,),
    timeout: float = 30.0,
) -> tuple[Any, Mapping[str, str]]:
    headers = {"Accept": "application/json", "User-Agent": "olivium-jeeb-ephemeral/1"}
    data = None
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    if body is not None:
        data = canonical_json(body)
        headers["Content-Type"] = "application/json"
    status, response_headers, raw = bounded_request(
        method,
        url,
        headers=headers,
        data=data,
        timeout=timeout,
        max_response_bytes=1_048_576,
    )
    require(status in expected, f"trusted endpoint returned unexpected HTTP {status}")
    try:
        payload = json.loads(raw) if raw else None
    except json.JSONDecodeError as exc:
        raise ContractError("trusted endpoint returned invalid JSON") from exc
    return payload, response_headers


def request_bytes(
    method: str,
    url: str,
    *,
    bearer: str,
    body: Any,
    expected: tuple[int, ...] = (200,),
    timeout: int = 120,
) -> tuple[bytes, Mapping[str, str]]:
    request = urllib.request.Request(
        url,
        data=canonical_json(body),
        headers={
            "Accept": "application/vnd.olivium.source-bundle.v1+tar+gzip",
            "Authorization": f"Bearer {bearer}",
            "Content-Type": "application/json",
            "User-Agent": "olivium-jeeb-ephemeral/1",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            raw = response.read()
            status = response.status
            response_headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        exc.close()
        raise ContractError(f"HTTP {exc.code} from source broker") from exc
    except urllib.error.URLError as exc:
        raise ContractError(f"source broker request failed: {exc.reason}") from exc
    require(status in expected, f"source broker returned unexpected HTTP {status}")
    return raw, response_headers


def redact(value: str) -> str:
    patterns = (
        r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+",
        r"(?i)(authorization|token|secret|password|client_secret)[\s\"':=]+[^\s\",}]+",
        r"gh[pousr]_[A-Za-z0-9_]{20,}",
        r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    )
    redacted = value
    for pattern in patterns:
        redacted = re.sub(pattern, "[REDACTED]", redacted)
    return redacted[:4096]


def digest_header_sha256(headers: Mapping[str, str]) -> str:
    raw = headers.get("Digest") or headers.get("digest") or ""
    require(raw.startswith("sha-256="), "source broker response is missing Digest: sha-256")
    try:
        decoded = base64.b64decode(raw.removeprefix("sha-256="), validate=True)
    except ValueError as exc:
        raise ContractError("source broker Digest header is invalid") from exc
    require(len(decoded) == 32, "source broker Digest header is invalid")
    return decoded.hex()


def write_github_output(values: Mapping[str, str]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    require(bool(output_path), "GITHUB_OUTPUT is unavailable")
    with Path(output_path).open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is not None, "invalid output key")
            require("\n" not in value and "\r" not in value, f"output {key} must be single-line")
            handle.write(f"{key}={value}\n")


def open_binary(path: Path) -> BinaryIO:
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("wb")
