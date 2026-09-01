#!/usr/bin/env python3
"""Security-focused helpers shared by the Jeeb reusable workflow tools."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import ssl
import tarfile
import tempfile
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
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {request_token}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            payload = json.load(response)
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise TransientRequestError(f"GitHub OIDC token request failed: {exc}") from exc
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
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            raw = response.read()
            status = response.status
            response_headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        raw = exc.read(16_384)
        detail = raw.decode("utf-8", errors="replace")
        raise HttpRequestError(
            exc.code,
            f"HTTP {exc.code} from trusted endpoint: {redact(detail)}",
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        detail = exc.reason if isinstance(exc, urllib.error.URLError) else exc
        raise TransientRequestError(f"trusted endpoint request failed: {detail}") from exc
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
        detail = exc.read(16_384).decode("utf-8", errors="replace")
        raise ContractError(f"HTTP {exc.code} from source broker: {redact(detail)}") from exc
    except urllib.error.URLError as exc:
        raise ContractError(f"source broker request failed: {exc.reason}") from exc
    require(status in expected, f"source broker returned unexpected HTTP {status}")
    return raw, response_headers


def redact(value: str) -> str:
    patterns = (
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
