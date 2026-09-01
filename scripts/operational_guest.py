#!/usr/bin/env python3
"""Deploy the proven Jeeb staging topology into one isolated Swarm lease."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import ipaddress
import json
import os
import re
import secrets
import select
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import quote

from operational_seed import (
    SeedContractError,
    build_user_seed_sql,
    build_wallet_seed_sql,
    roles_for,
    seed_counts,
    seed_digest,
    validate_seed_data,
    wallet_total,
)


FORBIDDEN = (
    "192.168.2.20",
    "192.168.2.39",
    "192.168.2.50",
    "jeeb-staging",
    "app.jeeb.fds-1.com",
    "cms.jeeb.fds-1.com",
)
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9./_-]+@sha256:[0-9a-f]{64}$")
SAFE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
COROOT_NODE_AGENT_IMAGE = (
    "ghcr.io/coroot/coroot-node-agent:1.35.8@"
    "sha256:aa14e9ea552ccda55ca31fe7a7f03b0f743f00c20d9971537cd4a4d85f4146d7"
)
COROOT_COLLECTOR_ENDPOINT = "https://coroot-staging.fds-3.space"
COROOT_CONTAINER_NAME = "coroot-ephemeral-node-agent"
LEGACY_FAKE_VOICE_COMMIT = "8f76393982e224306a30a067636109d3573f2f8b"
POSTGRES_DATABASES = {
    "jeeb-state-service": "jeeb_state_staging",
    "user-management": "jeeb-user-management_staging",
    "one-time-password": "jeeb-otpdb_staging",
    "wallet-service": "jeeb-wallet_staging",
    "feedback-service": "feedback_service_staging",
    "remote-user-preferences": "jeeb_remote_user_preferences_staging",
    "kyc-service": "jeeb_kyc_staging",
    "push-notification": "jeeb-push-notifications_staging",
    "realtime-comunication-service": "jeeb_realtime_comm_staging",
    "contract-signing-service": "jeeb_contract_signing_staging",
    "form-builder-service": "jeeb_form_builder_staging",
    "geolocation-service": "jeeb-location_staging",
    "delivery-service": "delivery_staging",
    "compliment-service": "compliment_staging",
    "offer-service": "offer_service_staging",
    "settlement-service": "jeeb_settlement_staging",
    "bundler-service": "jeeb_bundler_staging",
}
OFFER_SCHEMA_MIGRATIONS = (
    20260516000001,
    20260516000002,
    20260516000003,
    20260518082842,
    20260519140000,
    20260519140100,
    20260519160000,
    20260520090000,
    20260609000001,
    20260609000002,
)
URL_BY_PORT = {
    "10000": "http://jeeb-gateway:8080",
    "10001": "http://user-management:8080",
    "10014": "http://wallet-service:8080",
    "10026": "http://notification:8000",
    "10028": "http://chat-api:5176",
    "10036": "http://compliment-service:6070",
    "10037": "http://one-time-password:8080",
    "10040": "http://push-notification:8080",
    "10055": "http://delivery-service:8080",
    "10056": "http://bundler-service:8080",
    "10060": "http://geolocation-service:8000",
    "10062": "http://voice-transcription-service:8080",
    "10063": "http://offer-service:4040",
    "10064": "http://feedback-service:8080",
    "10065": "http://ban-service:3000",
    "10067": "http://remote-user-preferences:10023",
    "10069": "http://realtime-comunication-service:4000",
    "10070": "http://form-builder-service:8000",
    "10071": "http://contract-signing-service:8000",
    "10072": "http://cdn-service:8080",
    "10073": "http://jeeb-state-service:8080",
    "10074": "http://kyc-service:8080",
    "10075": "http://heart-beat:8080",
    "10090": "http://jeeb-gateway:8080",
}


class DeployError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DeployError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(
    argv: list[str],
    *,
    stdin: bytes | None = None,
    timeout: float = 1200,
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        argv,
        input=stdin,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        timeout=timeout,
        check=False,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or b"").decode(errors="replace")[-2000:]
        raise DeployError(f"command failed ({argv[0]}): {detail}")
    return result


def docker(*arguments: str, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
    return run(["docker", *arguments], **kwargs)


def bounded_command_output(
    argv: list[str],
    *,
    output_limit: int,
    timeout: float,
) -> subprocess.CompletedProcess[bytes]:
    require(output_limit > 0 and timeout > 0, "bounded command limits are invalid")
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    require(process.stdout is not None, "bounded command output is unavailable")
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        while len(output) <= output_limit:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            readable, _, _ = select.select([process.stdout.fileno()], [], [], remaining)
            if not readable:
                break
            chunk = os.read(
                process.stdout.fileno(),
                min(64 * 1024, output_limit + 1 - len(output)),
            )
            if not chunk:
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    try:
                        process.wait(timeout=remaining)
                    except subprocess.TimeoutExpired:
                        pass
                break
            output.extend(chunk)
        if process.poll() is None:
            process.kill()
        process.wait()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
    return subprocess.CompletedProcess(argv, process.returncode, bytes(output), b"")


def decode_chunked_http(body: bytes) -> bytes:
    decoded = bytearray()
    offset = 0
    while True:
        line_end = body.find(b"\r\n", offset)
        require(line_end >= 0, "Docker API returned an invalid chunked response")
        try:
            size = int(body[offset:line_end].split(b";", 1)[0], 16)
        except ValueError as exc:
            raise DeployError("Docker API returned an invalid chunk size") from exc
        offset = line_end + 2
        if size == 0:
            return bytes(decoded)
        chunk_end = offset + size
        require(chunk_end + 2 <= len(body), "Docker API returned a truncated chunk")
        decoded.extend(body[offset:chunk_end])
        require(body[chunk_end : chunk_end + 2] == b"\r\n", "Docker API chunk is malformed")
        offset = chunk_end + 2


def docker_api_post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    encoded = canonical(payload)
    request = (
        f"POST {path} HTTP/1.1\r\n"
        "Host: docker\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(encoded)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + encoded
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(30)
        client.connect("/var/run/docker.sock")
        client.sendall(request)
        response = bytearray()
        while True:
            block = client.recv(65536)
            if not block:
                break
            response.extend(block)
    headers, separator, body = bytes(response).partition(b"\r\n\r\n")
    require(bool(separator), "Docker API returned an invalid HTTP response")
    status_line = headers.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
    match = re.fullmatch(r"HTTP/1\.[01] ([0-9]{3})(?: .*)?", status_line)
    require(match is not None, "Docker API returned an invalid status line")
    header_lines = {
        key.strip().lower(): value.strip().lower()
        for key, separator, value in (line.partition(b":") for line in headers.split(b"\r\n")[1:])
        if separator
    }
    if header_lines.get(b"transfer-encoding") == b"chunked":
        body = decode_chunked_http(body)
    status = int(match.group(1))
    require(200 <= status < 300, f"Docker API update failed with HTTP {status}: {body[-1000:].decode(errors='replace')}")
    if not body:
        return {}
    try:
        result = json.loads(body)
    except json.JSONDecodeError as exc:
        raise DeployError("Docker API returned invalid JSON") from exc
    require(isinstance(result, dict), "Docker API response is not an object")
    return result


def configure_application_healthcheck(name: str, port: int, path: str) -> None:
    inspected = json.loads(docker("service", "inspect", name, capture=True).stdout)
    require(isinstance(inspected, list) and len(inspected) == 1, f"cannot inspect service {name}")
    service = inspected[0]
    service_id = service.get("ID")
    version = service.get("Version", {}).get("Index")
    spec = service.get("Spec")
    require(isinstance(service_id, str) and service_id, f"service {name} has no ID")
    require(isinstance(version, int) and version >= 1, f"service {name} has no version")
    require(isinstance(spec, dict), f"service {name} has no specification")
    container_spec = spec.get("TaskTemplate", {}).get("ContainerSpec")
    require(isinstance(container_spec, dict), f"service {name} has no container specification")
    container_spec["Healthcheck"] = {
        "Test": [
            "CMD",
            "/run/olivium/http-health-probe",
            "--url",
            f"http://127.0.0.1:{port}{path}",
        ],
        "Interval": 10_000_000_000,
        "Timeout": 5_000_000_000,
        "Retries": 60,
        "StartPeriod": 60_000_000_000,
    }
    docker_api_post(
        f"/v1.41/services/{quote(service_id, safe='')}/update?version={version}&registryAuthFrom=spec",
        spec,
    )


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DeployError(f"invalid JSON file: {path.name}") from exc


def load_template(path: Path) -> dict[str, Any]:
    try:
        encoded = path.read_text(encoding="ascii").strip()
        value = json.loads(gzip.decompress(base64.b64decode(encoded, validate=True)))
    except (OSError, ValueError, gzip.BadGzipFile, json.JSONDecodeError) as exc:
        raise DeployError("staging service template is invalid") from exc
    require(isinstance(value, dict), "staging service template must be an object")
    require(len(value.get("services", [])) == 24, "staging service template must contain 24 services")
    return value


def labels(lease_id: str, lock_hash: str, deployment_id: str, service_id: str | None = None) -> list[str]:
    values = {
        "com.olivium.ephemeral.managed": "true",
        "com.olivium.ephemeral.lease": lease_id,
        "com.olivium.ephemeral.lock-sha256": lock_hash,
        "com.olivium.ephemeral.deployment": deployment_id,
    }
    if service_id:
        values["com.olivium.ephemeral.service-id"] = service_id
    result: list[str] = []
    for key, value in sorted(values.items()):
        result.extend(("--label", f"{key}={value}"))
    return result


def wait_service(name: str, *, healthy: bool, timeout: int = 900) -> str:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        tasks = docker(
            "service",
            "ps",
            "--filter",
            "desired-state=running",
            "-q",
            name,
            capture=True,
            check=False,
        ).stdout.decode().split()
        if tasks:
            task = tasks[0]
            state = docker("inspect", "--format", "{{.Status.State}}", task, capture=True, check=False)
            if state.returncode == 0 and state.stdout.decode().strip() == "running":
                cid = docker(
                    "inspect",
                    "--format",
                    "{{.Status.ContainerStatus.ContainerID}}",
                    task,
                    capture=True,
                ).stdout.decode().strip()
                if not healthy:
                    return cid
                status = docker(
                    "container",
                    "inspect",
                    "--format",
                    "{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}",
                    cid,
                    capture=True,
                    check=False,
                )
                last = status.stdout.decode().strip()
                if status.returncode == 0 and last == "healthy":
                    return cid
        time.sleep(5)
    raise DeployError(f"service {name} did not become {'healthy' if healthy else 'running'} (last={last})")


def wait_application(name: str, port: int, path: str, timeout: int = 1200) -> str:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            container_id = wait_service(name, healthy=False, timeout=30)
        except DeployError as exc:
            last = str(exc)
            time.sleep(5)
            continue
        probe = docker(
            "exec",
            container_id,
            "/run/olivium/http-health-probe",
            "--url",
            f"http://127.0.0.1:{port}{path}",
            capture=True,
            check=False,
        )
        if probe.returncode == 0:
            return container_id
        last = (probe.stderr or probe.stdout or b"").decode(errors="replace")[-1000:]
        time.sleep(5)
    raise DeployError(f"application did not become ready: {name}: {last}")


def database_url(service_id: str, password: str) -> str:
    database = POSTGRES_DATABASES[service_id]
    user = "oudaykhaled"
    encoded_user = quote(user, safe="")
    encoded_password = quote(password, safe="")
    if service_id in {"form-builder-service"}:
        return f"postgresql+psycopg2://{encoded_user}:{encoded_password}@postgresql:5432/{database}"
    if service_id == "geolocation-service":
        return f"postgresql+asyncpg://{encoded_user}:{encoded_password}@postgresql:5432/{database}"
    if service_id in {"offer-service", "realtime-comunication-service"}:
        return f"ecto://{encoded_user}:{encoded_password}@postgresql:5432/{database}"
    return f"postgresql://{encoded_user}:{encoded_password}@postgresql:5432/{database}?sslmode=disable"


def dotnet_connection(service_id: str, password: str) -> str:
    database = POSTGRES_DATABASES[service_id]
    return (
        f"Host=postgresql;Port=5432;Database={database};Username=oudaykhaled;"
        f"Password={password};Trust Server Certificate=true"
    )


def rewrite_service_url(value: str) -> str:
    for port, replacement in URL_BY_PORT.items():
        value = value.replace(f"http://192.168.2.20:{port}", replacement)
        value = value.replace(f"https://192.168.2.20:{port}", replacement)
    return value


def transformed_environment(
    service: dict[str, Any],
    template_service: dict[str, Any],
    *,
    postgres_password: str,
    mongo_password: str,
    super_login_passcode: str,
    public_hostname: str,
    private_ip: str,
    gateway_routes: list[dict[str, Any]],
    openai_api_key: str = "",
) -> dict[str, str]:
    service_id = service["id"]
    environment: dict[str, str] = {}
    for row in template_service.get("env", []):
        key, separator, value = row.partition("=")
        require(bool(separator) and bool(key), f"invalid environment entry for {service_id}")
        value = rewrite_service_url(value)
        value = value.replace("app.jeeb.fds-1.com", public_hostname)
        value = value.replace("cms.jeeb.fds-1.com", public_hostname)
        value = value.replace("https://jeeb-staging.fds-1.com", f"https://{public_hostname}")
        value = value.replace("jeeb-staging-", "")
        environment[key] = value

    if service_id in POSTGRES_DATABASES:
        for key in list(environment):
            lowered = key.lower()
            if key == "DB_PASSWORD":
                environment[key] = postgres_password
            elif key == "DB_HOST":
                environment[key] = "postgresql"
            elif key == "DB_PORT":
                environment[key] = "5432"
            elif key == "DB_USER":
                environment[key] = "oudaykhaled"
            elif key == "DB_SSLMODE":
                environment[key] = "disable"
            elif "connectionstrings__" in lowered:
                environment[key] = dotnet_connection(service_id, postgres_password)
            elif key == "DATABASE_URL":
                environment[key] = database_url(service_id, postgres_password)
        environment["SKIP_DB_INIT"] = "true"

    if service_id == "user-management":
        require(super_login_passcode, "ephemeral super-login passcode is unavailable")
        environment["SuperAdmin__PassCode"] = super_login_passcode

    if service_id == "notification-service":
        environment["DB_PASSWORD"] = mongo_password
        environment["MONGODB_DATABASE"] = "jeeb_notifications_staging"
        environment["MONGODB_CONNECTION_STRING"] = (
            f"mongodb://mongo_admin:{quote(mongo_password, safe='')}@mongodb:27017/"
            "jeeb_notifications_staging?authSource=admin"
        )
        environment["SKIP_DB_INIT"] = "false"

    for key, value in list(environment.items()):
        if "redis" in key.lower() or "redis://" in value:
            environment[key] = value.replace("192.168.2.20", "redis")

    if service_id == "bundler-service":
        environment.update(
            {
                "DB_HOST": "postgresql",
                "DB_PORT": "5432",
                "DB_USER": "oudaykhaled",
                "DB_NAME": POSTGRES_DATABASES[service_id],
                "DB_SSLMODE": "disable",
                "ENVIRONMENT": "ephemeral",
                "BUNDLER_SERVER_MODE": "ephemeral",
            }
        )

    if service_id == "chat-service":
        environment["CHAT_STORE_MODE"] = "InMemory"
        environment.pop("Firestore__DatabaseId", None)
        environment.pop("Firestore__ProjectId", None)
        environment.pop("Firestore__KeyFilePath", None)
        environment.pop("GOOGLE_APPLICATION_CREDENTIALS", None)

    if service_id == "voice-transcription-service":
        environment.pop("OPENAI_API_KEY", None)
        if openai_api_key:
            environment["ENVIRONMENT"] = "production"
            environment["OPENAI_API_KEY_FILE"] = "/run/secrets/openai-ephemeral-sandbox-api-key"
            environment["WHISPER_FAKE_TRANSCRIBE"] = "0"
        else:
            environment.pop("OPENAI_API_KEY_FILE", None)
            environment["WHISPER_FAKE_TRANSCRIBE"] = "1"

    if service_id == "realtime-comunication-service":
        environment["PHX_HOST"] = public_hostname

    if service_id == "jeeb-state-service":
        environment["CaseManagement__GatewayCallbackUrl"] = (
            f"http://{private_ip}:10000/internal/case-management/callback"
        )

    if service_id == "form-builder-service":
        environment["API_BASE_URL"] = "http://jeeb-gateway:8080"
        environment["GATEWAY_URL_OVERRIDE"] = "http://jeeb-gateway:8080"

    if service_id == "offer-service":
        environment["CHAT_SERVICE_URL"] = "http://chat-api:5176"
        environment["NOTIFICATION_SERVICE_URL"] = "http://notification:8000"
        environment["FORCE_EXPIRE_SEAM_ENABLED"] = "false"

    if service_id == "jeeb-gateway":
        environment["Gateway__PublicBaseUrl"] = f"https://{public_hostname}"
        environment["Jwt__Issuer"] = f"https://{public_hostname}"
        environment["AdminPortal__AllowedOrigins__0"] = f"https://{public_hostname}"
        environment.pop("AdminPortal__AllowedOrigins__1", None)
        environment["Redis__ConnectionString"] = "redis:6379,defaultDatabase=1,abortConnect=false"
        environment["GatewayRateLimit__RedisConnectionString"] = (
            "redis:6379,defaultDatabase=2,abortConnect=false"
        )
        for route in gateway_routes:
            if "value" in route:
                environment[route["configKey"]] = route["value"]
        environment["Services__Realtime__PublicSocketUrl"] = (
            f"wss://{public_hostname}/realtime/socket/websocket"
        )

    serialized = "\n".join(f"{key}={value}" for key, value in sorted(environment.items()))
    for forbidden in FORBIDDEN:
        require(forbidden not in serialized, f"{service_id} still references forbidden endpoint {forbidden}")
    return environment


def ensure_network(name: str, lease_id: str, lock_hash: str, deployment_id: str) -> None:
    existing = docker("network", "inspect", name, capture=True, check=False)
    if existing.returncode == 0:
        return
    docker(
        "network",
        "create",
        "--driver",
        "overlay",
        "--opt",
        "encrypted",
        "--attachable",
        *labels(lease_id, lock_hash, deployment_id),
        name,
    )


def ensure_volume(name: str, lease_id: str, lock_hash: str, deployment_id: str) -> None:
    if docker("volume", "inspect", name, capture=True, check=False).returncode == 0:
        return
    docker("volume", "create", *labels(lease_id, lock_hash, deployment_id), name)


def write_restricted_secret(path: Path, value: str) -> None:
    payload = value.encode()
    if path.exists():
        metadata = path.lstat()
        require(
            stat.S_ISREG(metadata.st_mode)
            and not path.is_symlink()
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o400,
            "Coroot credential file has unsafe ownership or permissions",
        )
        require(secrets.compare_digest(path.read_bytes(), payload), "Coroot credential file does not match")
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            metadata = os.fstat(handle.fileno())
            require(
                metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o400,
                "Coroot credential file was not created securely",
            )
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def wait_coroot_node_agent(api_key: str, timeout: int = 90) -> None:
    deadline = time.monotonic() + timeout
    last = "container has not started"
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            inspected = docker(
                "container",
                "inspect",
                COROOT_CONTAINER_NAME,
                capture=True,
                check=False,
                timeout=remaining,
            )
        except subprocess.TimeoutExpired:
            last = "container inspection timed out"
            continue
        if inspected.returncode != 0:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(3, remaining))
            continue
        try:
            rows = json.loads(inspected.stdout)
        except json.JSONDecodeError as exc:
            raise DeployError("Coroot container inspection returned invalid JSON") from exc
        require(isinstance(rows, list) and len(rows) == 1, "Coroot container inspection is incomplete")
        row = rows[0]
        serialized = json.dumps(row, sort_keys=True)
        require(api_key not in serialized, "Coroot API key leaked into Docker metadata")
        require(row["Config"]["Image"] == COROOT_NODE_AGENT_IMAGE, "Coroot agent image is not pinned")
        command = row["Config"].get("Cmd")
        require(isinstance(command, list), "Coroot agent command metadata is invalid")
        command_text = "\n".join(str(part) for part in command)
        require(
            'export API_KEY="$api_key"' in command_text
            and "COROOT_API_KEY" not in command_text,
            "Coroot agent does not use the documented Linux API key environment",
        )
        require(row["HostConfig"]["Privileged"] is True, "Coroot agent is not privileged")
        require(row["HostConfig"]["PidMode"] == "host", "Coroot agent cannot see host processes")
        require(not row["HostConfig"].get("PortBindings"), "Coroot agent publishes a host port")
        if row["State"]["Running"] is not True:
            last = row["State"].get("Status", "not running")
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(3, remaining))
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        probe = bounded_command_output(
            [
                "docker",
                "exec",
                COROOT_CONTAINER_NAME,
                "/usr/bin/curl",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "5",
                "http://127.0.0.1:10300/metrics",
            ],
            output_limit=2_000_000,
            timeout=min(10, remaining),
        )
        if (
            probe.returncode == 0
            and len(probe.stdout) <= 2_000_000
            and b"node_agent_info" in probe.stdout
        ):
            return
        last = "namespace-local metrics endpoint is unavailable"
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(3, remaining))
    raise DeployError(f"Coroot node agent did not become ready: {last}")


def deploy_coroot_node_agent(
    *,
    state_dir: Path,
    api_key: str,
    lease_id: str,
    lock_hash: str,
    deployment_id: str,
) -> None:
    request = urllib.request.Request(
        f"{COROOT_COLLECTOR_ENDPOINT}/health",
        headers={"User-Agent": "olivium-jeeb-ephemeral-agent/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            require(response.status == 200, "Coroot collector health check failed")
    except urllib.error.URLError as exc:
        raise DeployError("Coroot collector is unreachable from the lease") from exc
    authenticated_request = urllib.request.Request(
        f"{COROOT_COLLECTOR_ENDPOINT}/v1/config",
        headers={
            "User-Agent": "olivium-jeeb-ephemeral-agent/1",
            "X-Api-Key": api_key,
        },
    )
    try:
        with urllib.request.urlopen(authenticated_request, timeout=15) as response:
            require(response.status == 200, "Coroot collector rejected the protected API key")
            response.read(2_000_000)
    except urllib.error.URLError as exc:
        raise DeployError("Coroot collector rejected the protected API key") from exc

    secret_dir = state_dir / "coroot"
    secret_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(secret_dir, 0o700)
    key_path = secret_dir / "api-key"
    write_restricted_secret(key_path, api_key)

    if docker("container", "inspect", COROOT_CONTAINER_NAME, capture=True, check=False).returncode == 0:
        wait_coroot_node_agent(api_key)
        return

    volume = f"jeeb-eph-{lease_id}-coroot-agent-data"
    ensure_volume(volume, lease_id, lock_hash, deployment_id)
    docker("pull", COROOT_NODE_AGENT_IMAGE, timeout=1800)
    entrypoint = (
        'api_key="$(cat /run/secrets/coroot-api-key)"; '
        'test -n "$api_key"; export API_KEY="$api_key"; unset api_key; '
        "exec /usr/bin/coroot-node-agent "
        '--collector-endpoint="$COROOT_COLLECTOR_ENDPOINT" '
        "--cgroupfs-root=/host/sys/fs/cgroup --wal-dir=/data"
    )
    docker(
        "run",
        "--detach",
        "--name",
        COROOT_CONTAINER_NAME,
        "--restart",
        "unless-stopped",
        "--privileged",
        "--pid",
        "host",
        "--cpus",
        "0.75",
        "--memory",
        "768m",
        *labels(lease_id, lock_hash, deployment_id, "coroot-node-agent"),
        "--env",
        f"COROOT_COLLECTOR_ENDPOINT={COROOT_COLLECTOR_ENDPOINT}",
        "--log-driver",
        "json-file",
        "--log-opt",
        "max-size=10m",
        "--log-opt",
        "max-file=3",
        "--mount",
        "type=bind,source=/sys/kernel/tracing,target=/sys/kernel/tracing",
        "--mount",
        "type=bind,source=/sys/kernel/debug,target=/sys/kernel/debug",
        "--mount",
        "type=bind,source=/sys/fs/cgroup,target=/host/sys/fs/cgroup,readonly",
        "--mount",
        f"type=bind,source={key_path},target=/run/secrets/coroot-api-key,readonly",
        "--mount",
        f"type=volume,source={volume},target=/data",
        "--entrypoint",
        "/bin/sh",
        COROOT_NODE_AGENT_IMAGE,
        "-ec",
        entrypoint,
        timeout=1800,
    )
    wait_coroot_node_agent(api_key)


def create_infrastructure(
    config: dict[str, Any],
    *,
    prefix: str,
    network: str,
    lease_id: str,
    lock_hash: str,
    deployment_id: str,
    postgres_password: str,
    mongo_password: str,
) -> None:
    images = {item["id"]: item["image"] for item in config["infrastructure"]}
    for component in ("postgresql", "mongodb", "redis", "lease-local-registry"):
        docker("pull", images[component], timeout=1800)

    postgres_volume = f"{prefix}-postgresql-data"
    mongo_volume = f"{prefix}-mongodb-data"
    registry_volume = f"{prefix}-registry-data"
    for volume in (postgres_volume, mongo_volume, registry_volume):
        ensure_volume(volume, lease_id, lock_hash, deployment_id)

    common = labels(lease_id, lock_hash, deployment_id)
    docker(
        "service",
        "create",
        "--detach=true",
        "--name",
        f"{prefix}-postgresql",
        *common,
        "--network",
        f"name={network},alias=postgresql",
        "--mount",
        f"type=volume,source={postgres_volume},target=/var/lib/postgresql/data",
        "--env",
        "POSTGRES_USER=oudaykhaled",
        "--env",
        f"POSTGRES_PASSWORD={postgres_password}",
        "--env",
        "POSTGRES_DB=postgres",
        "--limit-cpu",
        "2",
        "--limit-memory",
        "4G",
        images["postgresql"],
    )
    postgres_cid = wait_service(f"{prefix}-postgresql", healthy=False)
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        ready = docker(
            "exec",
            postgres_cid,
            "pg_isready",
            "-U",
            "oudaykhaled",
            "-d",
            "postgres",
            capture=True,
            check=False,
        )
        if ready.returncode == 0:
            break
        time.sleep(3)
    else:
        raise DeployError("PostgreSQL did not become ready")

    docker(
        "service",
        "create",
        "--detach=true",
        "--name",
        f"{prefix}-mongodb",
        *common,
        "--network",
        f"name={network},alias=mongodb",
        "--mount",
        f"type=volume,source={mongo_volume},target=/data/db",
        "--env",
        "MONGO_INITDB_ROOT_USERNAME=mongo_admin",
        "--env",
        f"MONGO_INITDB_ROOT_PASSWORD={mongo_password}",
        "--limit-cpu",
        "2",
        "--limit-memory",
        "4G",
        images["mongodb"],
    )
    mongo_cid = wait_service(f"{prefix}-mongodb", healthy=False, timeout=300)
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        ready = docker(
            "exec",
            mongo_cid,
            "mongosh",
            "--quiet",
            "--username",
            "mongo_admin",
            "--password",
            mongo_password,
            "--authenticationDatabase",
            "admin",
            "--eval",
            "db.adminCommand({ping:1}).ok",
            capture=True,
            check=False,
        )
        if ready.returncode == 0 and ready.stdout.strip() == b"1":
            break
        time.sleep(3)
    else:
        raise DeployError("MongoDB did not become ready")

    docker(
        "service",
        "create",
        "--detach=true",
        "--name",
        f"{prefix}-redis",
        *common,
        "--network",
        f"name={network},alias=redis",
        "--limit-cpu",
        "0.5",
        "--limit-memory",
        "1G",
        images["redis"],
    )
    redis_cid = wait_service(f"{prefix}-redis", healthy=False)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        ready = docker("exec", redis_cid, "redis-cli", "ping", capture=True, check=False)
        if ready.returncode == 0 and ready.stdout.strip() == b"PONG":
            break
        time.sleep(2)
    else:
        raise DeployError("Redis did not become ready")

    docker(
        "service",
        "create",
        "--detach=true",
        "--name",
        f"{prefix}-lease-local-registry",
        *common,
        "--network",
        f"name={network},alias=lease-local-registry",
        "--mount",
        f"type=volume,source={registry_volume},target=/var/lib/registry",
        "--limit-cpu",
        "0.5",
        "--limit-memory",
        "512M",
        images["lease-local-registry"],
    )
    wait_service(f"{prefix}-lease-local-registry", healthy=False)


def restore_postgres(schema_path: Path, prefix: str) -> None:
    cid = wait_service(f"{prefix}-postgresql", healthy=False)
    payload = gzip.decompress(schema_path.read_bytes())
    result = docker(
        "exec",
        "-i",
        cid,
        "sh",
        "-ceu",
        'export PGPASSWORD="$POSTGRES_PASSWORD"; exec psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres',
        stdin=payload,
        capture=True,
        timeout=900,
        check=False,
    )
    if result.returncode != 0:
        raise DeployError(f"PostgreSQL schema restore failed: {result.stderr.decode(errors='replace')[-2000:]}")


def record_offer_migration_ledger(prefix: str) -> None:
    cid = wait_service(f"{prefix}-postgresql", healthy=False)
    values = ",\n".join(f"({version}, CURRENT_TIMESTAMP)" for version in OFFER_SCHEMA_MIGRATIONS)
    payload = (
        "INSERT INTO public.schema_migrations (version, inserted_at) VALUES\n"
        f"{values}\nON CONFLICT (version) DO NOTHING;\n"
    ).encode()
    result = docker(
        "exec",
        "-i",
        cid,
        "sh",
        "-ceu",
        'export PGPASSWORD="$POSTGRES_PASSWORD"; '
        'exec psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d offer_service_staging',
        stdin=payload,
        capture=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        raise DeployError(f"Offer migration ledger restore failed: {result.stderr.decode(errors='replace')[-2000:]}")


def execute_seed_sql(prefix: str, database: str, payload: bytes, label: str) -> dict[str, Any]:
    cid = wait_service(f"{prefix}-postgresql", healthy=False)
    result = docker(
        "exec",
        "-i",
        cid,
        "sh",
        "-ceu",
        'export PGPASSWORD="$POSTGRES_PASSWORD"; '
        f'exec psql -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d {database}',
        stdin=payload,
        capture=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace")[-2000:]
        raise DeployError(f"{label} seed failed: {detail}")
    lines = [line for line in result.stdout.decode(errors="strict").splitlines() if line.strip()]
    require(lines, f"{label} seed returned no verification receipt")
    try:
        receipt = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise DeployError(f"{label} seed returned an invalid verification receipt") from exc
    require(isinstance(receipt, dict), f"{label} seed verification receipt must be an object")
    return receipt


def apply_seed_data(config: dict[str, Any], prefix: str) -> dict[str, int]:
    seed_data = config["seedData"]
    counts = seed_counts(seed_data)
    user_receipt = execute_seed_sql(
        prefix,
        POSTGRES_DATABASES["user-management"],
        build_user_seed_sql(seed_data),
        "user-management",
    )
    require(user_receipt.get("users") == counts["users"], "user-management seed count mismatch")
    wallet_receipt = execute_seed_sql(
        prefix,
        POSTGRES_DATABASES["wallet-service"],
        build_wallet_seed_sql(seed_data),
        "wallet-service",
    )
    expected_balance = sum((wallet_total(user) for user in seed_data["users"]), Decimal("0"))
    require(wallet_receipt.get("wallets") == counts["wallets"], "wallet seed count mismatch")
    try:
        actual_balance = Decimal(str(wallet_receipt.get("balance")))
    except Exception as exc:
        raise DeployError("wallet seed balance receipt is invalid") from exc
    require(actual_balance == expected_balance, "wallet seed balance mismatch")
    return counts


def service_environment(service_name: str) -> dict[str, str]:
    result = docker(
        "service",
        "inspect",
        "--format",
        "{{json .Spec.TaskTemplate.ContainerSpec.Env}}",
        service_name,
        capture=True,
    )
    values = json.loads(result.stdout)
    require(isinstance(values, list), f"service environment is invalid: {service_name}")
    environment: dict[str, str] = {}
    for value in values:
        key, separator, content = str(value).partition("=")
        if separator:
            environment[key] = content
    return environment


def gateway_json(path: str, *, payload: dict[str, Any] | None = None, token: str | None = None) -> Any:
    headers = {"Accept": "application/json", "User-Agent": "olivium-jeeb-seed-validator/1"}
    data = None
    method = "GET"
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
        method = "POST"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"http://127.0.0.1:10000{path}",
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            require(200 <= response.status < 300, f"gateway seed validation failed for {path}")
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        exc.read()
        raise DeployError(f"gateway seed validation failed for {path} (status {exc.code})") from exc
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        raise DeployError(f"gateway seed validation failed for {path}") from exc


def validate_seed_gateway(config: dict[str, Any], prefix: str) -> None:
    seed_data = config["seedData"]
    roster = gateway_json("/api/User/super-login/users")
    rows = roster.get("users") if isinstance(roster, dict) else None
    require(isinstance(rows, list), "gateway seed roster is invalid")
    by_id = {str(row.get("userId")): row for row in rows if isinstance(row, dict)}
    for user in seed_data["users"]:
        row = by_id.get(user["id"])
        require(row is not None, f"gateway roster is missing seeded user {user['id']}")
        roles, active_role, _ = roles_for(user["type"])
        require(row.get("name") == user["username"], f"gateway roster name mismatch for {user['id']}")
        require(row.get("role") == active_role, f"gateway roster role mismatch for {user['id']}")
        require(row.get("roles") == roles, f"gateway roster roles mismatch for {user['id']}")

    environment = service_environment(f"{prefix}-user-management")
    passcode = environment.get("SuperAdmin__PassCode", "")
    require(passcode, "user-management super-login passcode is unavailable")
    login_tokens: dict[str, str] = {}
    for user in seed_data["users"]:
        login = gateway_json(
            "/api/User/user-id-login",
            payload={"userId": user["id"], "superAdminPassCode": passcode},
        )
        require(isinstance(login, dict), f"seed login response is invalid for {user['id']}")
        token = login.get("authToken") or login.get("AuthToken")
        require(isinstance(token, str) and token.count(".") == 2, f"seed login returned no token for {user['id']}")
        login_tokens[user["id"]] = token

    for jeeber in (user for user in seed_data["users"] if user["type"] == "jeeber"):
        wallet = gateway_json("/v1/jeeb/wallet", token=login_tokens[jeeber["id"]])
        require(isinstance(wallet, dict) and "availableBalance" in wallet, "Jeeber wallet response is invalid")
        require(
            Decimal(str(wallet["availableBalance"])) == wallet_total(jeeber),
            f"Jeeber public wallet balance does not match seed data for {jeeber['id']}",
        )

    for admin in (user for user in seed_data["users"] if user["type"] == "admin"):
        session = gateway_json("/admin/session", token=login_tokens[admin["id"]])
        capabilities = session.get("capabilities") if isinstance(session, dict) else None
        require(
            isinstance(capabilities, list) and "admin.portal.access" in capabilities,
            f"admin portal capability is unavailable for {admin['id']}",
        )


def configure_public_gateway(config_path: Path = Path("/etc/nginx/sites-available/default")) -> None:
    config_path.write_text(
        """server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    location = /.well-known/olivium-lease {
        default_type text/plain;
        alias /etc/olivium-ephemeral-lease;
    }

    location = /gateway {
        return 308 /gateway/;
    }

    location /gateway/ {
        proxy_pass http://127.0.0.1:10000/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300s;
        proxy_buffering off;
    }

    location = /health {
        proxy_pass http://127.0.0.1:10080/health;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location ~ ^/(?:api|v1|admin|health)(?:/|$) {
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300s;
        proxy_buffering off;
    }

    location / {
        proxy_pass http://127.0.0.1:10080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
""",
        encoding="ascii",
    )
    os.chmod(config_path, 0o644)
    run(["nginx", "-t"])
    run(["systemctl", "reload", "nginx"])


def create_config(name: str, content: bytes, lease_id: str, lock_hash: str, deployment_id: str) -> None:
    if docker("config", "inspect", name, capture=True, check=False).returncode == 0:
        return
    docker("config", "create", *labels(lease_id, lock_hash, deployment_id), name, "-", stdin=content)


def create_secret(name: str, content: bytes, lease_id: str, lock_hash: str, deployment_id: str) -> None:
    if docker("secret", "inspect", name, capture=True, check=False).returncode == 0:
        return
    docker("secret", "create", *labels(lease_id, lock_hash, deployment_id), name, "-", stdin=content)


def mount_owner(value: Any, *, service_id: str, field: str) -> str:
    owner = str(value if value is not None else "0")
    require(owner.isdigit() and 0 <= int(owner) <= 2**31 - 1, f"invalid {field} for {service_id}")
    return owner


def mount_spec(mount: dict[str, Any]) -> str:
    return (
        f"source={mount['name']},target={mount['target']},uid={mount['uid']},"
        f"gid={mount['gid']},mode={mount['mode']:04o}"
    )


def materialize_mounts(
    template: dict[str, Any],
    template_service: dict[str, Any],
    *,
    prefix: str,
    lease_id: str,
    lock_hash: str,
    deployment_id: str,
    service_id: str,
    postgres_password: str,
    openai_api_key: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    secret_mounts: list[dict[str, Any]] = []
    for index, mount in enumerate(template_service.get("secrets", [])):
        old_name = mount["name"]
        require(old_name in template.get("secrets", {}), f"missing secret material for {service_id}")
        value = template["secrets"][old_name].encode()
        if mount["target"] == "bundler_db_password":
            value = postgres_password.encode()
        elif mount["target"] == "settlement_database_url":
            value = dotnet_connection("settlement-service", postgres_password).encode()
        name = f"{prefix}-{service_id}-secret-{index:02d}"
        create_secret(name, value, lease_id, lock_hash, deployment_id)
        secret_mounts.append(
            {
                "name": name,
                "target": mount["target"],
                "uid": mount_owner(mount.get("uid"), service_id=service_id, field="secret UID"),
                "gid": mount_owner(mount.get("gid"), service_id=service_id, field="secret GID"),
                "mode": int(mount["mode"]),
            }
        )

    if service_id == "voice-transcription-service" and openai_api_key:
        name = f"{prefix}-voice-transcription-service-openai"
        create_secret(name, openai_api_key.encode(), lease_id, lock_hash, deployment_id)
        secret_mounts.append(
            {
                "name": name,
                "target": "openai-ephemeral-sandbox-api-key",
                "uid": "65532",
                "gid": "65532",
                "mode": 0o400,
            }
        )

    config_mounts: list[dict[str, Any]] = []
    for index, mount in enumerate(template_service.get("configs", [])):
        old_name = mount["name"]
        require(old_name in template.get("configs", {}), f"missing config material for {service_id}")
        if service_id == "chat-service":
            continue
        value = template["configs"][old_name].encode()
        name = f"{prefix}-{service_id}-config-{index:02d}"
        create_config(name, value, lease_id, lock_hash, deployment_id)
        config_mounts.append(
            {
                "name": name,
                "target": mount["target"],
                "uid": mount_owner(mount.get("uid"), service_id=service_id, field="config UID"),
                "gid": mount_owner(mount.get("gid"), service_id=service_id, field="config GID"),
                "mode": int(mount["mode"]),
            }
        )
    return secret_mounts, config_mounts


def create_application(
    service: dict[str, Any],
    template: dict[str, Any],
    template_service: dict[str, Any],
    catalog: dict[str, Any],
    *,
    prefix: str,
    network: str,
    lease_id: str,
    lock_hash: str,
    deployment_id: str,
    postgres_password: str,
    mongo_password: str,
    super_login_passcode: str,
    openai_api_key: str,
    public_hostname: str,
    private_ip: str,
    probe_config: str,
) -> None:
    service_id = service["id"]
    image = service["image"]
    digest = image.rsplit("@", 1)[1]
    environment = transformed_environment(
        service,
        template_service,
        postgres_password=postgres_password,
        mongo_password=mongo_password,
        super_login_passcode=super_login_passcode,
        public_hostname=public_hostname,
        private_ip=private_ip,
        gateway_routes=catalog["gatewayRouting"],
        openai_api_key=openai_api_key,
    )
    secret_mounts, config_mounts = materialize_mounts(
        template,
        template_service,
        prefix=prefix,
        lease_id=lease_id,
        lock_hash=lock_hash,
        deployment_id=deployment_id,
        service_id=service_id,
        postgres_password=postgres_password,
        openai_api_key=openai_api_key,
    )
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", prefix="jeeb-env-", delete=False) as handle:
        for key, value in sorted(environment.items()):
            require("\n" not in value and "\r" not in value, f"multiline environment value for {service_id}")
            handle.write(f"{key}={value}\n")
        env_path = Path(handle.name)
    os.chmod(env_path, 0o600)
    try:
        command = [
            "service",
            "create",
            "--detach=true",
            "--name",
            f"{prefix}-{service_id}",
            *labels(lease_id, lock_hash, deployment_id, service_id),
            "--label",
            f"com.olivium.ephemeral.image-digest={digest}",
            "--network",
            f"name={network},alias={service['stagingName'].removeprefix('jeeb-staging-')}",
            "--env-file",
            str(env_path),
            "--config",
            f"source={probe_config},target=/run/olivium/http-health-probe,mode=0555",
            "--restart-condition",
            "any",
            "--limit-cpu",
            "1",
            "--limit-memory",
            "1G",
            "--log-driver",
            "json-file",
            "--log-opt",
            "max-size=10m",
            "--log-opt",
            "max-file=3",
        ]
        for mount in secret_mounts:
            command.extend(("--secret", mount_spec(mount)))
        for mount in config_mounts:
            command.extend(("--config", mount_spec(mount)))
        if service_id == "cdn-service":
            volume = f"{prefix}-cdn-data"
            ensure_volume(volume, lease_id, lock_hash, deployment_id)
            command.extend(("--mount", f"type=volume,source={volume},target=/app/uploads"))
        if service_id == "jeeb-gateway":
            command.extend(("--publish", f"published=10000,target={service['internalPort']},mode=host"))
        command.extend(("--with-registry-auth", image))
        docker(*command, timeout=1800)
        configure_application_healthcheck(
            f"{prefix}-{service_id}",
            int(service["internalPort"]),
            service["healthPath"],
        )
    finally:
        env_path.unlink(missing_ok=True)


def create_web_application(
    application: dict[str, Any],
    *,
    prefix: str,
    network: str,
    lease_id: str,
    lock_hash: str,
    deployment_id: str,
    probe_config: str,
) -> None:
    application_id = application["id"]
    image = application["image"]
    digest = image.rsplit("@", 1)[1]
    command = [
        "service",
        "create",
        "--detach=true",
        "--name",
        f"{prefix}-{application_id}",
        *labels(lease_id, lock_hash, deployment_id, application_id),
        "--label",
        f"com.olivium.ephemeral.image-digest={digest}",
        "--network",
        f"name={network},alias={application_id}",
        "--config",
        f"source={probe_config},target=/run/olivium/http-health-probe,mode=0555",
        "--restart-condition",
        "any",
        "--limit-cpu",
        "1",
        "--limit-memory",
        "1G",
        "--log-driver",
        "json-file",
        "--log-opt",
        "max-size=10m",
        "--log-opt",
        "max-file=3",
        "--publish",
        f"published={application['hostPort']},target={application['internalPort']},mode=host",
        "--with-registry-auth",
        image,
    ]
    docker(*command, timeout=1800)
    configure_application_healthcheck(
        f"{prefix}-{application_id}",
        int(application["internalPort"]),
        application["healthPath"],
    )


def validate_config(config: dict[str, Any], catalog: dict[str, Any]) -> None:
    require(config.get("apiVersion") == "olivium.dev/jeeb-operational-ephemeral/v1", "unsupported config")
    services = config.get("services")
    require(isinstance(services, list) and len(services) == 24, "config must contain exactly 24 services")
    ids = [item.get("id") for item in services]
    catalog_ids = [item.get("id") for item in catalog.get("services", [])]
    require(len(set(ids)) == 24 and set(ids) == set(catalog_ids), "service set does not match catalog")
    for item in services:
        require(SAFE_ID_RE.fullmatch(item["id"]) is not None, "invalid service ID")
        require(IMAGE_RE.fullmatch(item["image"]) is not None, f"image is not digest-pinned: {item['id']}")
        require(item["repository"] == f"olivium-dev/{item['id']}", f"repository mismatch: {item['id']}")
    web_applications = config.get("webApplications")
    require(isinstance(web_applications, list) and len(web_applications) == 1, "config must contain one web application")
    web_application = web_applications[0]
    require(isinstance(web_application, dict), "web application must be an object")
    require(web_application.get("id") == "jeeb-cms", "web application must be jeeb-cms")
    require(web_application.get("repository") == "olivium-dev/jeeb-cms", "jeeb-cms repository is invalid")
    require(IMAGE_RE.fullmatch(str(web_application.get("image", ""))) is not None, "jeeb-cms image is not digest-pinned")
    require(web_application.get("internalPort") == 8080, "jeeb-cms internal port must be 8080")
    require(web_application.get("hostPort") == 10080, "jeeb-cms host port must be 10080")
    require(web_application.get("healthPath") == "/health", "jeeb-cms health path must be /health")
    try:
        validate_seed_data(config.get("seedData"))
    except SeedContractError as exc:
        raise DeployError(str(exc)) from exc


def validate_openai_credential(config: dict[str, Any], openai_api_key: Any) -> str:
    require(isinstance(openai_api_key, str), "ephemeral OpenAI credential is invalid")
    if openai_api_key:
        require(
            20 <= len(openai_api_key) <= 4096
            and openai_api_key == openai_api_key.strip()
            and openai_api_key.isprintable()
            and not any(character.isspace() for character in openai_api_key),
            "ephemeral OpenAI credential is invalid",
        )
    voice_service = next(item for item in config["services"] if item["id"] == "voice-transcription-service")
    require(
        bool(openai_api_key) or voice_service["commit"] == LEGACY_FAKE_VOICE_COMMIT,
        "non-legacy voice deployment requires the protected OpenAI credential",
    )
    return openai_api_key


def deploy(args: argparse.Namespace) -> None:
    require(os.geteuid() == 0, "guest deployment must run as root")
    config = load_json(args.config)
    catalog = load_json(args.catalog)
    lock = load_json(args.deployment_lock)
    template = load_template(args.stage_template)
    validate_config(config, catalog)
    require(sha256_file(args.postgres_schema) == config["bootstrap"]["postgresSchemaSha256"], "schema digest mismatch")
    lock_payload = dict(lock)
    lock_hash = lock_payload.pop("lockSha256", "")
    require(hashlib.sha256(canonical(lock_payload)).hexdigest() == lock_hash == args.lock_sha256, "deployment lock mismatch")
    require(
        lock.get("seedData")
        == {"sha256": seed_digest(config["seedData"]), **seed_counts(config["seedData"])},
        "deployment lock seed data mismatch",
    )
    expected_web_applications = [
        {
            "applicationId": item["id"],
            "repository": item["repository"],
            "commit": item["commit"],
            "ref": item["ref"],
            "internalPort": item["internalPort"],
            "hostPort": item["hostPort"],
            "healthPath": item["healthPath"],
            "image": {
                "reference": item["image"],
                "digest": item["image"].rsplit("@", 1)[1],
            },
        }
        for item in sorted(config["webApplications"], key=lambda row: row["id"])
    ]
    require(lock.get("webApplications") == expected_web_applications, "deployment lock web applications mismatch")
    require(
        lock.get("observability")
        == {
            "provider": "coroot",
            "nodeAgentImage": COROOT_NODE_AGENT_IMAGE,
            "collectorEndpoint": COROOT_COLLECTOR_ENDPOINT,
        },
        "deployment lock observability contract mismatch",
    )
    require(SAFE_ID_RE.fullmatch(args.lease_id) is not None, "invalid lease ID")
    public_hostname = f"eph-{args.lease_id}.{args.zone}"
    try:
        private_ip = ipaddress.ip_address(args.private_ip)
    except ValueError as exc:
        raise DeployError("guest private IP is invalid") from exc
    rfc1918 = tuple(ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    require(private_ip.version == 4 and any(private_ip in network for network in rfc1918), "guest private IP is not RFC1918")
    prefix = f"jeeb-eph-{args.lease_id}"
    network = prefix

    info = json.loads(docker("info", "--format", "{{json .Swarm}}", capture=True).stdout)
    require(info.get("LocalNodeState") == "active" and info.get("ControlAvailable") is True, "guest is not a Swarm manager")
    existing = docker("service", "ls", "-q", capture=True).stdout.decode().split()
    require(not existing, "guest contains pre-existing Swarm services")

    credentials = json.load(sys.stdin)
    actor = credentials.get("ghcrActor")
    token = credentials.get("ghcrToken")
    super_login_passcode = credentials.get("superLoginPasscode")
    openai_api_key = credentials.get("openAiApiKey")
    coroot_api_key = credentials.get("corootApiKey")
    require(isinstance(actor, str) and actor and isinstance(token, str) and len(token) >= 20, "GHCR credentials missing")
    require(
        isinstance(super_login_passcode, str)
        and 6 <= len(super_login_passcode) <= 128
        and super_login_passcode == super_login_passcode.strip()
        and super_login_passcode.isprintable(),
        "ephemeral super-login passcode missing",
    )
    openai_api_key = validate_openai_credential(config, openai_api_key)
    require(
        isinstance(coroot_api_key, str)
        and 20 <= len(coroot_api_key) <= 4096
        and coroot_api_key == coroot_api_key.strip()
        and coroot_api_key.isprintable()
        and not any(character.isspace() for character in coroot_api_key),
        "Coroot API key missing",
    )
    docker("login", "ghcr.io", "-u", actor, "--password-stdin", stdin=token.encode())

    state_dir = Path("/var/lib/olivium-ephemeral")
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = state_dir / "deployment-lock.json"
    lock_path.write_bytes(canonical(lock) + b"\n")
    os.chmod(lock_path, 0o600)

    deploy_coroot_node_agent(
        state_dir=state_dir,
        api_key=coroot_api_key,
        lease_id=args.lease_id,
        lock_hash=lock_hash,
        deployment_id=args.deployment_id,
    )

    postgres_password = secrets.token_urlsafe(32)
    mongo_password = secrets.token_urlsafe(32)
    ensure_network(network, args.lease_id, lock_hash, args.deployment_id)
    create_infrastructure(
        config,
        prefix=prefix,
        network=network,
        lease_id=args.lease_id,
        lock_hash=lock_hash,
        deployment_id=args.deployment_id,
        postgres_password=postgres_password,
        mongo_password=mongo_password,
    )
    restore_postgres(args.postgres_schema, prefix)
    record_offer_migration_ledger(prefix)
    probe_config = f"{prefix}-http-health-probe"
    create_config(
        probe_config,
        args.health_probe.read_bytes(),
        args.lease_id,
        lock_hash,
        args.deployment_id,
    )

    template_by_name = {item["name"]: item for item in template["services"]}
    ordered = [item for item in config["services"] if item["id"] != "jeeb-gateway"]
    ordered.append(next(item for item in config["services"] if item["id"] == "jeeb-gateway"))
    for service in ordered:
        require(service["stagingName"] in template_by_name, f"template is missing {service['id']}")
        docker("pull", service["image"], timeout=1800)
        create_application(
            service,
            template,
            template_by_name[service["stagingName"]],
            catalog,
            prefix=prefix,
            network=network,
            lease_id=args.lease_id,
            lock_hash=lock_hash,
            deployment_id=args.deployment_id,
            postgres_password=postgres_password,
            mongo_password=mongo_password,
            super_login_passcode=super_login_passcode,
            openai_api_key=openai_api_key,
            public_hostname=public_hostname,
            private_ip=str(private_ip),
            probe_config=probe_config,
        )

    web_application = config["webApplications"][0]
    docker("pull", web_application["image"], timeout=1800)
    create_web_application(
        web_application,
        prefix=prefix,
        network=network,
        lease_id=args.lease_id,
        lock_hash=lock_hash,
        deployment_id=args.deployment_id,
        probe_config=probe_config,
    )

    failures: list[str] = []
    for service in ordered:
        name = f"{prefix}-{service['id']}"
        try:
            wait_application(name, int(service["internalPort"]), service["healthPath"], timeout=1200)
            wait_service(name, healthy=True, timeout=300)
            print(f"healthy: {service['id']}", flush=True)
        except DeployError:
            failures.append(service["id"])
    if failures:
        for service_id in failures:
            docker("service", "ps", "--no-trunc", f"{prefix}-{service_id}", check=False)
        raise DeployError("services did not become healthy: " + ", ".join(failures))

    web_application_name = f"{prefix}-{web_application['id']}"
    wait_application(
        web_application_name,
        int(web_application["internalPort"]),
        web_application["healthPath"],
        timeout=300,
    )
    wait_service(web_application_name, healthy=True, timeout=300)
    print(f"healthy: {web_application['id']}", flush=True)

    counts = apply_seed_data(config, prefix)
    validate_seed_gateway(config, prefix)
    docker("logout", "ghcr.io", check=False)
    gateway = f"{prefix}-jeeb-gateway"
    gateway_service = next(item for item in ordered if item["id"] == "jeeb-gateway")
    require(
        wait_application(gateway, int(gateway_service["internalPort"]), gateway_service["healthPath"], timeout=60),
        "gateway is not healthy",
    )
    probe = run(
        [str(args.health_probe), "--url", "http://127.0.0.1:10000/health/ready"],
        capture=True,
        check=False,
    )
    require(probe.returncode == 0, "gateway loopback health failed")
    cms_probe = run(
        [str(args.health_probe), "--url", "http://127.0.0.1:10080/health"],
        capture=True,
        check=False,
    )
    require(cms_probe.returncode == 0, "CMS loopback health failed")
    configure_public_gateway()
    print(
        json.dumps(
            {
                "ok": True,
                "serviceCount": 24,
                "webApplicationCount": 1,
                "leaseId": args.lease_id,
                "corootNodeAgent": "healthy",
                "seedData": counts,
            },
            sort_keys=True,
        )
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--deployment-lock", type=Path, required=True)
    parser.add_argument("--stage-template", type=Path, required=True)
    parser.add_argument("--postgres-schema", type=Path, required=True)
    parser.add_argument("--health-probe", type=Path, required=True)
    parser.add_argument("--lease-id", required=True)
    parser.add_argument("--private-ip", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--lock-sha256", required=True)
    parser.add_argument("--zone", choices=("fds-8.space", "fds-7.space"), required=True)
    return parser


def main() -> int:
    try:
        deploy(build_parser().parse_args())
        return 0
    except (DeployError, OSError, json.JSONDecodeError) as exc:
        print(f"Jeeb guest deployment failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
