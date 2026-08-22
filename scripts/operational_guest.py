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
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote


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
    timeout: int = 1200,
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
    public_hostname: str,
    private_ip: str,
    gateway_routes: list[dict[str, Any]],
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

    location / {
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
        public_hostname=public_hostname,
        private_ip=private_ip,
        gateway_routes=catalog["gatewayRouting"],
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
    finally:
        env_path.unlink(missing_ok=True)


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
    require(isinstance(actor, str) and actor and isinstance(token, str) and len(token) >= 20, "GHCR credentials missing")
    docker("login", "ghcr.io", "-u", actor, "--password-stdin", stdin=token.encode())

    state_dir = Path("/var/lib/olivium-ephemeral")
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = state_dir / "deployment-lock.json"
    lock_path.write_bytes(canonical(lock) + b"\n")
    os.chmod(lock_path, 0o600)

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
            public_hostname=public_hostname,
            private_ip=str(private_ip),
            probe_config=probe_config,
        )

    failures: list[str] = []
    for service in ordered:
        name = f"{prefix}-{service['id']}"
        try:
            wait_application(name, int(service["internalPort"]), service["healthPath"], timeout=1200)
            print(f"healthy: {service['id']}", flush=True)
        except DeployError:
            failures.append(service["id"])
    if failures:
        for service_id in failures:
            docker("service", "ps", "--no-trunc", f"{prefix}-{service_id}", check=False)
        raise DeployError("services did not become healthy: " + ", ".join(failures))

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
    configure_public_gateway()
    print(json.dumps({"ok": True, "serviceCount": 24, "leaseId": args.lease_id}, sort_keys=True))


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
