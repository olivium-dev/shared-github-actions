#!/usr/bin/env python3
"""Deploy and verify a finalized Jeeb lock on its single-node ephemeral Swarm."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class RuntimeFailure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeFailure(message)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeFailure(f"invalid runtime file {path.name}: {exc}") from exc


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Docker:
    def run(
        self,
        argv: list[str],
        *,
        stdin: bytes | None = None,
        environment: dict[str, str] | None = None,
        timeout: int = 300,
        check: bool = True,
    ) -> str:
        require(argv and argv[0] == "docker", "runtime may execute only Docker commands through this boundary")
        completed = subprocess.run(
            argv,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=timeout,
            check=False,
        )
        if check and completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace")[-2000:]
            raise RuntimeFailure(f"Docker operation {argv[1] if len(argv) > 1 else 'unknown'} failed: {detail}")
        return completed.stdout.decode("utf-8", errors="strict").strip()


def verify_bundle(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = read_json(root / "bundle-manifest.json")
    require(isinstance(manifest, dict) and manifest.get("apiVersion") == "olivium.dev/runtime-bundle/v1", "runtime bundle manifest version mismatch")
    files = manifest.get("files")
    require(isinstance(files, dict), "runtime bundle file manifest is invalid")
    required = {
        "config.json",
        "deployment-lock.json",
        "health-probe-provenance.json",
        "remote_runtime.py",
        "olivium-http-probe",
    }
    require(set(files) == required, "runtime bundle file set is not exact")
    for name, expected in files.items():
        path = root / name
        require(path.is_file() and not path.is_symlink(), f"runtime bundle file is missing: {name}")
        actual = digest_bytes(canonical(read_json(path))) if name.endswith(".json") else digest_file(path)
        require(actual == expected, f"runtime bundle file digest mismatch: {name}")
    config = read_json(root / "config.json")
    lock = read_json(root / "deployment-lock.json")
    require(config.get("apiVersion") == "olivium.dev/jeeb-ephemeral/v1", "runtime config version mismatch")
    require(lock.get("apiVersion") == "olivium.dev/deployment-lock/v1", "runtime requires a finalized deployment lock")
    require(lock.get("deploymentId") == config.get("deploymentId"), "runtime deployment ID mismatch")
    require(lock.get("configSha256") == digest_bytes(canonical(config)), "runtime config is not bound by the final lock")
    services = lock.get("services")
    require(isinstance(services, list) and len(services) == len(config["catalog"]["serviceIds"]), "final lock application set is incomplete")
    require(all(re.fullmatch(r".+@sha256:[0-9a-f]{64}", item.get("image", "")) for item in services), "final lock contains an unpinned application image")
    require(lock.get("healthProbe", {}).get("sha256") == digest_file(root / "olivium-http-probe"), "health probe does not match final lock")
    require((root / "olivium-http-probe").stat().st_size <= 500_000, "health probe exceeds Docker config size")
    return config, lock


def load_credentials(config: dict[str, Any]) -> tuple[str, str, dict[str, str]]:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        raise RuntimeFailure("runtime credential input is invalid") from exc
    require(isinstance(payload, dict) and set(payload) == {"ghcrActor", "ghcrToken", "runtimeSecrets"}, "runtime credential envelope is invalid")
    actor = payload["ghcrActor"]
    token = payload["ghcrToken"]
    secrets = payload["runtimeSecrets"]
    require(isinstance(actor, str) and actor and isinstance(token, str) and token, "GHCR credentials are missing")
    require(isinstance(secrets, dict), "runtime secrets must be an object")
    requirements = {item["name"]: item["minLength"] for item in config["runtime"]["secrets"]}
    require(set(secrets) == set(requirements), "runtime secret names do not exactly match the reviewed config")
    for name, minimum in requirements.items():
        require(isinstance(secrets[name], str) and minimum <= len(secrets[name]) <= 16_384, f"runtime secret {name} violates its length contract")
    return actor, token, secrets


def verify_swarm(docker: Docker) -> None:
    info = json.loads(docker.run(["docker", "info", "--format", "{{json .Swarm}}"] ) or "{}")
    require(info.get("LocalNodeState") == "active" and info.get("ControlAvailable") is True, "guest is not an active Swarm manager")
    nodes = docker.run(["docker", "node", "ls", "--format", "{{json .}}"])
    rows = [json.loads(line) for line in nodes.splitlines() if line]
    require(len(rows) == 1, "ephemeral Swarm must have exactly one node")
    require(rows[0].get("Status") == "Ready" and rows[0].get("ManagerStatus") in {"Leader", "Reachable"}, "ephemeral Swarm manager is not ready")


def docker_environment(config_dir: Path) -> dict[str, str]:
    allowed = {key: value for key, value in os.environ.items() if key in {"PATH", "HOME", "LANG", "LC_ALL"}}
    allowed["DOCKER_CONFIG"] = str(config_dir)
    return allowed


def start_local_registry(docker: Docker, config: dict[str, Any], lock: dict[str, Any], environment: dict[str, str]) -> None:
    runtime_registry = config["runtime"]["registry"]
    endpoint = runtime_registry["endpoint"]
    require(endpoint.startswith("127.0.0.1:"), "lease-local registry must bind loopback")
    certificate_dir = Path("/etc/olivium-ephemeral/registry")
    ca = Path("/etc/docker/certs.d") / endpoint / "ca.crt"
    certificate = certificate_dir / "tls.crt"
    private_key = certificate_dir / "tls.key"
    require(ca.is_file() and certificate.is_file() and private_key.is_file(), "lease-local registry TLS material is missing")
    require(digest_file(ca) == runtime_registry["caSha256"], "lease-local registry CA does not match reviewed config")
    registry_image = next(item["image"] for item in lock["infrastructureImages"] if item["id"] == "registry")
    docker.run(["docker", "pull", registry_image], environment=environment, timeout=600)
    name = f"jeeb-eph-{config['deploymentId']}-registry"
    existing = docker.run(["docker", "container", "inspect", name, "--format", "{{.State.Running}}"], check=False)
    if existing != "true":
        docker.run(["docker", "container", "rm", name], check=False)
        docker.run(
            [
                "docker", "run", "--detach", "--restart", "unless-stopped", "--name", name,
                "--network", "host",
                "--label", f"com.olivium.ephemeral.deployment={config['deploymentId']}",
                "--mount", f"type=bind,src={certificate},dst=/run/registry/tls.crt,readonly",
                "--mount", f"type=bind,src={private_key},dst=/run/registry/tls.key,readonly",
                "--env", f"REGISTRY_HTTP_ADDR={endpoint}",
                "--env", "REGISTRY_HTTP_TLS_CERTIFICATE=/run/registry/tls.crt",
                "--env", "REGISTRY_HTTP_TLS_KEY=/run/registry/tls.key",
                registry_image,
            ],
            environment=environment,
        )
    context = ssl.create_default_context(cafile=str(ca))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"https://{endpoint}/v2/", timeout=3, context=context) as response:
                if response.status == 200:
                    return
        except urllib.error.URLError:
            time.sleep(2)
    raise RuntimeFailure("lease-local registry did not become healthy")


def import_images(docker: Docker, config: dict[str, Any], lock: dict[str, Any], environment: dict[str, str]) -> dict[str, str]:
    endpoint = config["runtime"]["registry"]["endpoint"]
    namespace = config["deploymentId"]
    references = {item["id"]: item["image"] for item in lock["services"]}
    references.update({item["id"]: item["image"] for item in lock["infrastructureImages"] if item["id"] != "registry"})
    local: dict[str, str] = {}
    for service_id in sorted(references):
        source = references[service_id]
        digest = source.rsplit("@", 1)[1]
        tag = f"{endpoint}/{namespace}/{service_id}:{digest.removeprefix('sha256:')}"
        docker.run(["docker", "pull", source], environment=environment, timeout=900)
        docker.run(["docker", "tag", source, tag], environment=environment)
        output = docker.run(["docker", "push", tag], environment=environment, timeout=900)
        pushed = re.findall(r"digest:\s*(sha256:[0-9a-f]{64})", output)
        require(pushed and pushed[-1] == digest, f"lease-local registry changed digest for {service_id}")
        local[service_id] = f"{endpoint}/{namespace}/{service_id}@{digest}"
        docker.run(["docker", "image", "rm", source], environment=environment, check=False)
    return local


def create_network(docker: Docker, deployment_id: str, network: str) -> None:
    existing = docker.run(["docker", "network", "inspect", network, "--format", "{{index .Labels \"com.olivium.ephemeral.deployment\"}}"], check=False)
    if existing:
        require(existing == deployment_id, "reviewed network name is owned by another deployment")
        return
    docker.run([
        "docker", "network", "create", "--driver", "overlay", "--opt", "encrypted",
        "--label", f"com.olivium.ephemeral.deployment={deployment_id}", network,
    ])


def create_secrets(docker: Docker, deployment_id: str, requirements: list[dict[str, Any]], values: dict[str, str]) -> dict[str, str]:
    created: dict[str, str] = {}
    for requirement in requirements:
        logical = requirement["name"]
        name = f"jeeb-eph-{deployment_id}-{logical}"
        existing = docker.run(["docker", "secret", "inspect", name, "--format", "{{.Spec.Name}}"], check=False)
        if not existing:
            docker.run(
                ["docker", "secret", "create", "--label", f"com.olivium.ephemeral.deployment={deployment_id}", name, "-"],
                stdin=values[logical].encode(),
            )
        created[logical] = name
    return created


def create_health_probe_config(docker: Docker, deployment_id: str, probe: Path) -> str:
    name = f"jeeb-eph-{deployment_id}-http-probe-{digest_file(probe)[:12]}"
    existing = docker.run(["docker", "config", "inspect", name, "--format", "{{.Spec.Name}}"], check=False)
    if not existing:
        docker.run([
            "docker", "config", "create", "--label", f"com.olivium.ephemeral.deployment={deployment_id}", name, str(probe),
        ])
    return name


def topological_services(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {item["id"]: item for item in services}
    pending = set(by_id)
    ordered: list[dict[str, Any]] = []
    completed: set[str] = set()
    while pending:
        ready = sorted(item for item in pending if set(by_id[item]["dependsOn"]).issubset(completed))
        require(bool(ready), "runtime service dependency graph contains a cycle")
        for service_id in ready:
            ordered.append(by_id[service_id])
            completed.add(service_id)
            pending.remove(service_id)
    return ordered


def health_command(service: dict[str, Any]) -> str:
    health = service["healthcheck"]
    if health["type"] == "http":
        argv = [
            "/run/olivium/bin/http-probe",
            "--url", f"http://127.0.0.1:{health['port']}{health['path']}",
            "--timeout-ms", str(health["timeoutSeconds"] * 1000),
            "--expect-status", str(health["expectedStatus"]),
        ]
    else:
        argv = health["argv"]
    return shlex.join(argv)


def create_service(
    docker: Docker,
    deployment_id: str,
    network: str,
    service: dict[str, Any],
    image: str,
    secrets: dict[str, str],
    health_probe_config: str,
) -> str:
    name = f"jeeb-eph-{deployment_id}-{service['id']}"
    require(len(name) <= 200, "generated Swarm service name is too long")
    existing_owner = docker.run([
        "docker", "service", "inspect", name, "--format", "{{index .Spec.Labels \"com.olivium.ephemeral.deployment\"}}",
    ], check=False)
    if existing_owner:
        require(existing_owner == deployment_id, f"service {name} is owned by another deployment")
        current = docker.run(["docker", "service", "inspect", name, "--format", "{{.Spec.TaskTemplate.ContainerSpec.Image}}"])
        require(current == image, f"existing service {name} does not match final lock")
        return name

    aliases = ",".join(f"alias={alias}" for alias in service["aliases"])
    command = [
        "docker", "service", "create", "--detach=false", "--name", name,
        "--label", f"com.olivium.ephemeral.deployment={deployment_id}",
        "--label", f"com.olivium.ephemeral.application={service['id']}",
        "--label", f"com.olivium.ephemeral.lock={image.rsplit('@', 1)[1]}",
        "--constraint", "node.role==manager", "--replicas", "1",
        "--restart-condition", "on-failure", "--restart-max-attempts", "3",
        "--update-order", "start-first", "--update-failure-action", "rollback",
        "--rollback-order", "start-first",
        "--limit-cpu", service["resources"]["cpuLimit"],
        "--limit-memory", f"{service['resources']['memoryLimitMb']}M",
        "--network", f"{network},{aliases}",
        "--health-cmd", health_command(service),
        "--health-interval", f"{service['healthcheck']['intervalSeconds']}s",
        "--health-timeout", f"{service['healthcheck']['timeoutSeconds']}s",
        "--health-retries", str(service["healthcheck"]["retries"]),
        "--health-start-period", f"{service['healthcheck']['startPeriodSeconds']}s",
    ]
    for key, value in sorted(service["environment"].items()):
        command.extend(["--env", f"{key}={value}"])
    for mount in service["secretMounts"]:
        command.extend(["--secret", f"source={secrets[mount['secret']]},target={mount['target']},mode={mount['mode']}"])
    if service["healthcheck"]["type"] == "http":
        command.extend(["--config", f"source={health_probe_config},target=/run/olivium/bin/http-probe,mode=0555"])
    if service.get("publishedPort") is not None:
        command.extend(["--publish", f"published={service['publishedPort']},target={service['healthcheck']['port']},mode=host"])
    command.append(image)
    command.extend(service["command"])
    docker.run(command, timeout=900)
    return name


def wait_service_healthy(docker: Docker, name: str, timeout_seconds: int = 600) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        containers = docker.run([
            "docker", "ps", "--filter", f"label=com.docker.swarm.service.name={name}", "--format", "{{.ID}}",
        ]).splitlines()
        if len(containers) == 1:
            state = json.loads(docker.run(["docker", "container", "inspect", containers[0], "--format", "{{json .State}}"] ) or "{}")
            health = state.get("Health", {}).get("Status")
            if state.get("Running") is True and health == "healthy":
                require(state.get("OOMKilled") is not True, f"service {name} was OOM-killed")
                return
        time.sleep(5)
    raise RuntimeFailure(f"service {name} did not become healthy")


def run_migrations(
    docker: Docker,
    deployment_id: str,
    network: str,
    migrations: list[dict[str, Any]],
    services: dict[str, dict[str, Any]],
    images: dict[str, str],
    secrets: dict[str, str],
) -> None:
    for migration in migrations:
        service = services[migration["serviceId"]]
        name = f"jeeb-eph-{deployment_id}-migration-{migration['id']}"
        docker.run(["docker", "service", "rm", name], check=False)
        command = [
            "docker", "service", "create", "--detach", "--name", name,
            "--label", f"com.olivium.ephemeral.deployment={deployment_id}",
            "--label", f"com.olivium.ephemeral.migration={migration['id']}",
            "--network", network, "--restart-condition", "none",
        ]
        for key, value in sorted(service["environment"].items()):
            command.extend(["--env", f"{key}={value}"])
        for mount in service["secretMounts"]:
            command.extend(["--secret", f"source={secrets[mount['secret']]},target={mount['target']},mode={mount['mode']}"])
        command.append(images[service["id"]])
        command.extend(migration["argv"])
        docker.run(command)
        deadline = time.monotonic() + migration["timeoutSeconds"]
        succeeded = False
        while time.monotonic() < deadline:
            status = docker.run(["docker", "service", "ps", name, "--no-trunc", "--format", "{{.CurrentState}}|{{.Error}}"])
            if status.startswith("Complete"):
                succeeded = True
                break
            if status.startswith(("Failed", "Rejected")):
                break
            time.sleep(3)
        docker.run(["docker", "service", "rm", name], check=False)
        require(succeeded, f"migration {migration['id']} failed or timed out")


def apply_nginx_handoff(config: dict[str, Any], lease_id: str) -> None:
    require(re.fullmatch(r"[a-z0-9-]{3,80}", lease_id) is not None, "lease ID is invalid")
    nginx = f"""server {{
    listen 80 default_server;
    server_name _;
    location = /.well-known/olivium-lease {{
        default_type application/json;
        return 200 '{{\"leaseId\":\"{lease_id}\",\"deploymentId\":\"{config['deploymentId']}\"}}';
    }}
    location / {{
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_pass http://127.0.0.1:10000;
    }}
}}
"""
    target = Path("/etc/nginx/conf.d/olivium-ephemeral.conf")
    temporary = target.with_suffix(".tmp")
    temporary.write_text(nginx, encoding="ascii")
    os.chmod(temporary, 0o644)
    os.replace(temporary, target)
    subprocess.run(["nginx", "-t"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    subprocess.run(["systemctl", "reload", "nginx"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def validate_exact_set(docker: Docker, config: dict[str, Any], lock: dict[str, Any]) -> None:
    deployment_id = config["deploymentId"]
    expected_ids = set(config["catalog"]["serviceIds"])
    output = docker.run([
        "docker", "service", "ls", "--filter", f"label=com.olivium.ephemeral.deployment={deployment_id}",
        "--filter", "label=com.olivium.ephemeral.application", "--format", "{{.Name}}",
    ])
    prefix = f"jeeb-eph-{deployment_id}-"
    actual_ids = {name.removeprefix(prefix) for name in output.splitlines() if name.startswith(prefix)}
    require(actual_ids == expected_ids, "running application service set does not exactly match the 24-service catalog")
    locked = {item["id"]: item["image"].rsplit("@", 1)[1] for item in lock["services"]}
    for service_id in sorted(expected_ids):
        name = f"{prefix}{service_id}"
        label_digest = docker.run(["docker", "service", "inspect", name, "--format", "{{index .Spec.Labels \"com.olivium.ephemeral.lock\"}}"])
        require(label_digest == locked[service_id], f"service lock label mismatch for {service_id}")
        wait_service_healthy(docker, name)


def validate_gateway(config: dict[str, Any]) -> None:
    for key in ("gatewayReadyPath", "aggregateHealthPath"):
        path = config["runtime"]["validation"][key]
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:10000{path}", timeout=10) as response:
                require(200 <= response.status < 300, f"gateway check {path} returned HTTP {response.status}")
        except urllib.error.URLError as exc:
            raise RuntimeFailure(f"gateway check {path} failed: {exc}") from exc


def deploy(args: argparse.Namespace) -> None:
    root = args.bundle_dir.resolve()
    config, lock = verify_bundle(root)
    actor, token, secret_values = load_credentials(config)
    require(args.deployment_lock_sha256 == digest_bytes(canonical(lock)), "manager deployment lock hash does not match runtime bundle")
    docker = Docker()
    verify_swarm(docker)
    lock_file = Path("/run/lock/olivium-jeeb-ephemeral.lock")
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    with lock_file.open("w", encoding="ascii") as lease_lock:
        fcntl.flock(lease_lock, fcntl.LOCK_EX)
        with tempfile.TemporaryDirectory(prefix="olivium-docker-config-", dir="/run") as docker_config:
            config_dir = Path(docker_config)
            os.chmod(config_dir, 0o700)
            environment = docker_environment(config_dir)
            docker.run(["docker", "login", "ghcr.io", "--username", actor, "--password-stdin"], stdin=token.encode(), environment=environment)
            try:
                start_local_registry(docker, config, lock, environment)
                images = import_images(docker, config, lock, environment)
            finally:
                docker.run(["docker", "logout", "ghcr.io"], environment=environment, check=False)
                shutil.rmtree(config_dir, ignore_errors=True)
            require(not config_dir.exists(), "temporary GHCR Docker config was not removed")

        deployment_id = config["deploymentId"]
        create_network(docker, deployment_id, config["runtime"]["network"])
        secrets = create_secrets(docker, deployment_id, config["runtime"]["secrets"], secret_values)
        health_config = create_health_probe_config(docker, deployment_id, root / "olivium-http-probe")
        services = {item["id"]: item for item in config["runtime"]["services"]}
        ordered_services = topological_services(list(services.values()))
        for service in (item for item in ordered_services if item["kind"] == "infrastructure"):
            name = create_service(docker, deployment_id, config["runtime"]["network"], service, images[service["id"]], secrets, health_config)
            wait_service_healthy(docker, name)
        run_migrations(docker, deployment_id, config["runtime"]["network"], config["runtime"]["migrations"], services, images, secrets)
        for service in (item for item in ordered_services if item["kind"] == "application"):
            name = create_service(docker, deployment_id, config["runtime"]["network"], service, images[service["id"]], secrets, health_config)
            wait_service_healthy(docker, name)
        validate_exact_set(docker, config, lock)
        validate_gateway(config)
        apply_nginx_handoff(config, args.lease_id)
    print(json.dumps({"ok": True, "deploymentId": config["deploymentId"], "applicationCount": len(config["catalog"]["serviceIds"])}))


def validate(args: argparse.Namespace) -> None:
    config, lock = verify_bundle(args.bundle_dir.resolve())
    require(args.deployment_lock_sha256 == digest_bytes(canonical(lock)), "manager deployment lock hash does not match runtime bundle")
    docker = Docker()
    verify_swarm(docker)
    validate_exact_set(docker, config, lock)
    validate_gateway(config)
    docker_config_residue = list(Path("/run").glob("olivium-docker-config-*"))
    require(not docker_config_residue, "temporary GHCR Docker config residue exists")
    print(json.dumps({"ok": True, "deploymentId": config["deploymentId"], "validated": True}))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name, handler in (("deploy", deploy), ("validate", validate)):
        command = subparsers.add_parser(name)
        command.add_argument("--bundle-dir", type=Path, required=True)
        command.add_argument("--lease-id", required=True)
        command.add_argument("--deployment-lock-sha256", required=True)
        command.set_defaults(handler=handler)
    return parser


def main() -> int:
    try:
        args = build_parser().parse_args()
        args.handler(args)
        return 0
    except (RuntimeFailure, OSError, subprocess.SubprocessError) as exc:
        print(f"runtime deployment failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
