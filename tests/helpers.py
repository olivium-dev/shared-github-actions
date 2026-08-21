from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from common import BUILD_INTENT_VERSION, API_VERSION, canonical_sha256, write_json  # noqa: E402


def health(kind: str, port: int = 8080) -> dict[str, Any]:
    base = {
        "type": kind,
        "intervalSeconds": 10,
        "timeoutSeconds": 3,
        "retries": 5,
        "startPeriodSeconds": 5,
    }
    if kind == "http":
        base.update({"port": port, "path": "/readyz", "expectedStatus": 200})
    else:
        base["argv"] = ["/bin/true"]
    return base


def service(service_id: str, kind: str, depends: list[str], published: bool = False) -> dict[str, Any]:
    result = {
        "id": service_id,
        "kind": kind,
        "aliases": [service_id],
        "replicas": 1,
        "environment": {"ASPNETCORE_ENVIRONMENT": "Ephemeral"} if kind == "application" else {},
        "secretMounts": [],
        "command": [],
        "healthcheck": health("http" if kind == "application" else "exec", 10000 if published else 8080),
        "resources": {"cpuLimit": "0.5", "memoryLimitMb": 256},
        "dependsOn": depends,
        "publishedPort": 10000 if published else None,
    }
    return result


def make_contracts(root: Path, count: int = 2) -> tuple[dict[str, Any], dict[str, Any]]:
    application_ids = [f"service-{index:02d}" for index in range(1, count)] + ["jeeb-gateway"]
    sources = []
    for index, service_id in enumerate(application_ids, start=1):
        sources.append(
            {
                "id": service_id,
                "repository": f"olivium-dev/{service_id}",
                "commit": f"{index:040x}",
                "context": "app",
                "dockerfile": "app/Dockerfile",
                "test": {"argv": ["/bin/true"], "timeoutMinutes": 2},
                "buildArgs": {"BUILD_MODE": "ephemeral"},
            }
        )
    infra = [
        service("postgresql", "infrastructure", []),
        service("mongodb", "infrastructure", []),
        service("redis", "infrastructure", []),
    ]
    apps = [
        service(service_id, "application", ["postgresql", "mongodb", "redis"], service_id == "jeeb-gateway")
        for service_id in application_ids
    ]
    config = {
        "apiVersion": API_VERSION,
        "deploymentId": "jeeb-test-01",
        "profile": "jeeb-swarm-v1",
        "zone": "fds-8.space",
        "ttlMinutes": 10,
        "activationDeadlineMinutes": 30,
        "catalog": {
            "id": "jeeb-test-v1",
            "sha256": "a" * 64,
            "serviceIds": application_ids,
        },
        "sources": sources,
        "runtime": {
            "network": "jeeb-test-network",
            "registry": {"endpoint": "127.0.0.1:5443", "tls": True, "caSha256": "b" * 64},
            "secrets": [{"name": "sandbox-api-key", "minLength": 12, "scope": "ephemeral"}],
            "services": infra + apps,
            "migrations": [],
            "validation": {
                "gatewayReadyPath": "/readyz",
                "aggregateHealthPath": "/health/aggregate",
                "settleSeconds": 60,
            },
        },
    }
    intent_services = []
    for source in sources:
        build_input = {
            "catalogSha256": config["catalog"]["sha256"],
            "repository": source["repository"],
            "commit": source["commit"],
            "context": source["context"],
            "dockerfile": source["dockerfile"],
            "test": source["test"],
            "buildArgs": source["buildArgs"],
        }
        intent_services.append(
            {
                "id": source["id"],
                "repository": source["repository"],
                "commit": source["commit"],
                "imageRepository": f"ghcr.io/olivium-dev/jeeb-ephemeral-deploy/{source['id']}",
                "buildInputSha256": canonical_sha256(build_input),
            }
        )
    intent = {
        "apiVersion": BUILD_INTENT_VERSION,
        "deploymentId": config["deploymentId"],
        "configSha256": canonical_sha256(config),
        "catalogSha256": config["catalog"]["sha256"],
        "sourceCommit": "c" * 40,
        "services": intent_services,
        "infrastructureImages": [
            {"id": "registry", "image": f"registry.example/registry@sha256:{'1' * 64}"},
            {"id": "postgresql", "image": f"registry.example/postgresql@sha256:{'2' * 64}"},
            {"id": "mongodb", "image": f"registry.example/mongodb@sha256:{'3' * 64}"},
            {"id": "redis", "image": f"registry.example/redis@sha256:{'4' * 64}"},
        ],
        "healthProbe": {
            "url": "https://artifacts.example.test/olivium-http-probe-1.0.0",
            "sha256": "d" * 64,
            "size": 4096,
            "architecture": "amd64",
            "static": True,
        },
    }
    root.mkdir(parents=True, exist_ok=True)
    write_json(root / "config.json", config, 0o644)
    write_json(root / "build-intent.json", intent, 0o644)
    return config, intent


def fake_jwt(
    audience: str,
    workflow_ref: str,
    workflow_sha: str,
    environment: str,
) -> str:
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "aud": audience,
        "job_workflow_ref": workflow_ref,
        "job_workflow_sha": workflow_sha,
        "environment": environment,
        "repository_owner": "olivium-dev",
        "runner_environment": "github-hosted",
        "ref_protected": "true",
    }

    def encode(value: Any) -> str:
        return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")

    return f"{encode(header)}.{encode(payload)}.test-signature"
