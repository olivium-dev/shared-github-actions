#!/usr/bin/env python3
"""Validate reviewed deployment contracts and assemble a source-free runtime bundle."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any

from common import (
    API_VERSION,
    BUILD_INTENT_VERSION,
    FULL_SHA,
    IMAGE_DIGEST,
    LOCK_VERSION,
    MANAGER_AUDIENCE,
    MANAGER_URL,
    REPOSITORY,
    SAFE_ID,
    SHA256,
    ContractError,
    canonical_json,
    canonical_sha256,
    https_url,
    nonempty_string,
    read_json,
    require,
    safe_relative_path,
    strict_keys,
    write_github_output,
    write_json,
)


CONFIG_FIELDS = {
    "apiVersion",
    "deploymentId",
    "profile",
    "zone",
    "ttlMinutes",
    "activationDeadlineMinutes",
    "catalog",
    "sources",
    "runtime",
}
BUILD_INTENT_FIELDS = {
    "apiVersion",
    "deploymentId",
    "configSha256",
    "catalogSha256",
    "sourceCommit",
    "services",
    "infrastructureImages",
    "healthProbe",
}
FINAL_LOCK_FIELDS = BUILD_INTENT_FIELDS | {"buildIntentSha256", "generatedBy"}


def validate_config(value: Any, expected_service_count: int) -> dict[str, Any]:
    require(isinstance(value, dict), "deployment config must be an object")
    strict_keys(value, CONFIG_FIELDS, "deployment config")
    require(value.get("apiVersion") == API_VERSION, f"apiVersion must be {API_VERSION}")
    deployment_id = nonempty_string(value.get("deploymentId"), "deploymentId", 63)
    require(len(deployment_id) >= 8 and SAFE_ID.fullmatch(deployment_id) is not None, "deploymentId must be an 8-63 character lowercase DNS-safe identifier")
    require(value.get("profile") == "jeeb-swarm-v1", "profile must be jeeb-swarm-v1")
    require(value.get("zone") in {"fds-8.space", "fds-7.space"}, "zone is not allowlisted")
    require(isinstance(value.get("ttlMinutes"), int) and 5 <= value["ttlMinutes"] <= 240, "ttlMinutes must be 5..240")
    require(
        isinstance(value.get("activationDeadlineMinutes"), int)
        and 10 <= value["activationDeadlineMinutes"] <= 120,
        "activationDeadlineMinutes must be 10..120",
    )

    catalog = value.get("catalog")
    require(isinstance(catalog, dict), "catalog must be an object")
    strict_keys(catalog, {"id", "sha256", "serviceIds"}, "catalog")
    require(SAFE_ID.fullmatch(nonempty_string(catalog.get("id"), "catalog.id", 63)) is not None, "catalog.id is invalid")
    require(SHA256.fullmatch(nonempty_string(catalog.get("sha256"), "catalog.sha256", 64)) is not None, "catalog.sha256 is invalid")
    service_ids = catalog.get("serviceIds")
    require(isinstance(service_ids, list) and len(service_ids) == expected_service_count, f"catalog.serviceIds must contain exactly {expected_service_count} services")
    require(len(set(service_ids)) == len(service_ids), "catalog.serviceIds contains duplicates")
    for service_id in service_ids:
        require(isinstance(service_id, str) and SAFE_ID.fullmatch(service_id) is not None, "catalog contains an invalid service ID")

    sources = value.get("sources")
    require(isinstance(sources, list) and len(sources) == expected_service_count, f"sources must contain exactly {expected_service_count} entries")
    source_ids: set[str] = set()
    for index, source in enumerate(sources):
        context = f"sources[{index}]"
        require(isinstance(source, dict), f"{context} must be an object")
        strict_keys(source, {"id", "repository", "commit", "context", "dockerfile", "test", "buildArgs"}, context)
        source_id = nonempty_string(source.get("id"), f"{context}.id", 63)
        require(SAFE_ID.fullmatch(source_id) is not None, f"{context}.id is invalid")
        require(source_id not in source_ids, f"duplicate source ID: {source_id}")
        source_ids.add(source_id)
        repository = nonempty_string(source.get("repository"), f"{context}.repository", 128)
        require(REPOSITORY.fullmatch(repository) is not None, f"{context}.repository is invalid")
        require(repository.lower().startswith("olivium-dev/"), f"{context}.repository must be owned by olivium-dev")
        require(FULL_SHA.fullmatch(nonempty_string(source.get("commit"), f"{context}.commit", 40)) is not None, f"{context}.commit must be a full lowercase SHA")
        safe_relative_path(source.get("context"), f"{context}.context")
        safe_relative_path(source.get("dockerfile"), f"{context}.dockerfile")
        test = source.get("test")
        require(isinstance(test, dict), f"{context}.test must be an object")
        strict_keys(test, {"argv", "timeoutMinutes"}, f"{context}.test")
        argv = test.get("argv")
        require(isinstance(argv, list) and 1 <= len(argv) <= 32, f"{context}.test.argv must be a non-empty array")
        for position, argument in enumerate(argv):
            nonempty_string(argument, f"{context}.test.argv[{position}]", 512)
        require(isinstance(test.get("timeoutMinutes"), int) and 1 <= test["timeoutMinutes"] <= 30, f"{context}.test.timeoutMinutes must be 1..30")
        build_args = source.get("buildArgs")
        require(isinstance(build_args, dict), f"{context}.buildArgs must be an object")
        for key, argument in build_args.items():
            require(re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", key) is not None, f"{context}.buildArgs has an invalid key")
            nonempty_string(argument, f"{context}.buildArgs.{key}", 512)
            require(not re.search(r"(?i)(token|secret|password|private|credential|key)", key), f"{context}.buildArgs may not contain credentials")

    require(source_ids == set(service_ids), "sources must exactly match catalog.serviceIds")
    validate_runtime(value.get("runtime"), set(service_ids))
    return value


def validate_runtime(value: Any, application_ids: set[str]) -> None:
    require(isinstance(value, dict), "runtime must be an object")
    strict_keys(value, {"network", "registry", "secrets", "services", "migrations", "validation"}, "runtime")
    network = nonempty_string(value.get("network"), "runtime.network", 63)
    require(SAFE_ID.fullmatch(network) is not None, "runtime.network is invalid")

    registry = value.get("registry")
    require(isinstance(registry, dict), "runtime.registry must be an object")
    strict_keys(registry, {"endpoint", "tls", "caSha256"}, "runtime.registry")
    endpoint = nonempty_string(registry.get("endpoint"), "runtime.registry.endpoint", 255)
    require(re.fullmatch(r"[a-z0-9.-]+:[0-9]{2,5}", endpoint) is not None, "runtime.registry.endpoint is invalid")
    require(registry.get("tls") is True, "lease-local registry must use TLS")
    require(SHA256.fullmatch(nonempty_string(registry.get("caSha256"), "runtime.registry.caSha256", 64)) is not None, "runtime.registry.caSha256 is invalid")

    secrets = value.get("secrets")
    require(isinstance(secrets, list), "runtime.secrets must be an array")
    secret_names: set[str] = set()
    for index, secret in enumerate(secrets):
        context = f"runtime.secrets[{index}]"
        require(isinstance(secret, dict), f"{context} must be an object")
        strict_keys(secret, {"name", "minLength", "scope"}, context)
        name = nonempty_string(secret.get("name"), f"{context}.name", 96)
        require(SAFE_ID.fullmatch(name) is not None and name not in secret_names, f"{context}.name is invalid or duplicated")
        secret_names.add(name)
        require(isinstance(secret.get("minLength"), int) and 12 <= secret["minLength"] <= 4096, f"{context}.minLength must be 12..4096")
        require(secret.get("scope") == "ephemeral", f"{context}.scope must be ephemeral")

    services = value.get("services")
    require(isinstance(services, list) and services, "runtime.services must be a non-empty array")
    all_ids: set[str] = set()
    application_runtime_ids: set[str] = set()
    for index, service in enumerate(services):
        context = f"runtime.services[{index}]"
        require(isinstance(service, dict), f"{context} must be an object")
        strict_keys(
            service,
            {
                "id", "kind", "aliases", "replicas", "environment", "secretMounts", "command",
                "healthcheck", "resources", "dependsOn", "publishedPort",
            },
            context,
        )
        service_id = nonempty_string(service.get("id"), f"{context}.id", 63)
        require(SAFE_ID.fullmatch(service_id) is not None and service_id not in all_ids, f"{context}.id is invalid or duplicated")
        all_ids.add(service_id)
        kind = service.get("kind")
        require(kind in {"application", "infrastructure"}, f"{context}.kind is invalid")
        if kind == "application":
            application_runtime_ids.add(service_id)
        require(service.get("replicas") == 1, f"{context}.replicas must be 1 on the single-node lease")
        aliases = service.get("aliases")
        require(isinstance(aliases, list) and aliases, f"{context}.aliases must be non-empty")
        for alias in aliases:
            require(isinstance(alias, str) and SAFE_ID.fullmatch(alias) is not None, f"{context}.aliases contains an invalid value")
        environment = service.get("environment")
        require(isinstance(environment, dict), f"{context}.environment must be an object")
        for name, item in environment.items():
            require(re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", name) is not None, f"{context}.environment has an invalid name")
            nonempty_string(item, f"{context}.environment.{name}", 2048)
            require(not re.search(r"(?i)(token|secret|password|private|credential|api[_-]?key)", name), f"{context}.environment may not contain secrets")
        mounts = service.get("secretMounts")
        require(isinstance(mounts, list), f"{context}.secretMounts must be an array")
        for mount in mounts:
            require(isinstance(mount, dict), f"{context}.secretMounts entries must be objects")
            strict_keys(mount, {"secret", "target", "mode"}, f"{context}.secretMounts")
            require(mount.get("secret") in secret_names, f"{context} references an unknown secret")
            safe_relative_path(mount.get("target"), f"{context}.secretMounts.target")
            require(mount.get("mode") == "0400", f"{context}.secretMounts.mode must be 0400")
        for field in ("command", "dependsOn"):
            items = service.get(field)
            require(isinstance(items, list), f"{context}.{field} must be an array")
            for item in items:
                nonempty_string(item, f"{context}.{field}", 512)
        health = service.get("healthcheck")
        require(isinstance(health, dict), f"{context}.healthcheck must be an object")
        strict_keys(health, {"type", "port", "path", "expectedStatus", "argv", "intervalSeconds", "timeoutSeconds", "retries", "startPeriodSeconds"}, f"{context}.healthcheck")
        health_type = health.get("type")
        require(health_type in {"http", "exec"}, f"{context}.healthcheck.type is invalid")
        if kind == "application":
            require(health_type == "http", f"{context} applications must use the trusted HTTP probe")
        if health_type == "http":
            require(isinstance(health.get("port"), int) and 1 <= health["port"] <= 65535, f"{context}.healthcheck.port is invalid")
            health_path = nonempty_string(health.get("path"), f"{context}.healthcheck.path", 256)
            require(health_path.startswith("/") and ".." not in health_path, f"{context}.healthcheck.path is invalid")
            require(isinstance(health.get("expectedStatus"), int) and 100 <= health["expectedStatus"] <= 599, f"{context}.healthcheck.expectedStatus is invalid")
            require(health.get("argv") is None, f"{context}.healthcheck.argv is prohibited for HTTP checks")
        else:
            require(kind == "infrastructure", f"{context}.healthcheck.exec is infrastructure-only")
            argv = health.get("argv")
            require(isinstance(argv, list) and argv, f"{context}.healthcheck.argv must be non-empty")
            for item in argv:
                nonempty_string(item, f"{context}.healthcheck.argv", 512)
            require(all(health.get(field) is None for field in ("port", "path", "expectedStatus")), f"{context}.healthcheck exec fields are inconsistent")
        for field, minimum, maximum in (
            ("intervalSeconds", 5, 120), ("timeoutSeconds", 1, 30), ("retries", 1, 20), ("startPeriodSeconds", 0, 300)
        ):
            require(isinstance(health.get(field), int) and minimum <= health[field] <= maximum, f"{context}.healthcheck.{field} is out of range")
        resources = service.get("resources")
        require(isinstance(resources, dict), f"{context}.resources must be an object")
        strict_keys(resources, {"cpuLimit", "memoryLimitMb"}, f"{context}.resources")
        require(isinstance(resources.get("cpuLimit"), str) and re.fullmatch(r"[0-9]+(?:\.[0-9]{1,3})?", resources["cpuLimit"]), f"{context}.resources.cpuLimit is invalid")
        require(isinstance(resources.get("memoryLimitMb"), int) and 64 <= resources["memoryLimitMb"] <= 8192, f"{context}.resources.memoryLimitMb is invalid")
        published_port = service.get("publishedPort")
        if published_port is not None:
            require(service_id == "jeeb-gateway" and published_port == 10000, "only jeeb-gateway may publish host port 10000")

    require(application_runtime_ids == application_ids, "runtime application services must exactly match catalog.serviceIds")
    for service in services:
        require(set(service["dependsOn"]).issubset(all_ids), f"runtime service {service['id']} has an unknown dependency")

    migrations = value.get("migrations")
    require(isinstance(migrations, list), "runtime.migrations must be an array")
    migration_ids: set[str] = set()
    for index, migration in enumerate(migrations):
        context = f"runtime.migrations[{index}]"
        require(isinstance(migration, dict), f"{context} must be an object")
        strict_keys(migration, {"id", "serviceId", "argv", "timeoutSeconds"}, context)
        migration_id = nonempty_string(migration.get("id"), f"{context}.id", 63)
        require(SAFE_ID.fullmatch(migration_id) is not None and migration_id not in migration_ids, f"{context}.id is invalid or duplicated")
        migration_ids.add(migration_id)
        require(migration.get("serviceId") in all_ids, f"{context}.serviceId is unknown")
        require(isinstance(migration.get("argv"), list) and migration["argv"], f"{context}.argv must be non-empty")
        for item in migration["argv"]:
            nonempty_string(item, f"{context}.argv", 512)
        require(isinstance(migration.get("timeoutSeconds"), int) and 30 <= migration["timeoutSeconds"] <= 1800, f"{context}.timeoutSeconds is invalid")

    validation = value.get("validation")
    require(isinstance(validation, dict), "runtime.validation must be an object")
    strict_keys(validation, {"gatewayReadyPath", "aggregateHealthPath", "settleSeconds"}, "runtime.validation")
    for key in ("gatewayReadyPath", "aggregateHealthPath"):
        path = nonempty_string(validation.get(key), f"runtime.validation.{key}", 256)
        require(path.startswith("/") and ".." not in path, f"runtime.validation.{key} is invalid")
    require(isinstance(validation.get("settleSeconds"), int) and 60 <= validation["settleSeconds"] <= 600, "runtime.validation.settleSeconds must be 60..600")


def validate_pinned_assets(value: dict[str, Any], context_prefix: str) -> None:
    infrastructure = value.get("infrastructureImages")
    require(isinstance(infrastructure, list) and infrastructure, f"{context_prefix}.infrastructureImages must be non-empty")
    infra_ids: set[str] = set()
    for index, image in enumerate(infrastructure):
        context = f"{context_prefix}.infrastructureImages[{index}]"
        require(isinstance(image, dict), f"{context} must be an object")
        strict_keys(image, {"id", "image"}, context)
        image_id = nonempty_string(image.get("id"), f"{context}.id", 63)
        require(SAFE_ID.fullmatch(image_id) is not None and image_id not in infra_ids, f"{context}.id is invalid or duplicated")
        infra_ids.add(image_id)
        reference = nonempty_string(image.get("image"), f"{context}.image", 512)
        require("@" in reference and IMAGE_DIGEST.fullmatch(reference.rsplit("@", 1)[1]) is not None, f"{context}.image must be digest locked")
    require({"registry", "postgresql", "mongodb", "redis"}.issubset(infra_ids), f"{context_prefix} must pin registry, PostgreSQL, MongoDB, and Redis")

    health_probe = value.get("healthProbe")
    require(isinstance(health_probe, dict), f"{context_prefix}.healthProbe must be an object")
    strict_keys(health_probe, {"url", "sha256", "size", "architecture", "static"}, f"{context_prefix}.healthProbe")
    require(isinstance(health_probe.get("url"), str) and health_probe["url"].startswith("https://"), f"{context_prefix}.healthProbe.url must use HTTPS")
    require(SHA256.fullmatch(nonempty_string(health_probe.get("sha256"), f"{context_prefix}.healthProbe.sha256", 64)) is not None, f"{context_prefix}.healthProbe.sha256 is invalid")
    require(isinstance(health_probe.get("size"), int) and 1 <= health_probe["size"] <= 500_000, f"{context_prefix}.healthProbe.size exceeds the Docker config limit")
    require(health_probe.get("architecture") == "amd64", f"{context_prefix}.healthProbe.architecture must be amd64")
    require(health_probe.get("static") is True, f"{context_prefix}.healthProbe must attest a static binary")


def validate_build_intent(value: Any, config: dict[str, Any]) -> dict[str, Any]:
    require(isinstance(value, dict), "build intent must be an object")
    strict_keys(value, BUILD_INTENT_FIELDS, "build intent")
    require(value.get("apiVersion") == BUILD_INTENT_VERSION, f"build intent apiVersion must be {BUILD_INTENT_VERSION}")
    require(value.get("deploymentId") == config["deploymentId"], "build intent deploymentId does not match config")
    require(value.get("configSha256") == canonical_sha256(config), "build intent configSha256 does not match canonical config")
    require(value.get("catalogSha256") == config["catalog"]["sha256"], "build intent catalogSha256 does not match config")
    require(FULL_SHA.fullmatch(nonempty_string(value.get("sourceCommit"), "build intent sourceCommit", 40)) is not None, "build intent sourceCommit must be a full SHA")
    source_by_id = {item["id"]: item for item in config["sources"]}
    services = value.get("services")
    require(isinstance(services, list) and len(services) == len(source_by_id), "build intent services must exactly match application sources")
    intent_ids: set[str] = set()
    for index, service in enumerate(services):
        context = f"buildIntent.services[{index}]"
        require(isinstance(service, dict), f"{context} must be an object")
        strict_keys(service, {"id", "repository", "commit", "imageRepository", "buildInputSha256"}, context)
        service_id = nonempty_string(service.get("id"), f"{context}.id", 63)
        require(service_id in source_by_id and service_id not in intent_ids, f"{context}.id is unknown or duplicated")
        intent_ids.add(service_id)
        source = source_by_id[service_id]
        require(service.get("repository") == source["repository"], f"{context}.repository does not match config")
        require(service.get("commit") == source["commit"], f"{context}.commit does not match config")
        image_repository = nonempty_string(service.get("imageRepository"), f"{context}.imageRepository", 440)
        require(re.fullmatch(r"ghcr\.io/[a-z0-9_.-]+/[a-z0-9_./-]+", image_repository) is not None, f"{context}.imageRepository is invalid")
        require("@" not in image_repository and ":" not in image_repository.removeprefix("ghcr.io/"), f"{context}.imageRepository must not predeclare a tag or digest")
        require(SHA256.fullmatch(nonempty_string(service.get("buildInputSha256"), f"{context}.buildInputSha256", 64)) is not None, f"{context}.buildInputSha256 is invalid")
    require(intent_ids == set(source_by_id), "build intent services do not exactly match sources")
    validate_pinned_assets(value, "buildIntent")
    return value


def validate_final_lock(value: Any, config: dict[str, Any], intent: dict[str, Any] | None = None) -> dict[str, Any]:
    require(isinstance(value, dict), "deployment lock must be an object")
    strict_keys(value, FINAL_LOCK_FIELDS, "deployment lock")
    require(value.get("apiVersion") == LOCK_VERSION, f"deployment lock apiVersion must be {LOCK_VERSION}")
    require(value.get("deploymentId") == config["deploymentId"], "deployment lock deploymentId does not match config")
    require(value.get("configSha256") == canonical_sha256(config), "deployment lock configSha256 does not match canonical config")
    require(value.get("catalogSha256") == config["catalog"]["sha256"], "deployment lock catalogSha256 does not match config")
    require(FULL_SHA.fullmatch(nonempty_string(value.get("sourceCommit"), "deployment lock sourceCommit", 40)) is not None, "deployment lock sourceCommit must be a full SHA")
    require(SHA256.fullmatch(nonempty_string(value.get("buildIntentSha256"), "deployment lock buildIntentSha256", 64)) is not None, "deployment lock buildIntentSha256 is invalid")
    if intent is not None:
        require(value["buildIntentSha256"] == canonical_sha256(intent), "deployment lock does not bind the reviewed build intent")
        require(value["sourceCommit"] == intent["sourceCommit"], "deployment lock sourceCommit does not match build intent")
        require(value["infrastructureImages"] == intent["infrastructureImages"], "deployment lock infrastructure pins changed after review")
        require(value["healthProbe"] == intent["healthProbe"], "deployment lock health probe pin changed after review")
    generated_by = value.get("generatedBy")
    require(isinstance(generated_by, dict), "deployment lock generatedBy must be an object")
    strict_keys(generated_by, {"repository", "runId", "runAttempt", "workflowSha"}, "deployment lock generatedBy")
    require(all(isinstance(generated_by.get(key), str) and generated_by[key] for key in generated_by), "deployment lock generatedBy is incomplete")

    source_by_id = {item["id"]: item for item in config["sources"]}
    intent_by_id = {item["id"]: item for item in intent["services"]} if intent is not None else {}
    services = value.get("services")
    require(isinstance(services, list) and len(services) == len(source_by_id), "deployment lock services must exactly match application sources")
    locked_ids: set[str] = set()
    for index, service in enumerate(services):
        context = f"deploymentLock.services[{index}]"
        require(isinstance(service, dict), f"{context} must be an object")
        strict_keys(service, {"id", "repository", "commit", "image", "buildInputSha256", "sourceArchiveSha256", "artifactSha256", "provenanceDigest"}, context)
        service_id = nonempty_string(service.get("id"), f"{context}.id", 63)
        require(service_id in source_by_id and service_id not in locked_ids, f"{context}.id is unknown or duplicated")
        locked_ids.add(service_id)
        source = source_by_id[service_id]
        require(service.get("repository") == source["repository"], f"{context}.repository does not match config")
        require(service.get("commit") == source["commit"], f"{context}.commit does not match config")
        image = nonempty_string(service.get("image"), f"{context}.image", 512)
        require(re.fullmatch(r"ghcr\.io/[a-z0-9_.-]+/[a-z0-9_./-]+@sha256:[0-9a-f]{64}", image) is not None, f"{context}.image must be digest locked")
        require(SHA256.fullmatch(nonempty_string(service.get("buildInputSha256"), f"{context}.buildInputSha256", 64)) is not None, f"{context}.buildInputSha256 is invalid")
        require(SHA256.fullmatch(nonempty_string(service.get("sourceArchiveSha256"), f"{context}.sourceArchiveSha256", 64)) is not None, f"{context}.sourceArchiveSha256 is invalid")
        require(SHA256.fullmatch(nonempty_string(service.get("artifactSha256"), f"{context}.artifactSha256", 64)) is not None, f"{context}.artifactSha256 is invalid")
        require(IMAGE_DIGEST.fullmatch(nonempty_string(service.get("provenanceDigest"), f"{context}.provenanceDigest", 71)) is not None, f"{context}.provenanceDigest is invalid")
        if intent is not None:
            intended = intent_by_id[service_id]
            require(image.split("@", 1)[0] == intended["imageRepository"], f"{context}.image repository changed after review")
            require(service["buildInputSha256"] == intended["buildInputSha256"], f"{context}.build input changed after review")
    require(locked_ids == set(source_by_id), "deployment lock services do not exactly match sources")
    validate_pinned_assets(value, "deploymentLock")
    return value


def validate_runtime_secrets(config: dict[str, Any], environment_name: str) -> str:
    raw = os.environ.get(environment_name, "")
    require(bool(raw), f"named workflow secret {environment_name} is required")
    try:
        values = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ContractError(f"{environment_name} must be a JSON object") from exc
    require(isinstance(values, dict), f"{environment_name} must be a JSON object")
    requirements = {item["name"]: item["minLength"] for item in config["runtime"]["secrets"]}
    require(set(values) == set(requirements), f"{environment_name} names must exactly match runtime.secrets")
    for name, minimum in requirements.items():
        value = values[name]
        require(isinstance(value, str) and minimum <= len(value) <= 16_384, f"secret {name} does not satisfy its length contract")
        require("\x00" not in value and "\r" not in value, f"secret {name} contains prohibited control characters")
    return canonical_sha256({name: len(values[name]) for name in sorted(values)})


def command_validate(args: argparse.Namespace) -> None:
    require(args.enable_deployment == "true", "enable_deployment must be explicitly true")
    for name in (
        "github_app_grants_ready",
        "package_grants_ready",
        "manager_oidc_ready",
        "cloudflare_access_ready",
    ):
        require(getattr(args, name) == "true", f"{name} must be explicitly true")
    require(FULL_SHA.fullmatch(args.shared_actions_sha) is not None, "shared_actions_sha must be a full lowercase commit SHA")
    require(SHA256.fullmatch(args.package_grant_set_sha256) is not None, "package_grant_set_sha256 must be a SHA-256")
    require(SHA256.fullmatch(args.cloudflared_sha256) is not None, "cloudflared_sha256 must be a SHA-256")
    require(re.fullmatch(r"20[0-9]{2}\.[0-9]+\.[0-9]+", args.cloudflared_version) is not None, "cloudflared_version must be an exact release")

    config = validate_config(read_json(args.config), args.expected_service_count)
    intent = validate_build_intent(read_json(args.intent), config)
    require(intent["healthProbe"]["url"] == args.health_probe_url, "health_probe_url does not match the reviewed build intent")
    require(intent["healthProbe"]["sha256"] == args.health_probe_sha256, "health_probe_sha256 does not match the reviewed build intent")
    require(intent["healthProbe"]["size"] == args.health_probe_size, "health_probe_size does not match the reviewed build intent")
    require(all(item["imageRepository"].startswith(args.registry_prefix.rstrip("/") + "/") for item in intent["services"]), "all application image repositories must use registry_prefix")
    secret_shape_hash = validate_runtime_secrets(config, args.runtime_secrets_env)

    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "config.json", config, 0o644)
    write_json(output / "build-intent.json", intent, 0o644)
    matrix = {"include": [{"id": item["id"]} for item in sorted(config["sources"], key=lambda item: item["id"])]}
    write_json(output / "matrix.json", matrix, 0o644)
    metadata = {
        "apiVersion": "olivium.dev/workflow-validation/v1",
        "deploymentId": config["deploymentId"],
        "configSha256": canonical_sha256(config),
        "buildIntentSha256": canonical_sha256(intent),
        "catalogSha256": config["catalog"]["sha256"],
        "packageGrantSetSha256": args.package_grant_set_sha256,
        "secretShapeSha256": secret_shape_hash,
        "sharedActionsSha": args.shared_actions_sha,
        "serviceCount": len(config["sources"]),
    }
    write_json(output / "validation.json", metadata, 0o644)
    if args.github_output:
        write_github_output(
            {
                "matrix": canonical_json(matrix).decode("ascii"),
                "deployment_id": config["deploymentId"],
                "build_intent_sha256": metadata["buildIntentSha256"],
                "zone": config["zone"],
                "ttl_minutes": str(config["ttlMinutes"]),
            }
        )
    print(json.dumps({"ok": True, "deploymentId": config["deploymentId"], "serviceCount": len(config["sources"])}))


def command_validate_capability(args: argparse.Namespace) -> None:
    require(FULL_SHA.fullmatch(args.shared_actions_sha) is not None, "shared_actions_sha must be a full lowercase commit SHA")
    require(args.zone in {"fds-8.space", "fds-7.space"}, "zone is not allowlisted")
    manager_url = https_url(args.manager_url, "manager URL", allow_http=args.allow_http_for_tests)
    nonempty_string(args.manager_audience, "manager audience", 255)
    if not args.allow_http_for_tests:
        require(manager_url == MANAGER_URL, "manager URL is not the trusted Olivium manager origin")
        require(args.manager_audience == MANAGER_AUDIENCE, "manager audience is not the trusted Olivium audience")
    environment = nonempty_string(args.environment, "environment", 128)
    workflow_ref = nonempty_string(args.expected_job_workflow_ref, "expected_job_workflow_ref", 512)
    require(
        workflow_ref.startswith("olivium-dev/shared-github-actions/.github/workflows/")
        and workflow_ref.endswith("@" + args.shared_actions_sha)
        and workflow_ref.rsplit("/.github/workflows/", 1)[1].split("@", 1)[0]
        in {"deploy-jeeb-ephemeral.yml", "capability-jeeb-ephemeral.yml"},
        "expected_job_workflow_ref must identify the approved reusable workflow",
    )
    args.output.mkdir(parents=True, exist_ok=True)
    write_json(
        args.output / "capability-contract.json",
        {
            "apiVersion": "olivium.dev/capability-contract/v1",
            "managerUrl": args.manager_url.rstrip("/"),
            "managerAudience": args.manager_audience,
            "zone": args.zone,
            "environment": environment,
            "expectedJobWorkflowRef": workflow_ref,
            "expectedJobWorkflowSha": args.shared_actions_sha,
        },
        0o644,
    )
    print(json.dumps({"ok": True, "operation": "capability", "zone": args.zone}))


def command_finalize_lock(args: argparse.Namespace) -> None:
    require(FULL_SHA.fullmatch(args.shared_actions_sha) is not None, "shared_actions_sha must be a full lowercase commit SHA")
    config = validate_config(read_json(args.contracts / "config.json"), args.expected_service_count)
    intent = validate_build_intent(read_json(args.contracts / "build-intent.json"), config)
    expected = {item["id"]: item for item in intent["services"]}
    receipts: dict[str, Any] = {}
    receipt_fields = {
        "apiVersion", "serviceId", "imageRepository", "image", "manifestDigest",
        "artifactSha256", "provenanceDigest", "sourceArchiveSha256", "buildInputSha256",
        "runId", "runAttempt",
    }
    for path in args.receipts.rglob("receipt.json"):
        receipt = read_json(path)
        require(isinstance(receipt, dict), f"invalid registry receipt: {path}")
        strict_keys(receipt, receipt_fields, f"registry receipt {path}")
        require(receipt.get("apiVersion") == "olivium.dev/registry-receipt/v1", f"unsupported registry receipt: {path}")
        service_id = receipt.get("serviceId")
        require(service_id in expected and service_id not in receipts, f"unknown or duplicate registry receipt: {service_id}")
        intended = expected[service_id]
        require(receipt.get("imageRepository") == intended["imageRepository"], f"registry receipt repository mismatch for {service_id}")
        digest = receipt.get("manifestDigest")
        require(isinstance(digest, str) and IMAGE_DIGEST.fullmatch(digest) is not None, f"registry receipt digest is invalid for {service_id}")
        require(receipt.get("image") == f"{intended['imageRepository']}@{digest}", f"registry receipt image mismatch for {service_id}")
        require(receipt.get("buildInputSha256") == intended["buildInputSha256"], f"registry receipt build input mismatch for {service_id}")
        require(SHA256.fullmatch(nonempty_string(receipt.get("artifactSha256"), "artifactSha256", 64)) is not None, f"registry receipt artifact digest is invalid for {service_id}")
        require(SHA256.fullmatch(nonempty_string(receipt.get("sourceArchiveSha256"), "sourceArchiveSha256", 64)) is not None, f"registry receipt source digest is invalid for {service_id}")
        require(IMAGE_DIGEST.fullmatch(nonempty_string(receipt.get("provenanceDigest"), "provenanceDigest", 71)) is not None, f"registry receipt provenance digest is invalid for {service_id}")
        require(receipt.get("runId") == os.environ.get("GITHUB_RUN_ID", receipt.get("runId")), f"registry receipt runId mismatch for {service_id}")
        require(receipt.get("runAttempt") == os.environ.get("GITHUB_RUN_ATTEMPT", receipt.get("runAttempt")), f"registry receipt runAttempt mismatch for {service_id}")
        receipts[service_id] = receipt
    require(set(receipts) == set(expected), "registry receipts must exactly match the reviewed build intent")

    final_services = []
    sources = {item["id"]: item for item in config["sources"]}
    for service_id in sorted(receipts):
        receipt = receipts[service_id]
        intended = expected[service_id]
        final_services.append(
            {
                "id": service_id,
                "repository": sources[service_id]["repository"],
                "commit": sources[service_id]["commit"],
                "image": receipt["image"],
                "buildInputSha256": intended["buildInputSha256"],
                "sourceArchiveSha256": receipt["sourceArchiveSha256"],
                "artifactSha256": receipt["artifactSha256"],
                "provenanceDigest": receipt["provenanceDigest"],
            }
        )
    final_lock = {
        "apiVersion": LOCK_VERSION,
        "deploymentId": config["deploymentId"],
        "configSha256": canonical_sha256(config),
        "catalogSha256": config["catalog"]["sha256"],
        "buildIntentSha256": canonical_sha256(intent),
        "sourceCommit": intent["sourceCommit"],
        "services": final_services,
        "infrastructureImages": intent["infrastructureImages"],
        "healthProbe": intent["healthProbe"],
        "generatedBy": {
            "repository": os.environ.get("GITHUB_REPOSITORY", "offline-test"),
            "runId": os.environ.get("GITHUB_RUN_ID", "offline-test"),
            "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
            "workflowSha": args.shared_actions_sha,
        },
    }
    validate_final_lock(final_lock, config, intent)
    args.output.mkdir(parents=True, exist_ok=True)
    write_json(args.output / "deployment-lock.json", final_lock, 0o644)
    lock_sha256 = canonical_sha256(final_lock)
    write_json(
        args.output / "deployment-lock-receipt.json",
        {
            "apiVersion": "olivium.dev/deployment-lock-receipt/v1",
            "deploymentId": config["deploymentId"],
            "deploymentLockSha256": lock_sha256,
            "buildIntentSha256": canonical_sha256(intent),
            "serviceCount": len(final_services),
        },
        0o644,
    )
    if args.github_output:
        write_github_output({"deployment_lock_sha256": lock_sha256})
    print(json.dumps({"ok": True, "deploymentLockSha256": lock_sha256, "serviceCount": len(final_services)}))


def command_assemble(args: argparse.Namespace) -> None:
    config = validate_config(read_json(args.contracts / "config.json"), args.expected_service_count)
    intent = validate_build_intent(read_json(args.contracts / "build-intent.json"), config)
    lock = validate_final_lock(read_json(args.final_lock / "deployment-lock.json"), config, intent)
    probe_receipt = read_json(args.health_probe / "health-probe.json")
    require(isinstance(probe_receipt, dict), "health probe receipt must be an object")
    strict_keys(probe_receipt, {"apiVersion", "sha256", "size", "mode", "provenanceSha256"}, "health probe receipt")
    require(probe_receipt.get("apiVersion") == "olivium.dev/health-probe-artifact/v1", "health probe receipt version mismatch")
    require(probe_receipt.get("sha256") == lock["healthProbe"]["sha256"], "health probe receipt digest mismatch")
    require(probe_receipt.get("size") == lock["healthProbe"]["size"], "health probe receipt size mismatch")
    require(probe_receipt.get("mode") == "0555", "health probe must be mounted read-execute")
    probe_binary = args.health_probe / "olivium-http-probe"
    require(probe_binary.is_file() and __import__("hashlib").sha256(probe_binary.read_bytes()).hexdigest() == lock["healthProbe"]["sha256"], "health probe binary mismatch")

    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="olivium-runtime-") as temporary:
        root = Path(temporary)
        write_json(root / "config.json", config, 0o644)
        write_json(root / "deployment-lock.json", lock, 0o644)
        shutil.copy2(args.remote_runtime, root / "remote_runtime.py")
        shutil.copy2(probe_binary, root / "olivium-http-probe")
        shutil.copy2(args.health_probe / "health-probe-provenance.json", root / "health-probe-provenance.json")
        manifest = {
            "apiVersion": "olivium.dev/runtime-bundle/v1",
            "deploymentId": config["deploymentId"],
            "lockSha256": canonical_sha256(lock),
            "files": {
                name: canonical_sha256(read_json(root / name)) if name.endswith(".json") else None
                for name in ("config.json", "deployment-lock.json", "health-probe-provenance.json")
            },
        }
        manifest["files"]["remote_runtime.py"] = __import__("hashlib").sha256((root / "remote_runtime.py").read_bytes()).hexdigest()
        manifest["files"]["olivium-http-probe"] = __import__("hashlib").sha256((root / "olivium-http-probe").read_bytes()).hexdigest()
        write_json(root / "bundle-manifest.json", manifest, 0o644)
        with tarfile.open(args.output / "runtime-bundle.tar.gz", "w:gz", format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(root.iterdir()):
                info = archive.gettarinfo(str(path), arcname=path.name)
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                info.mtime = 0
                with path.open("rb") as handle:
                    archive.addfile(info, handle)
    write_json(
        args.output / "bundle.json",
        {
            "apiVersion": "olivium.dev/runtime-bundle-receipt/v1",
            "deploymentId": config["deploymentId"],
            "lockSha256": canonical_sha256(lock),
            "bundleSha256": __import__("hashlib").sha256((args.output / "runtime-bundle.tar.gz").read_bytes()).hexdigest(),
        },
        0o644,
    )
    print(json.dumps({"ok": True, "deploymentId": config["deploymentId"], "serviceCount": len(lock["services"])}))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate-workflow")
    validate.add_argument("--config", type=Path, required=True)
    validate.add_argument("--intent", type=Path, required=True)
    validate.add_argument("--output", type=Path, required=True)
    validate.add_argument("--expected-service-count", type=int, default=24)
    validate.add_argument("--shared-actions-sha", required=True)
    validate.add_argument("--registry-prefix", required=True)
    validate.add_argument("--package-grant-set-sha256", required=True)
    validate.add_argument("--cloudflared-version", required=True)
    validate.add_argument("--cloudflared-sha256", required=True)
    validate.add_argument("--health-probe-url", required=True)
    validate.add_argument("--health-probe-sha256", required=True)
    validate.add_argument("--health-probe-size", type=int, required=True)
    validate.add_argument("--runtime-secrets-env", default="JEEB_RUNTIME_SECRETS_JSON")
    validate.add_argument("--enable-deployment", required=True)
    validate.add_argument("--github-app-grants-ready", required=True)
    validate.add_argument("--package-grants-ready", required=True)
    validate.add_argument("--manager-oidc-ready", required=True)
    validate.add_argument("--cloudflare-access-ready", required=True)
    validate.add_argument("--github-output", action="store_true")
    validate.set_defaults(handler=command_validate)

    capability = subparsers.add_parser("validate-capability")
    capability.add_argument("--shared-actions-sha", required=True)
    capability.add_argument("--manager-url", required=True)
    capability.add_argument("--manager-audience", required=True)
    capability.add_argument("--zone", required=True)
    capability.add_argument("--environment", required=True)
    capability.add_argument("--expected-job-workflow-ref", required=True)
    capability.add_argument("--output", type=Path, required=True)
    capability.add_argument("--allow-http-for-tests", action="store_true")
    capability.set_defaults(handler=command_validate_capability)

    finalize = subparsers.add_parser("finalize-lock")
    finalize.add_argument("--contracts", type=Path, required=True)
    finalize.add_argument("--receipts", type=Path, required=True)
    finalize.add_argument("--output", type=Path, required=True)
    finalize.add_argument("--shared-actions-sha", required=True)
    finalize.add_argument("--expected-service-count", type=int, default=24)
    finalize.add_argument("--github-output", action="store_true")
    finalize.set_defaults(handler=command_finalize_lock)

    assemble = subparsers.add_parser("assemble")
    assemble.add_argument("--contracts", type=Path, required=True)
    assemble.add_argument("--final-lock", type=Path, required=True)
    assemble.add_argument("--remote-runtime", type=Path, required=True)
    assemble.add_argument("--health-probe", type=Path, required=True)
    assemble.add_argument("--output", type=Path, required=True)
    assemble.add_argument("--expected-service-count", type=int, default=24)
    assemble.set_defaults(handler=command_assemble)
    return parser


def main() -> int:
    try:
        args = build_parser().parse_args()
        args.handler(args)
        return 0
    except ContractError as exc:
        print(f"contract validation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
