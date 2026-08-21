#!/usr/bin/env python3
"""Resolve exact private sources through the trusted GitHub App broker contract."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common import (
    SOURCE_BROKER_VERSION,
    ContractError,
    MANAGER_AUDIENCE,
    MANAGER_URL,
    canonical_sha256,
    digest_header_sha256,
    https_url,
    nonempty_string,
    oidc_token,
    read_json,
    request_bytes,
    request_json,
    require,
    safe_tar_members,
    sha256_bytes,
    strict_keys,
    write_json,
)
from contracts import validate_build_intent, validate_config


def caller_identity() -> dict[str, str]:
    names = {
        "repository": "GITHUB_REPOSITORY",
        "repositoryId": "GITHUB_REPOSITORY_ID",
        "runId": "GITHUB_RUN_ID",
        "runAttempt": "GITHUB_RUN_ATTEMPT",
        "workflowRef": "GITHUB_WORKFLOW_REF",
        "sha": "GITHUB_SHA",
    }
    identity: dict[str, str] = {}
    for key, environment_name in names.items():
        value = os.environ.get(environment_name, "")
        if not value and environment_name in {"GITHUB_REPOSITORY", "GITHUB_RUN_ID"}:
            raise ContractError(f"{environment_name} is required")
        identity[key] = value
    return identity


def load_contracts(path: Path, expected_service_count: int) -> tuple[dict[str, Any], dict[str, Any]]:
    config = validate_config(read_json(path / "config.json"), expected_service_count)
    intent = validate_build_intent(read_json(path / "build-intent.json"), config)
    return config, intent


def broker_url(base: str, suffix: str, allow_http: bool) -> str:
    trusted = https_url(base, "source broker URL", allow_http=allow_http)
    if not allow_http:
        require(trusted == MANAGER_URL, "source broker URL is not the trusted Olivium manager origin")
    return f"{trusted}{suffix}"


def get_token(args: argparse.Namespace) -> str:
    if not args.allow_http_for_tests:
        require(args.audience == MANAGER_AUDIENCE, "source broker audience is not the trusted Olivium audience")
    return oidc_token(args.audience, static_env=args.static_oidc_env)


def command_preflight(args: argparse.Namespace) -> None:
    config, intent = load_contracts(args.contracts, args.expected_service_count)
    token = get_token(args)
    request = {
        "apiVersion": SOURCE_BROKER_VERSION,
        "deploymentId": config["deploymentId"],
        "buildIntentSha256": canonical_sha256(intent),
        "repositories": [
            {"id": item["id"], "repository": item["repository"], "commit": item["commit"]}
            for item in sorted(config["sources"], key=lambda item: item["id"])
        ],
        "requiredPackageGrantSetSha256": args.package_grant_set_sha256,
        "caller": caller_identity(),
    }
    payload, _ = request_json(
        "POST",
        broker_url(args.base_url, "/v1/preflight", args.allow_http_for_tests),
        bearer=token,
        body=request,
    )
    require(isinstance(payload, dict), "source broker preflight response must be an object")
    strict_keys(payload, {"apiVersion", "ready", "installationId", "repositories", "packageGrantSetSha256", "expiresAt"}, "source broker preflight response")
    require(payload.get("apiVersion") == SOURCE_BROKER_VERSION, "source broker API version mismatch")
    require(payload.get("ready") is True, "source broker is not ready")
    nonempty_string(payload.get("installationId"), "source broker installationId", 64)
    require(payload.get("packageGrantSetSha256") == args.package_grant_set_sha256, "package grant evidence does not match the owner-approved hash")
    repositories = payload.get("repositories")
    require(isinstance(repositories, list), "source broker repositories must be an array")
    expected = {(item["repository"], item["commit"]) for item in config["sources"]}
    actual: set[tuple[str, str]] = set()
    for item in repositories:
        require(isinstance(item, dict), "source broker repository result must be an object")
        strict_keys(item, {"repository", "commit", "allowed"}, "source broker repository result")
        require(item.get("allowed") is True, f"source broker denied {item.get('repository', 'unknown repository')}")
        actual.add((item.get("repository"), item.get("commit")))
    require(actual == expected, "source broker grant set does not exactly match reviewed sources")
    expires_at = nonempty_string(payload.get("expiresAt"), "source broker expiresAt", 64)
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError("source broker expiresAt is invalid") from exc
    require(expiry > datetime.now(timezone.utc), "source broker preflight evidence is expired")
    args.output.mkdir(parents=True, exist_ok=True)
    write_json(
        args.output / "source-preflight.json",
        {
            "apiVersion": SOURCE_BROKER_VERSION,
            "ready": True,
            "installationId": payload["installationId"],
            "packageGrantSetSha256": payload["packageGrantSetSha256"],
            "expiresAt": expires_at,
            "repositoriesSha256": canonical_sha256(sorted([list(item) for item in actual])),
        },
        0o644,
    )
    print(json.dumps({"ok": True, "repositoryCount": len(actual)}))


def command_fetch(args: argparse.Namespace) -> None:
    config, intent = load_contracts(args.contracts, args.expected_service_count)
    sources = {item["id"]: item for item in config["sources"]}
    require(args.service_id in sources, f"unknown service ID: {args.service_id}")
    source = sources[args.service_id]
    intended = next(item for item in intent["services"] if item["id"] == args.service_id)
    request = {
        "apiVersion": SOURCE_BROKER_VERSION,
        "deploymentId": config["deploymentId"],
        "buildIntentSha256": canonical_sha256(intent),
        "source": {
            "id": source["id"],
            "repository": source["repository"],
            "commit": source["commit"],
            "buildInputSha256": intended["buildInputSha256"],
        },
        "caller": caller_identity(),
    }
    raw, headers = request_bytes(
        "POST",
        broker_url(args.base_url, "/v1/source-bundles", args.allow_http_for_tests),
        bearer=get_token(args),
        body=request,
    )
    require(len(raw) <= args.max_archive_bytes, "source bundle exceeds the compressed size limit")
    expected_digest = digest_header_sha256(headers)
    actual_digest = sha256_bytes(raw)
    require(actual_digest == expected_digest, "source bundle digest does not match the broker Digest header")
    require(headers.get("X-Olivium-Source-Id") == source["id"], "source broker returned the wrong service")
    require(headers.get("X-Olivium-Source-Repository") == source["repository"], "source broker returned the wrong repository")
    require(headers.get("X-Olivium-Source-Commit") == source["commit"], "source broker returned the wrong commit")
    content_type = (headers.get("Content-Type") or "").split(";", 1)[0]
    require(content_type == "application/vnd.olivium.source-bundle.v1+tar+gzip", "source broker returned an unsupported content type")

    args.output.mkdir(parents=True, exist_ok=True)
    bundle = args.output / "source.tar.gz"
    bundle.write_bytes(raw)
    bundle.chmod(0o600)
    try:
        with tarfile.open(bundle, "r:gz") as archive:
            members = safe_tar_members(archive, max_bytes=args.max_uncompressed_bytes)
            require(any(member.isfile() for member in members), "source bundle is empty")
    except tarfile.TarError as exc:
        raise ContractError(f"source broker returned an invalid tar archive: {exc}") from exc
    write_json(
        args.output / "source.json",
        {
            "apiVersion": "olivium.dev/resolved-source/v1",
            "serviceId": source["id"],
            "repository": source["repository"],
            "commit": source["commit"],
            "archiveSha256": actual_digest,
            "buildInputSha256": intended["buildInputSha256"],
        },
        0o644,
    )
    print(json.dumps({"ok": True, "serviceId": source["id"], "archiveSha256": actual_digest}))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("preflight", "fetch"):
        command = subparsers.add_parser(name)
        command.add_argument("--contracts", type=Path, required=True)
        command.add_argument("--base-url", required=True)
        command.add_argument("--audience", required=True)
        command.add_argument("--expected-service-count", type=int, default=24)
        command.add_argument("--static-oidc-env")
        command.add_argument("--allow-http-for-tests", action="store_true")
        if name == "preflight":
            command.add_argument("--package-grant-set-sha256", required=True)
            command.add_argument("--output", type=Path, required=True)
            command.set_defaults(handler=command_preflight)
        else:
            command.add_argument("--service-id", required=True)
            command.add_argument("--output", type=Path, required=True)
            command.add_argument("--max-archive-bytes", type=int, default=500_000_000)
            command.add_argument("--max-uncompressed-bytes", type=int, default=2_000_000_000)
            command.set_defaults(handler=command_fetch)
    return parser


def main() -> int:
    try:
        args = build_parser().parse_args()
        args.handler(args)
        return 0
    except ContractError as exc:
        print(f"source broker contract failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
