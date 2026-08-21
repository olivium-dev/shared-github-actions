#!/usr/bin/env python3
"""Run credential-free tests and build one digest-locked OCI image artifact."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

from common import (
    ContractError,
    IMAGE_DIGEST,
    canonical_sha256,
    extract_tar_safely,
    read_json,
    require,
    safe_tar_members,
    sha256_bytes,
    sha256_file,
    strict_keys,
    write_json,
)
from contracts import validate_build_intent, validate_config


PROHIBITED_ENV_MARKERS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PRIVATE_KEY",
    "ACTIONS_ID_TOKEN",
    "CLOUDFLARE",
    "PROXMOX",
    "SSH_AUTH_SOCK",
)


def credential_free_environment() -> dict[str, str]:
    allowed = {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "CI",
        "RUNNER_OS",
        "RUNNER_ARCH",
        "TMPDIR",
        "DOCKER_HOST",
        "DOCKER_BUILDKIT",
        "BUILDX_CONFIG",
    }
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    for key in environment:
        require(not any(marker in key.upper() for marker in PROHIBITED_ENV_MARKERS), f"credential-like environment variable leaked into build: {key}")
    environment["CI"] = "true"
    environment["DOCKER_BUILDKIT"] = "1"
    return environment


def service_contracts(contracts: Path, service_id: str, expected_service_count: int) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    config = validate_config(read_json(contracts / "config.json"), expected_service_count)
    intent = validate_build_intent(read_json(contracts / "build-intent.json"), config)
    source = next((item for item in config["sources"] if item["id"] == service_id), None)
    intended = next((item for item in intent["services"] if item["id"] == service_id), None)
    require(source is not None and intended is not None, f"service {service_id} is absent from reviewed contracts")
    build_input = {
        "catalogSha256": config["catalog"]["sha256"],
        "repository": source["repository"],
        "commit": source["commit"],
        "context": source["context"],
        "dockerfile": source["dockerfile"],
        "test": source["test"],
        "buildArgs": source["buildArgs"],
    }
    require(canonical_sha256(build_input) == intended["buildInputSha256"], f"buildInputSha256 mismatch for {service_id}")
    return config, source, intended


def validate_resolved_source(path: Path, source: dict[str, Any], intended: dict[str, Any]) -> dict[str, Any]:
    metadata = read_json(path / "source.json")
    require(isinstance(metadata, dict), "resolved source metadata must be an object")
    strict_keys(metadata, {"apiVersion", "serviceId", "repository", "commit", "archiveSha256", "buildInputSha256"}, "resolved source metadata")
    require(metadata.get("apiVersion") == "olivium.dev/resolved-source/v1", "resolved source API version mismatch")
    require(metadata.get("serviceId") == source["id"], "resolved source ID mismatch")
    require(metadata.get("repository") == source["repository"], "resolved source repository mismatch")
    require(metadata.get("commit") == source["commit"], "resolved source commit mismatch")
    require(metadata.get("buildInputSha256") == intended["buildInputSha256"], "resolved source build input mismatch")
    archive = path / "source.tar.gz"
    require(archive.is_file(), "resolved source archive is missing")
    require(metadata.get("archiveSha256") == sha256_file(archive), "resolved source archive digest mismatch")
    return metadata


def run_checked(argv: list[str], *, cwd: Path, environment: dict[str, str], timeout: int, log: Path) -> None:
    started = time.monotonic()
    with log.open("wb") as output:
        try:
            completed = subprocess.run(
                argv,
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ContractError(f"command timed out after {timeout} seconds") from exc
    require(completed.returncode == 0, f"credential-free command failed with exit code {completed.returncode}; see retained job log")
    elapsed = int(time.monotonic() - started)
    print(json.dumps({"command": argv[0], "ok": True, "elapsedSeconds": elapsed}))


def oci_manifest_digest(archive_path: Path) -> str:
    with tarfile.open(archive_path, "r:*") as archive:
        members = safe_tar_members(archive, max_files=200_000, max_bytes=5_000_000_000)
        names = {member.name: member for member in members}
        require("oci-layout" in names and "index.json" in names, "build output is not an OCI image layout")
        index_file = archive.extractfile(names["index.json"])
        require(index_file is not None, "OCI index.json is unreadable")
        try:
            index = json.load(index_file)
        except json.JSONDecodeError as exc:
            raise ContractError("OCI index.json is invalid") from exc
        require(isinstance(index, dict) and index.get("schemaVersion") == 2, "OCI index schema is invalid")
        manifests = index.get("manifests")
        require(isinstance(manifests, list) and len(manifests) == 1, "OCI layout must contain exactly one manifest")
        descriptor = manifests[0]
        require(isinstance(descriptor, dict), "OCI manifest descriptor is invalid")
        digest = descriptor.get("digest")
        require(isinstance(digest, str) and IMAGE_DIGEST.fullmatch(digest) is not None, "OCI manifest digest is invalid")
        blob_name = f"blobs/sha256/{digest.removeprefix('sha256:')}"
        require(blob_name in names and names[blob_name].isfile(), "OCI manifest blob is missing")
        blob = archive.extractfile(names[blob_name])
        require(blob is not None, "OCI manifest blob is unreadable")
        require(f"sha256:{sha256_bytes(blob.read())}" == digest, "OCI manifest blob digest mismatch")
        return digest


def command_build(args: argparse.Namespace) -> None:
    config, source, intended = service_contracts(args.contracts, args.service_id, args.expected_service_count)
    resolved = validate_resolved_source(args.source, source, intended)
    args.output.mkdir(parents=True, exist_ok=True)
    environment = credential_free_environment()

    with tempfile.TemporaryDirectory(prefix=f"jeeb-{args.service_id}-") as temporary:
        root = Path(temporary)
        repository_root = root / "source"
        extract_tar_safely(args.source / "source.tar.gz", repository_root)
        context = repository_root / source["context"]
        dockerfile = repository_root / source["dockerfile"]
        require(context.is_dir(), "reviewed Docker build context is missing")
        require(dockerfile.is_file() and dockerfile.is_relative_to(repository_root), "reviewed Dockerfile is missing")

        dockerfile_text = dockerfile.read_text(encoding="utf-8", errors="strict")
        for prohibited in ("--mount=type=secret", "--mount=type=ssh"):
            require(prohibited not in dockerfile_text.lower(), f"Dockerfile credential mount is prohibited: {prohibited}")

        test_log = args.output / "test.log"
        run_checked(
            list(source["test"]["argv"]),
            cwd=context,
            environment=environment,
            timeout=source["test"]["timeoutMinutes"] * 60,
            log=test_log,
        )

        image_archive = args.output / "image.oci.tar"
        image_name = intended["imageRepository"]
        command = [
            "docker",
            "buildx",
            "build",
            "--file",
            str(dockerfile),
            "--platform",
            "linux/amd64",
            "--provenance=false",
            "--sbom=false",
            "--output",
            f"type=oci,dest={image_archive}",
            "--tag",
            f"{image_name}:candidate",
            "--label",
            f"com.olivium.source.repository={source['repository']}",
            "--label",
            f"com.olivium.source.commit={source['commit']}",
            "--label",
            f"com.olivium.deployment={config['deploymentId']}",
        ]
        for key, value in sorted(source["buildArgs"].items()):
            command.extend(["--build-arg", f"{key}={value}"])
        command.append(str(context))
        run_checked(command, cwd=repository_root, environment=environment, timeout=args.build_timeout_minutes * 60, log=args.output / "build.log")

    digest = oci_manifest_digest(args.output / "image.oci.tar")
    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": intended["imageRepository"], "digest": {"sha256": digest.removeprefix("sha256:")}}],
        "predicateType": "https://olivium.dev/provenance/credential-free-build/v1",
        "predicate": {
            "deploymentId": config["deploymentId"],
            "serviceId": args.service_id,
            "source": {
                "repository": source["repository"],
                "commit": source["commit"],
                "archiveSha256": resolved["archiveSha256"],
            },
            "buildInputSha256": intended["buildInputSha256"],
            "testLogSha256": sha256_file(args.output / "test.log"),
            "buildLogSha256": sha256_file(args.output / "build.log"),
            "runner": {
                "repository": os.environ.get("GITHUB_REPOSITORY", ""),
                "runId": os.environ.get("GITHUB_RUN_ID", ""),
                "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
                "job": os.environ.get("GITHUB_JOB", ""),
            },
            "credentialFree": True,
        },
    }
    write_json(args.output / "provenance.json", provenance, 0o644)
    write_json(
        args.output / "artifact.json",
        {
            "apiVersion": "olivium.dev/image-artifact/v1",
            "serviceId": args.service_id,
            "imageRepository": intended["imageRepository"],
            "image": f"{intended['imageRepository']}@{digest}",
            "manifestDigest": digest,
            "ociArchiveSha256": sha256_file(args.output / "image.oci.tar"),
            "provenanceSha256": sha256_file(args.output / "provenance.json"),
            "sourceArchiveSha256": resolved["archiveSha256"],
            "buildInputSha256": intended["buildInputSha256"],
        },
        0o644,
    )
    print(json.dumps({"ok": True, "serviceId": args.service_id, "manifestDigest": digest}))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service-id", required=True)
    parser.add_argument("--contracts", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-service-count", type=int, default=24)
    parser.add_argument("--build-timeout-minutes", type=int, default=45)
    return parser


def main() -> int:
    try:
        command_build(build_parser().parse_args())
        return 0
    except (ContractError, OSError) as exc:
        print(f"credential-free build failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
