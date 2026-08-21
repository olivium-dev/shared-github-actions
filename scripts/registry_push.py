#!/usr/bin/env python3
"""Push a reviewed OCI artifact to GHCR without checking out or executing source."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import ssl
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from common import (
    ContractError,
    IMAGE_DIGEST,
    canonical_json,
    canonical_sha256,
    extract_tar_safely,
    read_json,
    require,
    sha256_bytes,
    sha256_file,
    strict_keys,
    write_json,
)
from contracts import validate_build_intent, validate_config


ALLOWED_ARTIFACT_FILES = {"image.oci.tar", "artifact.json", "provenance.json"}


class GhcrClient:
    def __init__(self, repository: str, actor: str, token: str) -> None:
        self.repository = repository
        self.actor = actor
        self._token = token
        self._bearer = self._exchange_token()

    def _exchange_token(self) -> str:
        query = urllib.parse.urlencode(
            {"service": "ghcr.io", "scope": f"repository:{self.repository}:pull,push"}
        )
        basic = base64.b64encode(f"{self.actor}:{self._token}".encode()).decode("ascii")
        request = urllib.request.Request(
            f"https://ghcr.io/token?{query}",
            headers={"Authorization": f"Basic {basic}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30, context=ssl.create_default_context()) as response:
                payload = json.load(response)
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            raise ContractError(f"GHCR token exchange failed: {exc}") from exc
        bearer = payload.get("token") if isinstance(payload, dict) else None
        require(isinstance(bearer, str) and bearer, "GHCR token exchange returned no bearer token")
        return bearer

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        content_type: str | None = None,
        expected: tuple[int, ...],
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPSConnection("ghcr.io", timeout=120, context=ssl.create_default_context())
        headers = {"Authorization": f"Bearer {self._bearer}", "User-Agent": "olivium-registry-push/1"}
        if content_type:
            headers["Content-Type"] = content_type
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response_body = response.read(16_384)
        response_headers = {key: value for key, value in response.getheaders()}
        status = response.status
        connection.close()
        require(status in expected, f"GHCR {method} returned HTTP {status}")
        return status, response_headers, response_body

    def has_blob(self, digest: str) -> bool:
        status, _, _ = self._request(
            "HEAD",
            f"/v2/{self.repository}/blobs/{digest}",
            expected=(200, 404),
        )
        return status == 200

    def upload_blob(self, path: Path, digest: str) -> None:
        require(f"sha256:{sha256_file(path)}" == digest, f"local OCI blob does not match {digest}")
        if self.has_blob(digest):
            return
        _, headers, _ = self._request(
            "POST",
            f"/v2/{self.repository}/blobs/uploads/",
            expected=(202,),
        )
        location = headers.get("Location") or headers.get("location")
        require(isinstance(location, str) and location, "GHCR blob upload did not return a Location")
        parsed = urllib.parse.urlsplit(urllib.parse.urljoin("https://ghcr.io", location))
        require(parsed.scheme == "https" and parsed.hostname == "ghcr.io", "GHCR blob upload redirected outside ghcr.io")
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query.append(("digest", digest))
        target = urllib.parse.urlunsplit(("", "", parsed.path, urllib.parse.urlencode(query), ""))
        connection = http.client.HTTPSConnection("ghcr.io", timeout=300, context=ssl.create_default_context())
        connection.putrequest("PUT", target)
        connection.putheader("Authorization", f"Bearer {self._bearer}")
        connection.putheader("Content-Type", "application/octet-stream")
        connection.putheader("Content-Length", str(path.stat().st_size))
        connection.putheader("User-Agent", "olivium-registry-push/1")
        connection.endheaders()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                connection.send(chunk)
        response = connection.getresponse()
        response.read(16_384)
        status = response.status
        connection.close()
        require(status == 201, f"GHCR blob upload returned HTTP {status}")

    def put_manifest(self, reference: str, manifest: bytes, media_type: str) -> str:
        expected_digest = f"sha256:{sha256_bytes(manifest)}"
        _, put_headers, _ = self._request(
            "PUT",
            f"/v2/{self.repository}/manifests/{urllib.parse.quote(reference, safe=':-_.')}",
            body=manifest,
            content_type=media_type,
            expected=(201,),
        )
        put_digest = next(
            (value for key, value in put_headers.items() if key.lower() == "docker-content-digest"),
            None,
        )
        require(put_digest == expected_digest, "GHCR PUT did not confirm the expected manifest digest")
        _, head_headers, _ = self._request(
            "HEAD",
            f"/v2/{self.repository}/manifests/{urllib.parse.quote(reference, safe=':-_.')}",
            expected=(200,),
        )
        observed_digest = next(
            (value for key, value in head_headers.items() if key.lower() == "docker-content-digest"),
            None,
        )
        require(observed_digest == expected_digest, "GHCR HEAD did not observe the expected manifest digest")
        return observed_digest


def load_oci_layout(archive: Path, destination: Path) -> tuple[dict[str, Any], bytes]:
    extract_tar_safely(archive, destination, max_bytes=5_000_000_000)
    index = read_json(destination / "index.json")
    require(isinstance(index, dict) and index.get("schemaVersion") == 2, "OCI index is invalid")
    manifests = index.get("manifests")
    require(isinstance(manifests, list) and len(manifests) == 1, "OCI layout must contain exactly one manifest")
    descriptor = manifests[0]
    require(isinstance(descriptor, dict) and IMAGE_DIGEST.fullmatch(str(descriptor.get("digest"))) is not None, "OCI descriptor is invalid")
    manifest_path = destination / "blobs" / "sha256" / descriptor["digest"].removeprefix("sha256:")
    require(manifest_path.is_file(), "OCI manifest blob is missing")
    manifest = manifest_path.read_bytes()
    require(f"sha256:{sha256_bytes(manifest)}" == descriptor["digest"], "OCI manifest digest mismatch")
    return descriptor, manifest


def push_provenance(client: GhcrClient, descriptor: dict[str, Any], provenance_path: Path) -> str:
    provenance = provenance_path.read_bytes()
    provenance_digest = f"sha256:{sha256_bytes(provenance)}"
    empty_config = b"{}"
    config_digest = f"sha256:{sha256_bytes(empty_config)}"
    with tempfile.TemporaryDirectory(prefix="olivium-provenance-") as temporary:
        root = Path(temporary)
        provenance_blob = root / provenance_digest.removeprefix("sha256:")
        config_blob = root / config_digest.removeprefix("sha256:")
        provenance_blob.write_bytes(provenance)
        config_blob.write_bytes(empty_config)
        client.upload_blob(provenance_blob, provenance_digest)
        client.upload_blob(config_blob, config_digest)
    artifact = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.in-toto+json",
        "config": {
            "mediaType": "application/vnd.unknown.config.v1+json",
            "digest": config_digest,
            "size": len(empty_config),
        },
        "layers": [
            {
                "mediaType": "application/vnd.in-toto+json",
                "digest": provenance_digest,
                "size": len(provenance),
            }
        ],
        "subject": {
            "mediaType": descriptor.get("mediaType", "application/vnd.oci.image.manifest.v1+json"),
            "digest": descriptor["digest"],
            "size": descriptor["size"],
        },
        "annotations": {"dev.olivium.provenance.type": "credential-free-build-v1"},
    }
    artifact_bytes = canonical_json(artifact)
    tag = f"sha256-{descriptor['digest'].removeprefix('sha256:')}.olivium-provenance"
    return client.put_manifest(tag, artifact_bytes, "application/vnd.oci.image.manifest.v1+json")


def command_push(args: argparse.Namespace) -> None:
    actual_files = {path.name for path in args.artifact.iterdir() if path.is_file()}
    require(actual_files == ALLOWED_ARTIFACT_FILES, "source-free push artifact contains unexpected files")
    config = validate_config(read_json(args.contracts / "config.json"), args.expected_service_count)
    intent = validate_build_intent(read_json(args.contracts / "build-intent.json"), config)
    intended = next((item for item in intent["services"] if item["id"] == args.service_id), None)
    require(intended is not None, f"unknown service ID: {args.service_id}")
    artifact = read_json(args.artifact / "artifact.json")
    require(isinstance(artifact, dict), "image artifact receipt is invalid")
    strict_keys(
        artifact,
        {
            "apiVersion", "serviceId", "imageRepository", "image", "manifestDigest",
            "ociArchiveSha256", "provenanceSha256", "sourceArchiveSha256", "buildInputSha256",
        },
        "image artifact receipt",
    )
    require(artifact.get("apiVersion") == "olivium.dev/image-artifact/v1", "image artifact API version mismatch")
    require(artifact.get("serviceId") == args.service_id, "image artifact service ID mismatch")
    require(artifact.get("imageRepository") == intended["imageRepository"], "image artifact repository mismatch")
    manifest_digest = artifact.get("manifestDigest")
    require(isinstance(manifest_digest, str) and IMAGE_DIGEST.fullmatch(manifest_digest) is not None, "image artifact manifest digest is invalid")
    require(artifact.get("image") == f"{intended['imageRepository']}@{manifest_digest}", "image artifact reference mismatch")
    require(artifact.get("buildInputSha256") == intended["buildInputSha256"], "image artifact build input mismatch")
    require(artifact.get("ociArchiveSha256") == sha256_file(args.artifact / "image.oci.tar"), "OCI artifact digest mismatch")
    require(artifact.get("provenanceSha256") == sha256_file(args.artifact / "provenance.json"), "provenance digest mismatch")

    image_without_digest = intended["imageRepository"]
    require(image_without_digest.startswith(args.registry_prefix.rstrip("/") + "/"), "image is outside registry_prefix")
    require(image_without_digest.startswith("ghcr.io/"), "only GHCR is supported")
    repository = image_without_digest.removeprefix("ghcr.io/")
    github_repository = os.environ.get("GITHUB_REPOSITORY", "").lower()
    require(github_repository and repository.startswith(github_repository + "/"), "GHCR destination must be linked beneath the current deployment repository")
    actor = os.environ.get("GHCR_ACTOR", "")
    token = os.environ.get("GHCR_TOKEN", "")
    require(actor and token, "current-repository GHCR credentials are unavailable")

    with tempfile.TemporaryDirectory(prefix="olivium-oci-") as temporary:
        layout = Path(temporary)
        descriptor, manifest = load_oci_layout(args.artifact / "image.oci.tar", layout)
        require(descriptor["digest"] == manifest_digest, "OCI descriptor does not match the build artifact receipt")
        client = GhcrClient(repository, actor, token)
        for blob in (layout / "blobs" / "sha256").iterdir():
            if blob.is_file():
                client.upload_blob(blob, f"sha256:{blob.name}")
        digest_result = client.put_manifest(manifest_digest, manifest, descriptor.get("mediaType", "application/vnd.oci.image.manifest.v1+json"))
        require(digest_result == manifest_digest, "uploaded digest differs from the built artifact digest")
        tag = f"eph-{config['deploymentId']}-{os.environ.get('GITHUB_RUN_ID', 'unknown')}"
        require(client.put_manifest(tag, manifest, descriptor.get("mediaType", "application/vnd.oci.image.manifest.v1+json")) == manifest_digest, "tagged manifest digest changed")
        provenance_digest = push_provenance(client, descriptor, args.artifact / "provenance.json")

    args.output.mkdir(parents=True, exist_ok=True)
    write_json(
        args.output / "receipt.json",
        {
            "apiVersion": "olivium.dev/registry-receipt/v1",
            "serviceId": args.service_id,
            "imageRepository": image_without_digest,
            "image": f"{image_without_digest}@{manifest_digest}",
            "manifestDigest": manifest_digest,
            "artifactSha256": artifact["ociArchiveSha256"],
            "provenanceDigest": provenance_digest,
            "sourceArchiveSha256": artifact["sourceArchiveSha256"],
            "buildInputSha256": artifact["buildInputSha256"],
            "runId": os.environ.get("GITHUB_RUN_ID", ""),
            "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        },
        0o644,
    )
    print(json.dumps({"ok": True, "serviceId": args.service_id, "manifestDigest": manifest_digest}))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service-id", required=True)
    parser.add_argument("--contracts", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--registry-prefix", required=True)
    parser.add_argument("--expected-service-count", type=int, default=24)
    return parser


def main() -> int:
    try:
        command_push(build_parser().parse_args())
        return 0
    except (ContractError, OSError) as exc:
        print(f"source-free registry push failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
