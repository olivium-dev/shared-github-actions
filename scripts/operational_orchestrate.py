#!/usr/bin/env python3
"""Provision, deploy, validate, and activate one operational Jeeb lease."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from common import ContractError, canonical_sha256, require, write_github_output, write_json
from manager_client import ManagerClient
from operational_seed import SeedContractError, seed_counts, seed_digest, validate_seed_data


IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9./_-]+@sha256:[0-9a-f]{64}$")
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


class Heartbeat:
    def __init__(self, client: ManagerClient, lease: dict[str, Any], interval_seconds: int = 45) -> None:
        self.client = client
        self.lease = lease
        self.phase = "infrastructure_ready"
        self.interval_seconds = interval_seconds
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._error: Exception | None = None
        self._thread = threading.Thread(target=self._run, name="manager-heartbeat", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def transition(self, phase: str) -> dict[str, Any]:
        with self._lock:
            self._raise_if_failed()
            self.lease = self.client.progress(self.lease, phase)
            self.phase = phase
            return dict(self.lease)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            self._raise_if_failed()
            return dict(self.lease)

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=10)
        with self._lock:
            self._raise_if_failed()

    def _raise_if_failed(self) -> None:
        if self._error is not None:
            raise ContractError(f"manager heartbeat failed: {self._error}")

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            try:
                with self._lock:
                    self.lease = self.client.progress(self.lease, self.phase)
            except Exception as exc:
                with self._lock:
                    self._error = exc
                self._stop.set()
                return


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"invalid JSON: {path}") from exc
    require(isinstance(value, dict), f"{path.name} must contain an object")
    return value


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def protected_deployment_credentials() -> tuple[str, str, str, str]:
    ghcr_token = os.environ.get("JEEB_EPHEMERAL_GHCR_TOKEN", "")
    stage_template = os.environ.get("JEEB_EPHEMERAL_STAGE_TEMPLATE_B64", "")
    super_login_passcode = os.environ.get("JEEB_EPHEMERAL_SUPER_LOGIN_PASSCODE", "")
    openai_api_key = os.environ.get("JEEB_EPHEMERAL_OPENAI_API_KEY", "")
    require(len(ghcr_token) >= 20 and len(stage_template) >= 100, "protected deployment secrets are unavailable")
    require(
        6 <= len(super_login_passcode) <= 128
        and super_login_passcode == super_login_passcode.strip()
        and super_login_passcode.isprintable(),
        "protected ephemeral super-login passcode is unavailable",
    )
    require(
        20 <= len(openai_api_key) <= 4096
        and openai_api_key == openai_api_key.strip()
        and openai_api_key.isprintable()
        and not any(character.isspace() for character in openai_api_key),
        "protected ephemeral OpenAI credential is unavailable",
    )
    return ghcr_token, stage_template, super_login_passcode, openai_api_key


def validate_inputs(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], int, str]:
    config = load_json(args.config)
    catalog = load_json(args.catalog)
    require(config.get("apiVersion") == "olivium.dev/jeeb-operational-ephemeral/v1", "unsupported operational config")
    services = config.get("services")
    require(isinstance(services, list) and len(services) == 24, "operational config must contain 24 services")
    ids = [item.get("id") for item in services]
    require(len(set(ids)) == 24, "operational config contains duplicate service IDs")
    require(set(ids) == {item.get("id") for item in catalog.get("services", [])}, "operational service set does not match catalog")
    for item in services:
        require(isinstance(item, dict), "service entry must be an object")
        require(IMAGE_RE.fullmatch(str(item.get("image", ""))) is not None, f"{item.get('id')} image is not digest-pinned")
        require(FULL_SHA.fullmatch(str(item.get("commit", ""))) is not None, f"{item.get('id')} commit is not immutable")
        require(item.get("ref") in {"main", "master"} or isinstance(item.get("ref"), str), f"{item.get('id')} branch is invalid")
    web_applications = config.get("webApplications")
    require(isinstance(web_applications, list) and len(web_applications) == 1, "config must contain one web application")
    web_application = web_applications[0]
    require(isinstance(web_application, dict), "web application must be an object")
    require(web_application.get("id") == "jeeb-cms", "web application must be jeeb-cms")
    require(web_application.get("repository") == "olivium-dev/jeeb-cms", "jeeb-cms repository is invalid")
    require(IMAGE_RE.fullmatch(str(web_application.get("image", ""))) is not None, "jeeb-cms image is not digest-pinned")
    require(FULL_SHA.fullmatch(str(web_application.get("commit", ""))) is not None, "jeeb-cms commit is not immutable")
    require(web_application.get("internalPort") == 8080, "jeeb-cms internal port must be 8080")
    require(web_application.get("hostPort") == 10080, "jeeb-cms host port must be 10080")
    require(web_application.get("healthPath") == "/health", "jeeb-cms health path must be /health")
    try:
        validate_seed_data(config.get("seedData"))
    except SeedContractError as exc:
        raise ContractError(str(exc)) from exc
    ttl = args.ttl_minutes if args.ttl_minutes is not None else config["defaults"]["ttlMinutes"]
    zone = args.zone or config["defaults"]["zone"]
    require(isinstance(ttl, int) and 5 <= ttl <= 240, "TTL must be 5..240 minutes")
    require(zone in {"fds-8.space", "fds-7.space"}, "zone is not allowed")
    return config, catalog, ttl, zone


def deployment_lock(config: dict[str, Any], catalog: dict[str, Any], deployment_id: str) -> tuple[dict[str, Any], str]:
    catalog_hash = hashlib.sha256(canonical(catalog)).hexdigest()
    value: dict[str, Any] = {
        "apiVersion": "olivium.dev/deployment-lock/v2",
        "kind": "JeebDeploymentLock",
        "deploymentId": deployment_id,
        "catalog": {
            "profile": catalog["metadata"]["profile"],
            "version": catalog["metadata"]["version"],
            "fileSha256": catalog_hash,
        },
        "validation": {
            "vmProfile": "jeeb-swarm-v1",
            "serviceCount": 24,
        },
        "seedData": {
            "sha256": seed_digest(config["seedData"]),
            **seed_counts(config["seedData"]),
        },
        "services": [
            {
                "serviceId": item["id"],
                "repository": item["repository"],
                "commit": item["commit"],
                "ref": item["ref"],
                "image": {
                    "reference": item["image"],
                    "digest": item["image"].rsplit("@", 1)[1],
                },
            }
            for item in sorted(config["services"], key=lambda row: row["id"])
        ],
        "webApplications": [
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
        ],
    }
    lock_hash = hashlib.sha256(canonical(value)).hexdigest()
    value["lockSha256"] = lock_hash
    return value, lock_hash


def generate_key(directory: Path, deployment_id: str) -> tuple[Path, str]:
    private_key = directory / "id_ed25519"
    result = subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", deployment_id, "-f", str(private_key)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(result.returncode == 0, "could not generate lease SSH key")
    os.chmod(private_key, 0o600)
    public_key = private_key.with_suffix(".pub").read_text(encoding="ascii").strip()
    require(public_key.startswith("ssh-ed25519 "), "generated SSH public key is invalid")
    return private_key, public_key


def download_cloudflared(directory: Path, version: str, expected_sha256: str) -> Path:
    require(re.fullmatch(r"20[0-9]{2}\.[0-9]+\.[0-9]+", version) is not None, "invalid cloudflared version")
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None, "invalid cloudflared digest")
    url = f"https://github.com/cloudflare/cloudflared/releases/download/{version}/cloudflared-linux-amd64"
    try:
        with urllib.request.urlopen(url, timeout=90, context=ssl.create_default_context()) as response:
            payload = response.read(100_000_001)
    except urllib.error.URLError as exc:
        raise ContractError(f"cloudflared download failed: {exc}") from exc
    require(len(payload) <= 100_000_000, "cloudflared download is too large")
    require(hashlib.sha256(payload).hexdigest() == expected_sha256, "cloudflared digest mismatch")
    path = directory / "cloudflared"
    path.write_bytes(payload)
    os.chmod(path, 0o500)
    return path


def known_hosts_file(lease: dict[str, Any], directory: Path) -> Path:
    hostname = lease.get("sshHostname")
    line = lease.get("sshKnownHostsLine")
    require(isinstance(hostname, str) and hostname.startswith("ssh-eph-"), "manager returned invalid SSH hostname")
    require(isinstance(line, str) and line.startswith(hostname + " ssh-ed25519 "), "manager returned invalid known-host line")
    path = directory / "known_hosts"
    path.write_text(line + "\n", encoding="ascii")
    os.chmod(path, 0o600)
    return path


def ssh_options(cloudflared: Path, private_key: Path, known_hosts: Path) -> list[str]:
    proxy = f"{shlex.quote(str(cloudflared))} access ssh --hostname %h"
    return [
        "-o",
        f"ProxyCommand={proxy}",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "PubkeyAuthentication=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "HostKeyAlgorithms=ssh-ed25519",
        "-o",
        "ConnectTimeout=30",
        "-i",
        str(private_key),
    ]


def transport(
    argv: list[str],
    *,
    stdin: bytes | None = None,
    timeout: int = 1800,
) -> str:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"}
    }
    environment["GODEBUG"] = "netdns=go"
    result = subprocess.run(
        argv,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace")[-3000:]
        raise ContractError(f"Cloudflare SSH operation failed ({result.returncode}): {detail}")
    return result.stdout.decode(errors="strict").strip()


def upload_runtime(
    args: argparse.Namespace,
    lease: dict[str, Any],
    directory: Path,
    private_key: Path,
    known_hosts: Path,
    cloudflared: Path,
    lock_path: Path,
    template_path: Path,
) -> None:
    hostname = lease["sshHostname"]
    destination = f"ec2-user@{hostname}"
    options = ssh_options(cloudflared, private_key, known_hosts)
    remote_root = f"/tmp/jeeb-operational-{lease['leaseId']}"
    transport(["ssh", *options, destination, f"install -d -m 0700 {shlex.quote(remote_root)}"])
    files = {
        args.config: "config.json",
        args.catalog: "catalog.json",
        args.postgres_schema: "postgres-schema.sql.gz",
        args.health_probe: "http-health-probe",
        args.guest_script: "operational_guest.py",
        args.seed_helper: "operational_seed.py",
        lock_path: "deployment-lock.json",
        template_path: "stage-template.b64",
    }
    remote_files: list[str] = []
    for source, name in files.items():
        payload = source.read_bytes()
        remote_path = f"{remote_root}/{name}"
        transport(
            [
                "ssh",
                *options,
                destination,
                f"umask 077; dd of={shlex.quote(remote_path)} status=none",
            ],
            stdin=payload,
            timeout=900,
        )
        remote_digest = transport(
            [
                "ssh",
                *options,
                destination,
                f"sha256sum -- {shlex.quote(remote_path)}",
            ]
        ).split()[0]
        require(
            remote_digest == hashlib.sha256(payload).hexdigest(),
            f"remote runtime upload digest mismatch: {name}",
        )
        remote_files.append(remote_path)
    quoted_files = " ".join(shlex.quote(path) for path in remote_files)
    install_command = (
        f"sudo chown root:root {shlex.quote(remote_root)} {quoted_files} && "
        f"sudo chmod 0700 {shlex.quote(remote_root)} && "
        f"sudo chmod 0600 {quoted_files} && "
        f"sudo chmod 0500 {shlex.quote(remote_root + '/operational_guest.py')} "
        f"{shlex.quote(remote_root + '/http-health-probe')}"
    )
    transport(["ssh", *options, destination, install_command])
    ghcr_token, _, super_login_passcode, openai_api_key = protected_deployment_credentials()
    credentials = canonical(
        {
            "ghcrActor": os.environ.get("GITHUB_ACTOR", ""),
            "ghcrToken": ghcr_token,
            "superLoginPasscode": super_login_passcode,
            "openAiApiKey": openai_api_key,
        }
    )
    command = (
        f"sudo python3 {shlex.quote(remote_root + '/operational_guest.py')} "
        f"--config {shlex.quote(remote_root + '/config.json')} "
        f"--catalog {shlex.quote(remote_root + '/catalog.json')} "
        f"--deployment-lock {shlex.quote(remote_root + '/deployment-lock.json')} "
        f"--stage-template {shlex.quote(remote_root + '/stage-template.b64')} "
        f"--postgres-schema {shlex.quote(remote_root + '/postgres-schema.sql.gz')} "
        f"--health-probe {shlex.quote(remote_root + '/http-health-probe')} "
        f"--lease-id {shlex.quote(lease['leaseId'])} "
        f"--private-ip {shlex.quote(lease['privateIp'])} "
        f"--deployment-id {shlex.quote(lease['deploymentId'])} "
        f"--lock-sha256 {shlex.quote(lease['deploymentLockHash'])} "
        f"--zone {shlex.quote(lease['zone'])}"
    )
    output = transport(["ssh", *options, destination, command], stdin=credentials, timeout=5400)
    require(any(json.loads(line).get("ok") is True for line in output.splitlines() if line.startswith("{")), "guest deploy returned no success receipt")


def wait_public(url: str, timeout: int = 300) -> None:
    deadline = time.monotonic() + timeout
    request = urllib.request.Request(url, headers={"User-Agent": "olivium-jeeb-operational/1"})
    last = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(request, timeout=20, context=ssl.create_default_context()) as response:
                require(200 <= response.status < 300, "public endpoint returned non-success")
                response.read(4096)
                return
        except (urllib.error.URLError, ContractError) as exc:
            last = str(exc)
            time.sleep(5)
    raise ContractError(f"public endpoint did not become ready: {last}")


def wait_public_cms(base_url: str, timeout: int = 300) -> None:
    required_paths = ("/health", "/login", "/mf/config/remoteEntry.js")
    for path in required_paths:
        wait_public(f"{base_url}{path}", timeout=timeout)


def wait_public_seed_roster(base_url: str, seed_data: dict[str, Any], timeout: int = 300) -> None:
    deadline = time.monotonic() + timeout
    expected = {user["id"]: user["username"] for user in seed_data["users"]}
    request = urllib.request.Request(
        f"{base_url}/gateway/api/User/super-login/users",
        headers={"Accept": "application/json", "User-Agent": "olivium-jeeb-operational/1"},
    )
    last = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(request, timeout=20, context=ssl.create_default_context()) as response:
                require(200 <= response.status < 300, "public seed roster returned non-success")
                payload = json.loads(response.read())
                rows = payload.get("users") if isinstance(payload, dict) else None
                require(isinstance(rows, list), "public seed roster is invalid")
                actual = {
                    str(row.get("userId")): row.get("name")
                    for row in rows
                    if isinstance(row, dict)
                }
                require(
                    all(actual.get(user_id) == username for user_id, username in expected.items()),
                    "public seed roster is missing configured users",
                )
                return
        except (urllib.error.URLError, json.JSONDecodeError, ContractError) as exc:
            last = str(exc)
            time.sleep(5)
    raise ContractError(f"public seed roster did not become ready: {last}")


def save_state(path: Path, lease: dict[str, Any] | None, lock_hash: str) -> None:
    write_json(
        path,
        {
            "apiVersion": "olivium.dev/workflow-lease-state/v1",
            "leaseId": lease.get("leaseId") if lease else None,
            "deploymentId": lease.get("deploymentId") if lease else None,
            "deploymentLockHash": lock_hash,
            "state": lease.get("state") if lease else "not_allocated",
            "stateVersion": lease.get("stateVersion") if lease else None,
            "jobId": lease.get("jobId") if lease else None,
            "updatedAt": datetime.now(timezone.utc).isoformat(),
        },
        0o600,
    )


def run_deployment(args: argparse.Namespace) -> None:
    config, catalog, ttl, zone = validate_inputs(args)
    _, stage_template, _, _ = protected_deployment_credentials()
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    require(repository == "olivium-dev/jeeb-ephemeral-deploy" and run_id.isdigit(), "unexpected GitHub caller")
    deployment_id = f"jeeb-gh-{run_id}-{run_attempt}"
    lock, lock_hash = deployment_lock(config, catalog, deployment_id)
    client = ManagerClient(
        base_url=args.manager_url,
        audience=args.manager_audience,
        expected_workflow_ref=args.expected_job_workflow_ref,
        expected_workflow_sha=args.expected_job_workflow_sha,
        expected_environment=args.environment,
    )
    lease: dict[str, Any] | None = None
    heartbeat: Heartbeat | None = None
    save_state(args.state, None, lock_hash)
    with tempfile.TemporaryDirectory(prefix="jeeb-operational-") as temporary_name:
        temporary = Path(temporary_name)
        private_key, public_key = generate_key(temporary, deployment_id)
        cloudflared = download_cloudflared(temporary, args.cloudflared_version, args.cloudflared_sha256)
        lock_path = temporary / "deployment-lock.json"
        lock_path.write_bytes(canonical(lock) + b"\n")
        os.chmod(lock_path, 0o600)
        template_path = temporary / "stage-template.b64"
        template_path.write_text(stage_template, encoding="ascii")
        os.chmod(template_path, 0o600)
        try:
            body = {
                "deploymentId": deployment_id,
                "deploymentLockHash": lock_hash,
                "profile": "jeeb-swarm-v1",
                "ttlMinutes": ttl,
                "zone": zone,
                "activationDeadline": (
                    datetime.now(timezone.utc) + timedelta(minutes=config["defaults"]["activationDeadlineMinutes"])
                ).isoformat(),
                "sshPublicKey": public_key,
            }
            idempotency = "operational:" + hashlib.sha256(
                f"{repository}:{run_id}:{run_attempt}:{lock_hash}".encode()
            ).hexdigest()
            created = client.create(body, idempotency)
            lease_id = created.get("leaseId")
            job_id = created.get("jobId")
            require(isinstance(lease_id, str) and isinstance(job_id, str), "manager create response is incomplete")
            lease = {
                "leaseId": lease_id,
                "jobId": job_id,
                "deploymentId": deployment_id,
                "deploymentLockHash": lock_hash,
                "state": created.get("state"),
                "stateVersion": created.get("stateVersion"),
            }
            save_state(args.state, lease, lock_hash)
            client.wait_job(job_id, 2400)
            lease = client.lease(lease_id)
            require(lease.get("state") == "infrastructure_ready", "manager did not provision a deferred Jeeb lease")
            save_state(args.state, lease, lock_hash)
            heartbeat = Heartbeat(client, lease)
            heartbeat.start()
            lease = heartbeat.transition("deploying")
            save_state(args.state, lease, lock_hash)
            known_hosts = known_hosts_file(lease, temporary)
            upload_runtime(
                args,
                lease,
                temporary,
                private_key,
                known_hosts,
                cloudflared,
                lock_path,
                template_path,
            )
            lease = heartbeat.transition("validating")
            save_state(args.state, lease, lock_hash)
            identity = transport(
                [
                    "ssh",
                    *ssh_options(cloudflared, private_key, known_hosts),
                    f"ec2-user@{lease['sshHostname']}",
                    "cat /etc/olivium-ephemeral-lease",
                ]
            )
            require(lease_id in identity, "Cloudflare SSH reached the wrong lease")
            public_url = f"https://{lease['httpsHostname']}"
            wait_public(f"{public_url}/health/ready")
            wait_public_cms(public_url)
            wait_public_seed_roster(public_url, config["seedData"])
            heartbeat.stop()
            heartbeat = None
            lease = client.lease(lease_id)
            activation = client.activate(lease)
            activation_job = activation.get("jobId")
            require(isinstance(activation_job, str), "manager activation response is incomplete")
            client.wait_job(activation_job, 1800)
            lease = client.lease(lease_id)
            require(lease.get("state") == "active", "manager did not activate the validated lease")
            save_state(args.state, lease, lock_hash)
            wait_public(f"{public_url}/health/ready")
            wait_public_cms(public_url)
            wait_public_seed_roster(public_url, config["seedData"])
            counts = seed_counts(config["seedData"])
            if args.github_output:
                write_github_output(
                    {
                        "lease_id": lease_id,
                        "https_url": f"https://{lease['httpsHostname']}",
                        "ssh_hostname": lease["sshHostname"],
                        "vmid": str(lease["vmid"]),
                        "private_ip": lease["privateIp"],
                        "expires_at": lease["expiresAt"],
                        "deployment_lock_sha256": lock_hash,
                        "seed_user_count": str(counts["users"]),
                        "seed_regular_user_count": str(counts["regularUsers"]),
                        "seed_jeeber_count": str(counts["jeebers"]),
                        "seed_admin_count": str(counts["admins"]),
                        "seed_wallet_count": str(counts["wallets"]),
                    }
                )
            print(
                json.dumps(
                    {
                        "ok": True,
                        "leaseId": lease_id,
                        "httpsUrl": f"https://{lease['httpsHostname']}",
                        "sshHostname": lease["sshHostname"],
                        "serviceCount": 24,
                        "webApplicationCount": 1,
                        "seedData": counts,
                    },
                    sort_keys=True,
                )
            )
        except BaseException:
            if heartbeat is not None:
                try:
                    heartbeat.stop()
                    lease = heartbeat.snapshot()
                except Exception:
                    pass
            if lease is not None:
                try:
                    latest = client.lease(lease["leaseId"])
                    if latest.get("state") in {
                        "queued",
                        "provisioning",
                        "infrastructure_ready",
                        "deploying",
                        "validating",
                        "cleanup_pending",
                    }:
                        aborted = client.abort(latest)
                        if isinstance(aborted.get("jobId"), str):
                            client.wait_job(aborted["jobId"], 1200)
                        lease = client.lease(lease["leaseId"])
                except Exception:
                    pass
                save_state(args.state, lease, lock_hash)
            raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--postgres-schema", type=Path, required=True)
    parser.add_argument("--health-probe", type=Path, required=True)
    parser.add_argument("--guest-script", type=Path, required=True)
    parser.add_argument("--seed-helper", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--ttl-minutes", type=int)
    parser.add_argument("--zone")
    parser.add_argument("--manager-url", required=True)
    parser.add_argument("--manager-audience", required=True)
    parser.add_argument("--expected-job-workflow-ref", required=True)
    parser.add_argument("--expected-job-workflow-sha", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--cloudflared-version", required=True)
    parser.add_argument("--cloudflared-sha256", required=True)
    parser.add_argument("--github-output", action="store_true")
    return parser


def main() -> int:
    try:
        run_deployment(build_parser().parse_args())
        return 0
    except (ContractError, OSError, subprocess.SubprocessError) as exc:
        print(f"operational deployment failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
