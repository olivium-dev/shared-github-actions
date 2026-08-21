#!/usr/bin/env python3
"""Provision, deploy, validate, and activate one deferred Jeeb lease."""

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

from common import ContractError, canonical_sha256, read_json, redact, require, sha256_file, write_github_output, write_json
from contracts import validate_build_intent, validate_config, validate_final_lock
from manager_client import ManagerClient


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

    def access_grant(self, nonce: str) -> dict[str, Any]:
        with self._lock:
            self._raise_if_failed()
            grant = self.client.access_grant(self.lease, nonce)
            self.lease["stateVersion"] = grant["stateVersion"]
            return grant

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
            except Exception as exc:  # surfaced synchronously by snapshot/stop
                with self._lock:
                    self._error = exc
                self._stop.set()
                return


def client_from_args(args: argparse.Namespace) -> ManagerClient:
    return ManagerClient(
        base_url=args.manager_url,
        audience=args.manager_audience,
        expected_workflow_ref=args.expected_job_workflow_ref,
        expected_workflow_sha=args.expected_job_workflow_sha,
        expected_environment=args.environment,
        static_oidc_env=args.static_oidc_env,
        allow_http_for_tests=args.allow_http_for_tests,
    )


def load_contracts(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    config = validate_config(read_json(args.contracts / "config.json"), args.expected_service_count)
    intent = validate_build_intent(read_json(args.contracts / "build-intent.json"), config)
    lock = validate_final_lock(read_json(args.final_lock / "deployment-lock.json"), config, intent)
    lock_hash = canonical_sha256(lock)
    bundle_receipt = read_json(args.bundle / "bundle.json")
    require(isinstance(bundle_receipt, dict) and bundle_receipt.get("lockSha256") == lock_hash, "runtime bundle does not contain the finalized deployment lock")
    bundle = args.bundle / "runtime-bundle.tar.gz"
    require(bundle.is_file() and bundle_receipt.get("bundleSha256") == sha256_file(bundle), "runtime bundle digest mismatch")
    return config, intent, lock, lock_hash


def generate_key(directory: Path, deployment_id: str) -> tuple[Path, str]:
    private_key = directory / "id_ed25519"
    completed = subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"olivium-ephemeral-{deployment_id}", "-f", str(private_key)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(completed.returncode == 0, "could not generate ephemeral Ed25519 key")
    os.chmod(private_key, 0o600)
    public_key = private_key.with_suffix(".pub").read_text(encoding="ascii").strip()
    require(public_key.startswith("ssh-ed25519 ") and "\n" not in public_key, "generated SSH public key is invalid")
    return private_key, public_key


def download_cloudflared(version: str, expected_sha256: str, destination: Path) -> Path:
    require(re.fullmatch(r"20[0-9]{2}\.[0-9]+\.[0-9]+", version) is not None, "cloudflared version is invalid")
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None, "cloudflared SHA-256 is invalid")
    url = f"https://github.com/cloudflare/cloudflared/releases/download/{version}/cloudflared-linux-amd64"
    request = urllib.request.Request(url, headers={"User-Agent": "olivium-jeeb-ephemeral/1"})
    try:
        with urllib.request.urlopen(request, timeout=60, context=ssl.create_default_context()) as response:
            require(response.geturl().startswith("https://"), "cloudflared download left HTTPS")
            payload = response.read(100_000_001)
    except urllib.error.URLError as exc:
        raise ContractError(f"cloudflared download failed: {exc}") from exc
    require(len(payload) <= 100_000_000, "cloudflared download exceeds the size limit")
    require(hashlib.sha256(payload).hexdigest() == expected_sha256, "cloudflared SHA-256 mismatch")
    binary = destination / "cloudflared"
    binary.write_bytes(payload)
    os.chmod(binary, 0o500)
    return binary


def verify_known_hosts(lease: dict[str, Any], directory: Path) -> Path:
    hostname = lease.get("sshHostname")
    line = lease.get("sshKnownHostsLine")
    fingerprint = lease.get("sshHostKeyFingerprint")
    require(isinstance(hostname, str) and re.fullmatch(r"ssh-eph-[a-z0-9-]+\.(?:fds-8|fds-7)\.space", hostname), "manager returned an invalid SSH hostname")
    require(isinstance(line, str) and line.startswith(f"{hostname} ssh-ed25519 ") and "\n" not in line, "manager returned an invalid pinned SSH host key")
    require(isinstance(fingerprint, str) and fingerprint.startswith("SHA256:"), "manager returned an invalid SSH host fingerprint")
    known_hosts = directory / "known_hosts"
    known_hosts.write_text(line + "\n", encoding="ascii")
    os.chmod(known_hosts, 0o600)
    completed = subprocess.run(
        ["ssh-keygen", "-lf", str(known_hosts), "-E", "sha256"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    require(completed.returncode == 0 and fingerprint in completed.stdout, "manager SSH host-key fingerprint does not match known_hosts")
    return known_hosts


def ssh_options(cloudflared: Path, hostname: str, private_key: Path, known_hosts: Path) -> list[str]:
    proxy = f"{shlex.quote(str(cloudflared))} access ssh --hostname {shlex.quote(hostname)}"
    return [
        "-o", f"ProxyCommand={proxy}",
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "PubkeyAuthentication=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "HostKeyAlgorithms=ssh-ed25519",
        "-o", "ConnectTimeout=20",
        "-i", str(private_key),
    ]


def transport_environment(access_grant: dict[str, Any]) -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if key in {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"}}
    environment["TUNNEL_SERVICE_TOKEN_ID"] = access_grant["clientId"]
    environment["TUNNEL_SERVICE_TOKEN_SECRET"] = access_grant["clientSecret"]
    return environment


def run_transport(
    argv: list[str],
    *,
    environment: dict[str, str],
    stdin: bytes | None = None,
    timeout: int = 1200,
) -> str:
    completed = subprocess.run(
        argv,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        detail = redact(completed.stderr.decode("utf-8", errors="replace"))
        raise ContractError(f"pinned Cloudflare SSH operation failed with exit code {completed.returncode}: {detail}")
    return completed.stdout.decode("utf-8", errors="strict").strip()


def deploy_over_ssh(
    args: argparse.Namespace,
    lease: dict[str, Any],
    private_key: Path,
    known_hosts: Path,
    cloudflared: Path,
    access_grant: dict[str, Any],
    lock_hash: str,
) -> None:
    hostname = lease["sshHostname"]
    destination = f"{args.ssh_user}@{hostname}"
    options = ssh_options(cloudflared, hostname, private_key, known_hosts)
    environment = transport_environment(access_grant)
    remote_archive = f"/tmp/olivium-runtime-{lease['leaseId']}.tar.gz"
    run_transport(
        ["scp", *options, str(args.bundle / "runtime-bundle.tar.gz"), f"{destination}:{remote_archive}"],
        environment=environment,
        timeout=900,
    )
    remote_root = f"/var/lib/olivium-ephemeral/runtime/{lease['leaseId']}"
    prepare = (
        f"sudo install -d -m 0700 {shlex.quote(remote_root)} && "
        f"sudo tar -xzf {shlex.quote(remote_archive)} -C {shlex.quote(remote_root)} --no-same-owner --no-same-permissions && "
        f"sudo chmod 0555 {shlex.quote(remote_root + '/olivium-http-probe')}"
    )
    run_transport(["ssh", *options, destination, prepare], environment=environment)
    try:
        runtime_secrets = json.loads(os.environ.get("JEEB_RUNTIME_SECRETS_JSON", ""))
    except json.JSONDecodeError as exc:
        raise ContractError("JEEB_RUNTIME_SECRETS_JSON is invalid") from exc
    ghcr_token = os.environ.get("GHCR_TOKEN", "")
    ghcr_actor = os.environ.get("GHCR_ACTOR", "")
    require(ghcr_token and ghcr_actor, "current-repository GHCR credentials are unavailable")
    credential_envelope = json.dumps(
        {"ghcrActor": ghcr_actor, "ghcrToken": ghcr_token, "runtimeSecrets": runtime_secrets},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    deploy_command = (
        f"sudo python3 {shlex.quote(remote_root + '/remote_runtime.py')} deploy "
        f"--bundle-dir {shlex.quote(remote_root)} --lease-id {shlex.quote(lease['leaseId'])} "
        f"--deployment-lock-sha256 {lock_hash}"
    )
    output = run_transport(
        ["ssh", *options, destination, deploy_command],
        environment=environment,
        stdin=credential_envelope,
        timeout=3600,
    )
    require(any(json.loads(line).get("ok") is True for line in output.splitlines() if line.startswith("{")), "remote deploy did not return a success receipt")
    validate_command = (
        f"sudo python3 {shlex.quote(remote_root + '/remote_runtime.py')} validate "
        f"--bundle-dir {shlex.quote(remote_root)} --lease-id {shlex.quote(lease['leaseId'])} "
        f"--deployment-lock-sha256 {lock_hash}"
    )
    output = run_transport(["ssh", *options, destination, validate_command], environment=environment, timeout=1200)
    require(any(json.loads(line).get("validated") is True for line in output.splitlines() if line.startswith("{")), "remote validation did not return a success receipt")
    identity = run_transport(
        ["ssh", *options, destination, "cat /etc/olivium-ephemeral-lease"],
        environment=environment,
    )
    require(lease["leaseId"] in identity, "Cloudflare SSH reached the wrong lease")


def validate_public_https(lease: dict[str, Any], deployment_id: str) -> None:
    hostname = lease.get("httpsHostname")
    require(isinstance(hostname, str) and re.fullmatch(r"eph-[a-z0-9-]+\.(?:fds-8|fds-7)\.space", hostname), "manager returned an invalid HTTPS hostname")
    request = urllib.request.Request(
        f"https://{hostname}/.well-known/olivium-lease",
        headers={"User-Agent": "olivium-jeeb-ephemeral-validation/1", "Cache-Control": "no-cache"},
    )
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(request, timeout=15, context=ssl.create_default_context()) as response:
                payload = json.load(response)
            if payload.get("leaseId") == lease["leaseId"] and payload.get("deploymentId") == deployment_id:
                return
        except (urllib.error.URLError, json.JSONDecodeError):
            time.sleep(5)
    raise ContractError("public Cloudflare HTTPS validation did not reach the expected lease")


def save_state(path: Path, lease: dict[str, Any] | None, lock_hash: str, status: str) -> None:
    write_json(
        path,
        {
            "apiVersion": "olivium.dev/workflow-lease-state/v1",
            "leaseId": lease.get("leaseId") if lease else None,
            "deploymentId": lease.get("deploymentId") if lease else None,
            "deploymentLockHash": lock_hash,
            "state": lease.get("state") if lease else status,
            "stateVersion": lease.get("stateVersion") if lease else None,
            "jobId": lease.get("jobId") if lease else None,
            "updatedAt": datetime.now(timezone.utc).isoformat(),
        },
        0o600,
    )


def run(args: argparse.Namespace) -> None:
    config, _, _, lock_hash = load_contracts(args)
    client = client_from_args(args)
    lease: dict[str, Any] | None = None
    heartbeat: Heartbeat | None = None
    save_state(args.state, None, lock_hash, "not_allocated")
    with tempfile.TemporaryDirectory(prefix="olivium-lease-") as temporary:
        private_key, public_key = generate_key(Path(temporary), config["deploymentId"])
        try:
            deadline = datetime.now(timezone.utc) + timedelta(minutes=config["activationDeadlineMinutes"])
            body = {
                "deploymentId": config["deploymentId"],
                "deploymentLockHash": lock_hash,
                "profile": config["profile"],
                "ttlMinutes": config["ttlMinutes"],
                "zone": config["zone"],
                "activationDeadline": deadline.isoformat(),
                "sshPublicKey": public_key,
            }
            idempotency = "gha:" + hashlib.sha256(
                f"{os.environ.get('GITHUB_REPOSITORY')}:{os.environ.get('GITHUB_RUN_ID')}:{os.environ.get('GITHUB_RUN_ATTEMPT')}:{lock_hash}".encode()
            ).hexdigest()
            created = client.create(body, idempotency)
            lease_id = created.get("leaseId")
            job_id = created.get("jobId")
            require(isinstance(lease_id, str) and isinstance(job_id, str), "manager create response is incomplete")
            lease = {
                "leaseId": lease_id,
                "jobId": job_id,
                "deploymentId": config["deploymentId"],
                "deploymentLockHash": lock_hash,
                "state": created.get("state"),
                "stateVersion": created.get("stateVersion"),
            }
            save_state(args.state, lease, lock_hash, "queued")
            client.wait_job(job_id, args.provision_timeout_seconds)
            lease = client.lease(lease_id)
            require(lease.get("state") == "infrastructure_ready", "manager did not leave the lease deferred before activation")
            require(lease.get("deploymentLockHash") == lock_hash, "manager lease lock hash mismatch")
            save_state(args.state, lease, lock_hash, "infrastructure_ready")

            heartbeat = Heartbeat(client, lease)
            heartbeat.start()
            lease = heartbeat.transition("deploying")
            save_state(args.state, lease, lock_hash, "deploying")
            nonce = hashlib.sha256(f"{lease_id}:{lock_hash}:{time.time_ns()}".encode()).hexdigest()
            access_grant = heartbeat.access_grant(nonce)
            lease = heartbeat.snapshot()
            known_hosts = verify_known_hosts(lease, Path(temporary))
            cloudflared = download_cloudflared(args.cloudflared_version, args.cloudflared_sha256, Path(temporary))
            deploy_over_ssh(args, lease, private_key, known_hosts, cloudflared, access_grant, lock_hash)
            lease = heartbeat.transition("validating")
            save_state(args.state, lease, lock_hash, "validating")
            validate_public_https(lease, config["deploymentId"])
            heartbeat.stop()
            heartbeat = None
            lease = client.lease(lease_id)
            activation = client.activate(lease)
            activation_job = activation.get("jobId")
            require(isinstance(activation_job, str) and activation_job, "manager activation response is incomplete")
            client.wait_job(activation_job, args.activation_timeout_seconds)
            lease = client.lease(lease_id)
            require(lease.get("state") == "active", "manager did not activate the validated lease")
            save_state(args.state, lease, lock_hash, "active")
            if args.github_output:
                write_github_output(
                    {
                        "lease_id": lease_id,
                        "https_url": f"https://{lease['httpsHostname']}",
                        "ssh_hostname": lease["sshHostname"],
                        "deployment_lock_sha256": lock_hash,
                    }
                )
            print(json.dumps({"ok": True, "leaseId": lease_id, "httpsUrl": f"https://{lease['httpsHostname']}", "state": "active"}))
        except Exception:
            if heartbeat is not None:
                try:
                    heartbeat.stop()
                    lease = heartbeat.snapshot()
                except Exception:
                    pass
            if lease is not None and isinstance(lease.get("leaseId"), str):
                try:
                    latest = client.lease(lease["leaseId"])
                    if latest.get("state") in {"queued", "provisioning", "infrastructure_ready", "deploying", "validating", "cleanup_pending"}:
                        aborted = client.abort(latest)
                        abort_job = aborted.get("jobId")
                        if isinstance(abort_job, str) and abort_job:
                            client.wait_job(abort_job, args.abort_timeout_seconds)
                        lease = client.lease(lease["leaseId"])
                except Exception:
                    pass
                save_state(args.state, lease, lock_hash, "cleanup_pending")
            raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contracts", type=Path, required=True)
    parser.add_argument("--final-lock", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--manager-url", required=True)
    parser.add_argument("--manager-audience", required=True)
    parser.add_argument("--expected-job-workflow-ref", required=True)
    parser.add_argument("--expected-job-workflow-sha", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--cloudflared-version", required=True)
    parser.add_argument("--cloudflared-sha256", required=True)
    parser.add_argument("--ssh-user", default="ec2-user")
    parser.add_argument("--expected-service-count", type=int, default=24)
    parser.add_argument("--provision-timeout-seconds", type=int, default=1800)
    parser.add_argument("--activation-timeout-seconds", type=int, default=1200)
    parser.add_argument("--abort-timeout-seconds", type=int, default=1200)
    parser.add_argument("--static-oidc-env")
    parser.add_argument("--allow-http-for-tests", action="store_true")
    parser.add_argument("--github-output", action="store_true")
    return parser


def main() -> int:
    try:
        run(build_parser().parse_args())
        return 0
    except (ContractError, OSError, subprocess.SubprocessError) as exc:
        print(f"lease orchestration failed: {redact(str(exc))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
