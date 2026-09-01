#!/usr/bin/env python3
"""One-token-per-request client for the manager GitHub OIDC automation API."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from common import (
    ContractError,
    HttpRequestError,
    MANAGER_AUDIENCE,
    MANAGER_URL,
    TransientRequestError,
    canonical_sha256,
    https_url,
    oidc_token,
    read_json,
    redact,
    request_json,
    require,
    strict_keys,
    write_github_output,
    write_json,
)


TERMINAL_JOB_STATES = {"succeeded", "failed", "cancelled"}
PREACTIVE_LEASE_STATES = {"queued", "provisioning", "infrastructure_ready", "deploying", "validating", "cleanup_pending"}


def decode_jwt_payload(token: str) -> dict[str, Any]:
    parts = token.split(".")
    require(len(parts) == 3, "OIDC token is not a JWT")
    padding = "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + padding))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ContractError("OIDC token payload is invalid") from exc
    require(isinstance(payload, dict), "OIDC token payload must be an object")
    return payload


class ManagerClient:
    def __init__(
        self,
        *,
        base_url: str,
        audience: str,
        expected_workflow_ref: str,
        expected_workflow_sha: str,
        expected_environment: str,
        static_oidc_env: str | None = None,
        allow_http_for_tests: bool = False,
    ) -> None:
        self.base_url = https_url(base_url, "manager URL", allow_http=allow_http_for_tests)
        self.audience = audience
        if not allow_http_for_tests:
            require(self.base_url == MANAGER_URL, "manager URL is not the trusted Olivium manager origin")
            require(self.audience == MANAGER_AUDIENCE, "manager audience is not the trusted Olivium audience")
        self.expected_workflow_ref = expected_workflow_ref
        self.expected_workflow_sha = expected_workflow_sha
        self.expected_environment = expected_environment
        self.static_oidc_env = static_oidc_env

    def fresh_token(self, timeout_seconds: float = 20.0) -> str:
        token = oidc_token(
            self.audience,
            static_env=self.static_oidc_env,
            timeout=timeout_seconds,
        )
        claims = decode_jwt_payload(token)
        audience = claims.get("aud")
        audience_values = audience if isinstance(audience, list) else [audience]
        require(self.audience in audience_values, "OIDC token audience mismatch")
        require(claims.get("job_workflow_ref") == self.expected_workflow_ref, "OIDC job_workflow_ref mismatch")
        require(claims.get("job_workflow_sha") == self.expected_workflow_sha, "OIDC job_workflow_sha mismatch")
        require(claims.get("environment") == self.expected_environment, "OIDC environment mismatch")
        require(claims.get("repository_owner") == "olivium-dev", "OIDC repository owner mismatch")
        require(claims.get("runner_environment") == "github-hosted", "OIDC runner must be GitHub-hosted")
        require(str(claims.get("ref_protected", "")).lower() == "true", "OIDC ref_protected must be true")
        return token

    def request(self, method: str, path: str, body: Any | None = None, expected: tuple[int, ...] = (200,)) -> Any:
        require(path.startswith("/api/automation/v1/"), "manager API path is outside the automation boundary")
        attempts = 4 if method == "GET" else 1
        for attempt in range(attempts):
            try:
                payload, _ = request_json(
                    method,
                    f"{self.base_url}{path}",
                    bearer=self.fresh_token(),
                    body=body,
                    expected=expected,
                )
                require(isinstance(payload, dict), "manager response must be an object")
                return payload
            except (TimeoutError, OSError, TransientRequestError) as exc:
                if attempt + 1 == attempts:
                    raise ContractError(f"manager read failed after transient retries: {exc}") from exc
            except HttpRequestError as exc:
                if not exc.retryable or attempt + 1 == attempts:
                    raise
            time.sleep(attempt + 1)
        raise ContractError("manager read retry loop ended unexpectedly")

    def capabilities(self, zone: str) -> dict[str, Any]:
        response = self.request("GET", f"/api/automation/v1/capabilities?{urllib.parse.urlencode({'zone': zone})}")
        strict_keys(response, {"ok", "exitCode", "lines"}, "manager capability response")
        require(response.get("ok") is True, "manager capability probe returned ok=false")
        require(response.get("exitCode") == 0, "manager capability probe returned a nonzero exitCode")
        require(isinstance(response.get("lines"), list), "manager capability lines must be an array")
        for line in response["lines"]:
            require(isinstance(line, str) and len(line) <= 4096, "manager capability output is invalid")
        return response

    def create(self, body: dict[str, Any], idempotency_key: str) -> dict[str, Any]:
        token = self.fresh_token()
        payload, _ = request_json_with_headers(
            "POST",
            f"{self.base_url}/api/automation/v1/leases",
            bearer=token,
            body=body,
            headers={"Idempotency-Key": idempotency_key},
            expected=(200, 202),
        )
        require(isinstance(payload, dict), "manager create response must be an object")
        return payload

    def lease(self, lease_id: str) -> dict[str, Any]:
        return self.request("GET", f"/api/automation/v1/leases/{urllib.parse.quote(lease_id, safe='')}")

    @staticmethod
    def _remaining_timeout(deadline: float, maximum: float) -> float:
        remaining = deadline - time.monotonic()
        require(remaining > 0.05, "manager heartbeat request deadline exhausted")
        return min(maximum, remaining)

    def _request_once_before(
        self,
        method: str,
        path: str,
        *,
        deadline: float,
        body: Any | None = None,
    ) -> dict[str, Any]:
        require(path.startswith("/api/automation/v1/"), "manager API path is outside the automation boundary")
        token = self.fresh_token(timeout_seconds=self._remaining_timeout(deadline, 5.0))
        payload, _ = request_json(
            method,
            f"{self.base_url}{path}",
            bearer=token,
            body=body,
            timeout=self._remaining_timeout(deadline, 8.0),
        )
        require(isinstance(payload, dict), "manager response must be an object")
        return payload

    def lease_once_before(self, lease_id: str, deadline: float) -> dict[str, Any]:
        path = f"/api/automation/v1/leases/{urllib.parse.quote(lease_id, safe='')}"
        return self._request_once_before("GET", path, deadline=deadline)

    def job(self, job_id: str) -> dict[str, Any]:
        return self.request("GET", f"/api/automation/v1/jobs/{urllib.parse.quote(job_id, safe='')}")

    def wait_job(self, job_id: str, timeout_seconds: int = 1200) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            result = self.job(job_id)
            status = result.get("status")
            require(isinstance(status, str), "manager job status is missing")
            if status in TERMINAL_JOB_STATES:
                require(status == "succeeded", f"manager job ended as {status}: {result.get('error') or 'no detail'}")
                return result
            require(status in {"queued", "running"}, f"manager returned an unknown job status: {status}")
            time.sleep(5)
        raise ContractError(f"manager job {job_id} did not finish before timeout")

    def progress(self, lease: dict[str, Any], phase: str) -> dict[str, Any]:
        body = {
            "deploymentId": lease["deploymentId"],
            "deploymentLockHash": lease["deploymentLockHash"],
            "stateVersion": lease["stateVersion"],
            "phase": phase,
        }
        return self.request("POST", f"/api/automation/v1/leases/{urllib.parse.quote(lease['leaseId'], safe='')}/progress", body)

    def progress_once_before(self, lease: dict[str, Any], phase: str, deadline: float) -> dict[str, Any]:
        body = {
            "deploymentId": lease["deploymentId"],
            "deploymentLockHash": lease["deploymentLockHash"],
            "stateVersion": lease["stateVersion"],
            "phase": phase,
        }
        path = f"/api/automation/v1/leases/{urllib.parse.quote(lease['leaseId'], safe='')}/progress"
        return self._request_once_before("POST", path, deadline=deadline, body=body)

    def access_grant(self, lease: dict[str, Any], nonce: str) -> dict[str, Any]:
        body = {
            "deploymentId": lease["deploymentId"],
            "deploymentLockHash": lease["deploymentLockHash"],
            "stateVersion": lease["stateVersion"],
            "idempotencyNonce": nonce,
        }
        response = self.request("POST", f"/api/automation/v1/leases/{urllib.parse.quote(lease['leaseId'], safe='')}/access-grants", body)
        strict_keys(response, {"clientId", "clientSecret", "expiresAt", "stateVersion"}, "manager access grant response")
        require(
            all(isinstance(response.get(key), str) and response[key] for key in ("clientId", "clientSecret", "expiresAt")),
            "manager access grant response is incomplete",
        )
        require(isinstance(response.get("stateVersion"), int) and response["stateVersion"] >= 1, "manager access grant stateVersion is invalid")
        return response

    def activate(self, lease: dict[str, Any]) -> dict[str, Any]:
        body = {"deploymentId": lease["deploymentId"], "deploymentLockHash": lease["deploymentLockHash"]}
        return self.request("POST", f"/api/automation/v1/leases/{urllib.parse.quote(lease['leaseId'], safe='')}/activate", body, (200, 202))

    def abort(self, lease: dict[str, Any]) -> dict[str, Any]:
        body = {
            "deploymentId": lease["deploymentId"],
            "deploymentLockHash": lease["deploymentLockHash"],
            "stateVersion": lease["stateVersion"],
            "expectedState": "pre-active",
        }
        return self.request("POST", f"/api/automation/v1/leases/{urllib.parse.quote(lease['leaseId'], safe='')}/abort", body, (200, 202))


def request_json_with_headers(
    method: str,
    url: str,
    *,
    bearer: str,
    body: Any,
    headers: dict[str, str],
    expected: tuple[int, ...],
) -> tuple[Any, dict[str, str]]:
    import ssl
    import urllib.error
    import urllib.request

    request_headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {bearer}",
        "Content-Type": "application/json",
        "User-Agent": "olivium-jeeb-ephemeral/1",
        **headers,
    }
    request = urllib.request.Request(url, data=json.dumps(body, sort_keys=True, separators=(",", ":")).encode(), headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30, context=ssl.create_default_context()) as response:
            raw = response.read()
            status = response.status
            response_headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        detail = exc.read(16_384).decode("utf-8", errors="replace")
        raise ContractError(f"manager returned HTTP {exc.code}: {redact(detail[:1024])}") from exc
    require(status in expected, f"manager returned unexpected HTTP {status}")
    try:
        return json.loads(raw), response_headers
    except json.JSONDecodeError as exc:
        raise ContractError("manager returned invalid JSON") from exc


def client_from_args(args: argparse.Namespace) -> ManagerClient:
    return ManagerClient(
        base_url=args.manager_url,
        audience=args.audience,
        expected_workflow_ref=args.expected_job_workflow_ref,
        expected_workflow_sha=args.expected_job_workflow_sha,
        expected_environment=args.environment,
        static_oidc_env=args.static_oidc_env,
        allow_http_for_tests=args.allow_http_for_tests,
    )


def command_capabilities(args: argparse.Namespace) -> None:
    contract = read_json(args.contract)
    require(isinstance(contract, dict) and contract.get("apiVersion") == "olivium.dev/capability-contract/v1", "capability contract is invalid")
    client = client_from_args(args)
    response = client.capabilities(args.zone)
    args.output.mkdir(parents=True, exist_ok=True)
    write_json(
        args.output / "capability-result.json",
        {
            "apiVersion": "olivium.dev/capability-result/v1",
            "ok": True,
            "zone": args.zone,
            "managerUrl": client.base_url,
            "workflowRef": args.expected_job_workflow_ref,
            "workflowSha": args.expected_job_workflow_sha,
            "environment": args.environment,
            "lineCount": len(response["lines"]),
        },
        0o644,
    )
    if args.github_output:
        write_github_output({"capability_ok": "true"})
    print(json.dumps({"ok": True, "zone": args.zone, "lineCount": len(response["lines"])}))


def command_abort_if_needed(args: argparse.Namespace) -> None:
    if not args.state.is_file():
        print(json.dumps({"ok": True, "action": "none", "reason": "no-state"}))
        return
    state = read_json(args.state)
    lease_id = state.get("leaseId") if isinstance(state, dict) else None
    if not isinstance(lease_id, str) or not lease_id:
        print(json.dumps({"ok": True, "action": "none", "reason": "no-lease"}))
        return
    client = client_from_args(args)
    lease = client.lease(lease_id)
    if lease.get("state") not in PREACTIVE_LEASE_STATES:
        print(json.dumps({"ok": True, "action": "none", "state": lease.get("state")}))
        return
    result = client.abort(lease)
    job_id = result.get("jobId")
    if isinstance(job_id, str) and job_id:
        client.wait_job(job_id, args.timeout_seconds)
    final = client.lease(lease_id)
    require(final.get("state") in {"cleanup_pending", "deleted"}, "manager did not accept pre-active abort")
    print(json.dumps({"ok": True, "action": "abort", "state": final.get("state")}))


def add_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--manager-url", required=True)
    parser.add_argument("--audience", required=True)
    parser.add_argument("--expected-job-workflow-ref", required=True)
    parser.add_argument("--expected-job-workflow-sha", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--static-oidc-env")
    parser.add_argument("--allow-http-for-tests", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    capability = subparsers.add_parser("capabilities")
    add_identity_arguments(capability)
    capability.add_argument("--contract", type=Path, required=True)
    capability.add_argument("--zone", required=True)
    capability.add_argument("--output", type=Path, required=True)
    capability.add_argument("--github-output", action="store_true")
    capability.set_defaults(handler=command_capabilities)

    abort = subparsers.add_parser("abort-if-needed")
    add_identity_arguments(abort)
    abort.add_argument("--state", type=Path, required=True)
    abort.add_argument("--timeout-seconds", type=int, default=1200)
    abort.set_defaults(handler=command_abort_if_needed)
    return parser


def main() -> int:
    try:
        args = build_parser().parse_args()
        args.handler(args)
        return 0
    except ContractError as exc:
        print(f"manager contract failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
