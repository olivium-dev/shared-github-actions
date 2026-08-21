from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from helpers import fake_jwt

from common import write_json
from manager_client import ManagerClient, command_capabilities
from orchestrate import transport_environment


AUDIENCE = "olivium-ephemeral-manager"
WORKFLOW_REF = "olivium-dev/shared-github-actions/.github/workflows/deploy-jeeb-ephemeral.yml@refs/heads/main"
WORKFLOW_SHA = "a" * 40
ENVIRONMENT = "ephemeral-production"


class FakeManagerState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.requests: list[tuple[str, str]] = []
        self.lease: dict | None = None
        self.jobs: dict[str, str] = {}


def handler_for(state: FakeManagerState):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            return

        def body(self) -> dict:
            length = int(self.headers.get("Content-Length", "0"))
            return json.loads(self.rfile.read(length) or b"{}")

        def send_json(self, status: int, payload: dict) -> None:
            raw = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def authorize(self) -> bool:
            if self.headers.get("Authorization") != f"Bearer {os.environ['TEST_OIDC_TOKEN']}":
                self.send_json(401, {"error": "unauthorized"})
                return False
            return True

        def do_GET(self) -> None:  # noqa: N802
            if not self.authorize():
                return
            parsed = urlsplit(self.path)
            with state.lock:
                state.requests.append(("GET", parsed.path))
                if parsed.path == "/api/automation/v1/capabilities":
                    zone = parse_qs(parsed.query).get("zone", [""])[0]
                    self.send_json(200, {"ok": zone == "fds-8.space", "exitCode": 0, "lines": ["strict preflight passed"]})
                    return
                if parsed.path.startswith("/api/automation/v1/jobs/"):
                    job_id = parsed.path.rsplit("/", 1)[1]
                    status = state.jobs.get(job_id, "succeeded")
                    if job_id == "activate-job" and state.lease:
                        state.lease["state"] = "active"
                        state.lease["stateVersion"] += 1
                    if job_id == "abort-job" and state.lease:
                        state.lease["state"] = "deleted"
                        state.lease["stateVersion"] += 1
                    self.send_json(200, {"id": job_id, "kind": "fake", "leaseId": "lease-test-01", "status": status})
                    return
                if parsed.path.startswith("/api/automation/v1/leases/") and state.lease:
                    self.send_json(200, state.lease)
                    return
            self.send_json(404, {"error": "not-found"})

        def do_POST(self) -> None:  # noqa: N802
            if not self.authorize():
                return
            parsed = urlsplit(self.path)
            body = self.body()
            with state.lock:
                state.requests.append(("POST", parsed.path))
                if parsed.path == "/api/automation/v1/leases":
                    if not self.headers.get("Idempotency-Key"):
                        self.send_json(400, {"error": "missing-idempotency"})
                        return
                    state.jobs["create-job"] = "succeeded"
                    state.lease = {
                        "leaseId": "lease-test-01",
                        "jobId": "create-job",
                        "deploymentId": body["deploymentId"],
                        "deploymentLockHash": body["deploymentLockHash"],
                        "profile": body["profile"],
                        "zone": body["zone"],
                        "ttlMinutes": body["ttlMinutes"],
                        "state": "infrastructure_ready",
                        "stateVersion": 2,
                        "httpsHostname": "eph-brave-eevee-22.fds-8.space",
                        "sshHostname": "ssh-eph-brave-eevee-22.fds-8.space",
                        "sshKnownHostsLine": "ssh-eph-brave-eevee-22.fds-8.space ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFIMXLegiMIrcB6K5bfhElmoPbudzkXD1eEBZ9VgW0xB",
                        "sshHostKeyFingerprint": "SHA256:P5Te27X/rHRaeiVlI3TkdfBcLbZaOZFG8eXbSQC5kqA",
                    }
                    self.send_json(202, {"leaseId": "lease-test-01", "jobId": "create-job", "state": "queued", "stateVersion": 1})
                    return
                if parsed.path.endswith("/progress") and state.lease:
                    if body["stateVersion"] != state.lease["stateVersion"]:
                        self.send_json(409, {"error": "state-version"})
                        return
                    state.lease["state"] = body["phase"]
                    state.lease["stateVersion"] += 1
                    self.send_json(200, state.lease)
                    return
                if parsed.path.endswith("/access-grants") and state.lease:
                    if body["stateVersion"] != state.lease["stateVersion"]:
                        self.send_json(409, {"error": "state-version"})
                        return
                    state.lease["stateVersion"] += 1
                    self.send_json(200, {
                        "clientId": "ephemeral-client",
                        "clientSecret": "ephemeral-secret",
                        "expiresAt": "2099-01-01T00:00:00Z",
                        "stateVersion": state.lease["stateVersion"],
                    })
                    return
                if parsed.path.endswith("/activate") and state.lease:
                    state.lease["state"] = "validating"
                    state.lease["stateVersion"] += 1
                    state.jobs["activate-job"] = "succeeded"
                    self.send_json(202, {"leaseId": state.lease["leaseId"], "state": "validating", "stateVersion": state.lease["stateVersion"], "jobId": "activate-job", "idempotentReplay": False})
                    return
                if parsed.path.endswith("/abort") and state.lease:
                    if body.get("expectedState") != "pre-active":
                        self.send_json(400, {"error": "expected-state"})
                        return
                    state.lease["state"] = "cleanup_pending"
                    state.lease["stateVersion"] += 1
                    state.jobs["abort-job"] = "succeeded"
                    self.send_json(202, {"leaseId": state.lease["leaseId"], "state": "cleanup_pending", "stateVersion": state.lease["stateVersion"], "jobId": "abort-job", "idempotentReplay": False})
                    return
            self.send_json(404, {"error": "not-found"})

    return Handler


class FakeManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = FakeManagerState()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(self.state))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        os.environ["TEST_OIDC_TOKEN"] = fake_jwt(AUDIENCE, WORKFLOW_REF, WORKFLOW_SHA, ENVIRONMENT)
        self.client = ManagerClient(
            base_url=f"http://127.0.0.1:{self.server.server_port}",
            audience=AUDIENCE,
            expected_workflow_ref=WORKFLOW_REF,
            expected_workflow_sha=WORKFLOW_SHA,
            expected_environment=ENVIRONMENT,
            static_oidc_env="TEST_OIDC_TOKEN",
            allow_http_for_tests=True,
        )

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        os.environ.pop("TEST_OIDC_TOKEN", None)

    def test_capability_only_calls_one_read_endpoint_and_no_mutation(self) -> None:
        result = self.client.capabilities("fds-8.space")
        self.assertTrue(result["ok"])
        self.assertEqual(self.state.requests, [("GET", "/api/automation/v1/capabilities")])

    def test_manager_lifecycle_contract(self) -> None:
        created = self.client.create(
            {
                "deploymentId": "jeeb-test-01",
                "deploymentLockHash": "f" * 64,
                "profile": "jeeb-swarm-v1",
                "ttlMinutes": 10,
                "zone": "fds-8.space",
                "activationDeadline": "2099-01-01T00:00:00Z",
                "sshPublicKey": "ssh-ed25519 test",
            },
            "offline:test:0001",
        )
        self.client.wait_job(created["jobId"], 2)
        lease = self.client.lease(created["leaseId"])
        lease = self.client.progress(lease, "deploying")
        grant = self.client.access_grant(lease, "nonce-00000001")
        self.assertEqual(grant["clientId"], "ephemeral-client")
        lease["stateVersion"] = grant["stateVersion"]
        lease = self.client.progress(lease, "validating")
        activation = self.client.activate(lease)
        self.client.wait_job(activation["jobId"], 2)
        self.assertEqual(self.client.lease(created["leaseId"])["state"], "active")

    def test_abort_uses_manager_preactive_precondition(self) -> None:
        created = self.client.create(
            {
                "deploymentId": "jeeb-test-02",
                "deploymentLockHash": "e" * 64,
                "profile": "jeeb-swarm-v1",
                "ttlMinutes": 10,
                "zone": "fds-8.space",
                "activationDeadline": "2099-01-01T00:00:00Z",
                "sshPublicKey": "ssh-ed25519 test",
            },
            "offline:test:0002",
        )
        lease = self.client.lease(created["leaseId"])
        result = self.client.abort(lease)
        self.assertEqual(result["state"], "cleanup_pending")

    def test_cloudflared_transport_uses_service_token_environment(self) -> None:
        environment = transport_environment({"clientId": "client", "clientSecret": "secret"})
        self.assertEqual(environment["TUNNEL_SERVICE_TOKEN_ID"], "client")
        self.assertEqual(environment["TUNNEL_SERVICE_TOKEN_SECRET"], "secret")
        self.assertNotIn("CF_ACCESS_CLIENT_ID", environment)
        self.assertNotIn("CF_ACCESS_CLIENT_SECRET", environment)


if __name__ == "__main__":
    unittest.main()
