from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import operational_guest  # noqa: E402
import operational_orchestrate  # noqa: E402
import operational_seed  # noqa: E402
import manager_client  # noqa: E402


SERVICE_IDS = (
    "ban-service",
    "bundler-service",
    "cdn-service",
    "chat-service",
    "compliment-service",
    "contract-signing-service",
    "delivery-service",
    "feedback-service",
    "form-builder-service",
    "geolocation-service",
    "heart-beat",
    "jeeb-gateway",
    "jeeb-state-service",
    "kyc-service",
    "notification-service",
    "offer-service",
    "one-time-password",
    "push-notification",
    "realtime-comunication-service",
    "remote-user-preferences",
    "settlement-service",
    "user-management",
    "voice-transcription-service",
    "wallet-service",
)


def seed_data() -> dict:
    return {
        "users": [
            {
                "id": "10000000-0000-4000-8000-000000000001",
                "email": "regular@seed.jeeb.invalid",
                "username": "Regular User",
                "type": "regular",
                "wallets": [
                    {
                        "id": "20000000-0000-4000-8000-000000000001",
                        "currencyId": 1,
                        "type": "customer",
                        "balance": "25.50",
                        "note": "regular seed",
                    }
                ],
            },
            {
                "id": "10000000-0000-4000-8000-000000000002",
                "email": "jeeber@seed.jeeb.invalid",
                "username": "Seed Jeeber",
                "type": "jeeber",
                "wallets": [
                    {
                        "id": "20000000-0000-4000-8000-000000000002",
                        "currencyId": 1,
                        "type": "jeeb",
                        "balance": "100.00",
                        "note": "jeeber seed credit",
                    },
                    {
                        "id": "20000000-0000-4000-8000-000000000003",
                        "currencyId": 2,
                        "type": "jeeb",
                        "balance": "12.75",
                        "note": "jeeber seed usd",
                    },
                ],
            },
            {
                "id": "10000000-0000-4000-8000-000000000003",
                "email": "cms.operator@seed.jeeb.invalid",
                "username": "CMS Operator",
                "type": "admin",
                "wallets": [],
            },
        ]
    }


def operational_config() -> dict:
    digest = "a" * 64
    return {
        "seedData": seed_data(),
        "services": [
            {
                "id": service_id,
                "repository": f"olivium-dev/{service_id}",
                "commit": "b" * 40,
                "ref": "main",
                "image": f"ghcr.io/olivium-dev/{service_id}@sha256:{digest}",
            }
            for service_id in SERVICE_IDS
        ],
        "webApplications": [
            {
                "id": "jeeb-cms",
                "repository": "olivium-dev/jeeb-cms",
                "commit": "c" * 40,
                "ref": "main",
                "image": f"ghcr.io/olivium-dev/jeeb-cms@sha256:{'d' * 64}",
                "internalPort": 8080,
                "hostPort": 10080,
                "healthPath": "/health",
            }
        ],
    }


class OperationalContractTests(unittest.TestCase):
    def test_guest_private_ip_validation_dependency_is_loaded(self) -> None:
        self.assertEqual(
            ipaddress.ip_address("192.168.2.197"),
            operational_guest.ipaddress.ip_address("192.168.2.197"),
        )

    def test_workflow_summary_contains_real_lifecycle_links(self) -> None:
        workflow = (ROOT / ".github/workflows/deploy-jeeb-operational.yml").read_text(encoding="utf-8")

        self.assertIn(
            "https://ephemeral.fds-8.space/?action=delete&lease=$LEASE_ID",
            workflow,
        )
        self.assertIn(
            "https://ephemeral.fds-8.space/?action=extend&lease=$LEASE_ID",
            workflow,
        )
        self.assertIn("super_login_passcode:\n        required: true", workflow)
        self.assertIn("openai_api_key:\n        required: false", workflow)
        self.assertIn("coroot_api_key:\n        required: true", workflow)
        self.assertIn(
            "JEEB_EPHEMERAL_SUPER_LOGIN_PASSCODE: ${{ secrets.super_login_passcode }}",
            workflow,
        )
        self.assertIn(
            "JEEB_EPHEMERAL_OPENAI_API_KEY: ${{ secrets.openai_api_key }}",
            workflow,
        )
        self.assertIn(
            "JEEB_EPHEMERAL_COROOT_API_KEY: ${{ secrets.coroot_api_key }}",
            workflow,
        )

    def test_protected_super_login_passcode_is_required_and_not_logged(self) -> None:
        valid = {
            "JEEB_EPHEMERAL_GHCR_TOKEN": "token-that-is-long-enough",
            "JEEB_EPHEMERAL_STAGE_TEMPLATE_B64": "x" * 100,
            "JEEB_EPHEMERAL_SUPER_LOGIN_PASSCODE": "ephemeral-only-passcode",
            "JEEB_EPHEMERAL_OPENAI_API_KEY": "sk-ephemeral-test-key-not-real",
            "JEEB_EPHEMERAL_COROOT_API_KEY": "coroot-ephemeral-test-key-not-real",
        }
        with mock.patch.dict(os.environ, valid, clear=True):
            self.assertEqual(
                (
                    valid["JEEB_EPHEMERAL_GHCR_TOKEN"],
                    valid["JEEB_EPHEMERAL_STAGE_TEMPLATE_B64"],
                    valid["JEEB_EPHEMERAL_SUPER_LOGIN_PASSCODE"],
                    valid["JEEB_EPHEMERAL_OPENAI_API_KEY"],
                    valid["JEEB_EPHEMERAL_COROOT_API_KEY"],
                ),
                operational_orchestrate.protected_deployment_credentials(),
            )
        invalid = {**valid, "JEEB_EPHEMERAL_SUPER_LOGIN_PASSCODE": ""}
        with mock.patch.dict(os.environ, invalid, clear=True):
            with self.assertRaisesRegex(operational_orchestrate.ContractError, "passcode is unavailable"):
                operational_orchestrate.protected_deployment_credentials()

        legacy = {**valid, "JEEB_EPHEMERAL_OPENAI_API_KEY": ""}
        with mock.patch.dict(os.environ, legacy, clear=True):
            self.assertEqual("", operational_orchestrate.protected_deployment_credentials()[3])

    def test_manager_get_retries_a_transient_read_timeout(self) -> None:
        client = manager_client.ManagerClient(
            base_url="http://127.0.0.1:1",
            audience="test-audience",
            expected_workflow_ref="workflow-ref",
            expected_workflow_sha="a" * 40,
            expected_environment="test",
            allow_http_for_tests=True,
        )
        with (
            mock.patch.object(client, "fresh_token", return_value="token"),
            mock.patch.object(
                manager_client,
                "request_json",
                side_effect=[TimeoutError("read timed out"), ({"ok": True}, {})],
            ) as request,
            mock.patch.object(manager_client.time, "sleep"),
        ):
            self.assertEqual({"ok": True}, client.request("GET", "/api/automation/v1/jobs/1"))
        self.assertEqual(2, request.call_count)

    def test_manager_post_does_not_retry_an_ambiguous_timeout(self) -> None:
        client = manager_client.ManagerClient(
            base_url="http://127.0.0.1:1",
            audience="test-audience",
            expected_workflow_ref="workflow-ref",
            expected_workflow_sha="a" * 40,
            expected_environment="test",
            allow_http_for_tests=True,
        )
        with (
            mock.patch.object(client, "fresh_token", return_value="token"),
            mock.patch.object(manager_client, "request_json", side_effect=TimeoutError("read timed out")) as request,
        ):
            with self.assertRaises(manager_client.ContractError):
                client.request("POST", "/api/automation/v1/leases/one/progress", {})
        self.assertEqual(1, request.call_count)

    def test_deployment_lock_is_canonical_and_covers_exact_service_set(self) -> None:
        config = operational_config()
        catalog = {
            "metadata": {"profile": "jeeb-full", "version": "1"},
            "services": [{"id": value} for value in SERVICE_IDS],
        }

        lock, lock_hash = operational_orchestrate.deployment_lock(config, catalog, "jeeb-gh-123-1")

        self.assertEqual(24, len(lock["services"]))
        self.assertEqual(set(SERVICE_IDS), {item["serviceId"] for item in lock["services"]})
        self.assertEqual(3, lock["seedData"]["users"])
        self.assertEqual(1, lock["seedData"]["admins"])
        self.assertEqual(3, lock["seedData"]["wallets"])
        self.assertEqual("jeeb-cms", lock["webApplications"][0]["applicationId"])
        self.assertEqual(10080, lock["webApplications"][0]["hostPort"])
        self.assertEqual(operational_seed.seed_digest(config["seedData"]), lock["seedData"]["sha256"])
        unsigned = dict(lock)
        unsigned.pop("lockSha256")
        self.assertEqual(
            lock_hash,
            hashlib.sha256(operational_orchestrate.canonical(unsigned)).hexdigest(),
        )

    def test_runtime_upload_streams_and_verifies_each_file_without_scp_or_globs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            sources = {
                "config": temporary / "config.json",
                "catalog": temporary / "catalog.json",
                "postgres_schema": temporary / "postgres-schema.sql.gz",
                "health_probe": temporary / "http-health-probe",
                "guest_script": temporary / "operational_guest.py",
                "seed_helper": temporary / "operational_seed.py",
                "lock": temporary / "deployment-lock.json",
                "template": temporary / "stage-template.b64",
            }
            for index, path in enumerate(sources.values(), start=1):
                path.write_bytes(f"payload-{index}".encode())
            args = SimpleNamespace(
                config=sources["config"],
                catalog=sources["catalog"],
                postgres_schema=sources["postgres_schema"],
                health_probe=sources["health_probe"],
                guest_script=sources["guest_script"],
                seed_helper=sources["seed_helper"],
            )
            lease = {
                "leaseId": "solar-piplup-26",
                "sshHostname": "ssh-eph-solar-piplup-26.fds-8.space",
                "deploymentId": "jeeb-gh-1-1",
                "deploymentLockHash": "a" * 64,
                "zone": "fds-8.space",
                "privateIp": "192.168.2.160",
            }
            uploaded: dict[str, bytes] = {}
            guest_credentials: dict[str, str] = {}
            commands: list[list[str]] = []

            def fake_transport(argv: list[str], *, stdin: bytes | None = None, timeout: int = 1800) -> str:
                del timeout
                commands.append(argv)
                command = argv[-1]
                if command.startswith("umask 077; dd of="):
                    path = command.split("dd of=", 1)[1].split(" status=none", 1)[0]
                    uploaded[path] = stdin or b""
                elif command.startswith("sha256sum -- "):
                    path = command.removeprefix("sha256sum -- ")
                    return hashlib.sha256(uploaded[path]).hexdigest() + "  " + path
                elif command.startswith("sudo python3 "):
                    guest_credentials.update(json.loads(stdin or b"{}"))
                    return '{"ok":true}'
                return ""

            with (
                mock.patch.object(operational_orchestrate, "transport", side_effect=fake_transport),
                mock.patch.dict(
                    os.environ,
                    {
                        "JEEB_EPHEMERAL_GHCR_TOKEN": "token-that-is-long-enough",
                        "JEEB_EPHEMERAL_STAGE_TEMPLATE_B64": "x" * 100,
                        "JEEB_EPHEMERAL_SUPER_LOGIN_PASSCODE": "ephemeral-only-passcode",
                        "JEEB_EPHEMERAL_OPENAI_API_KEY": "sk-ephemeral-test-key-not-real",
                        "JEEB_EPHEMERAL_COROOT_API_KEY": "coroot-ephemeral-test-key-not-real",
                        "GITHUB_ACTOR": "tester",
                    },
                ),
            ):
                operational_orchestrate.upload_runtime(
                    args,
                    lease,
                    temporary,
                    temporary / "id_ed25519",
                    temporary / "known_hosts",
                    temporary / "cloudflared",
                    sources["lock"],
                    sources["template"],
                )

            self.assertEqual(8, len(uploaded))
            self.assertFalse(any(command[0] == "scp" for command in commands))
            install = next(command[-1] for command in commands if command[-1].startswith("sudo chown "))
            self.assertNotIn("*", install)
            self.assertIn("operational_guest.py", install)
            self.assertIn("operational_seed.py", install)
            self.assertEqual("ephemeral-only-passcode", guest_credentials["superLoginPasscode"])
            self.assertEqual("sk-ephemeral-test-key-not-real", guest_credentials["openAiApiKey"])
            self.assertEqual("coroot-ephemeral-test-key-not-real", guest_credentials["corootApiKey"])

    def test_cloudflare_ssh_keeps_long_guest_deployments_alive(self) -> None:
        options = operational_orchestrate.ssh_options(
            Path("/tmp/cloudflared"),
            Path("/tmp/id_ed25519"),
            Path("/tmp/known_hosts"),
        )

        self.assertIn("ServerAliveInterval=15", options)
        self.assertIn("ServerAliveCountMax=12", options)
        self.assertIn("TCPKeepAlive=yes", options)
        self.assertIn("StrictHostKeyChecking=yes", options)
        self.assertIn("HostKeyAlgorithms=ssh-ed25519", options)

    def test_digest_pinned_pull_retries_transient_registry_resets(self) -> None:
        image = "ghcr.io/olivium-dev/test@sha256:" + "a" * 64
        reset = SimpleNamespace(
            returncode=1,
            stdout=b"",
            stderr=b"failed to do request: read: connection reset by peer",
        )
        success = SimpleNamespace(returncode=0, stdout=b"pulled", stderr=b"")

        with (
            mock.patch.object(
                operational_guest,
                "docker",
                side_effect=[reset, reset, success],
            ) as docker,
            mock.patch.object(operational_guest.time, "sleep") as sleep,
        ):
            operational_guest.pull_image(image)

        self.assertEqual(3, docker.call_count)
        docker.assert_called_with(
            "pull",
            "--quiet",
            image,
            timeout=1800,
            capture=True,
            check=False,
        )
        self.assertEqual([mock.call(5), mock.call(15)], sleep.call_args_list)

    def test_digest_pinned_pull_fails_fast_for_registry_auth_errors(self) -> None:
        image = "ghcr.io/olivium-dev/test@sha256:" + "b" * 64
        permanent_errors = (
            b"failed to do request: 401 Unauthorized",
            b"failed to do request: 404 Not Found",
            b"failed to do request: x509: certificate signed by unknown authority",
        )

        for detail in permanent_errors:
            with self.subTest(detail=detail):
                denied = SimpleNamespace(returncode=1, stdout=b"", stderr=detail)
                with (
                    mock.patch.object(
                        operational_guest, "docker", return_value=denied
                    ) as docker,
                    mock.patch.object(operational_guest.time, "sleep") as sleep,
                    self.assertRaisesRegex(
                        operational_guest.DeployError, "non-retryable error"
                    ),
                ):
                    operational_guest.pull_image(image)

                docker.assert_called_once()
                sleep.assert_not_called()

    def test_digest_pinned_pull_exhaustion_redacts_signed_registry_url(self) -> None:
        image = "ghcr.io/olivium-dev/test@sha256:" + "c" * 64
        signed_url = b'https://pkg-containers.example/blob?sig=do-not-log'
        reset = SimpleNamespace(
            returncode=1,
            stdout=b"",
            stderr=b"failed to do request: Get " + signed_url + b": connection reset by peer",
        )
        output = io.StringIO()

        with (
            mock.patch.object(operational_guest, "docker", return_value=reset) as docker,
            mock.patch.object(operational_guest.time, "sleep") as sleep,
            mock.patch.object(operational_guest.sys, "stderr", output),
            self.assertRaisesRegex(
                operational_guest.DeployError,
                "failed after 3 attempt.*transient network error",
            ) as raised,
        ):
            operational_guest.pull_image(image)

        self.assertEqual(3, docker.call_count)
        self.assertEqual([mock.call(5), mock.call(15)], sleep.call_args_list)
        self.assertNotIn("sig=do-not-log", str(raised.exception))
        self.assertNotIn("sig=do-not-log", output.getvalue())

    def test_digest_pinned_pull_retries_a_subprocess_timeout(self) -> None:
        image = "ghcr.io/olivium-dev/test@sha256:" + "d" * 64
        timeout = subprocess.TimeoutExpired(["docker", "pull", image], 1800)
        success = SimpleNamespace(returncode=0, stdout=b"pulled", stderr=b"")

        with (
            mock.patch.object(
                operational_guest, "docker", side_effect=[timeout, success]
            ) as docker,
            mock.patch.object(operational_guest.time, "sleep") as sleep,
        ):
            operational_guest.pull_image(image)

        self.assertEqual(2, docker.call_count)
        sleep.assert_called_once_with(5)

    def test_digest_pinned_pull_rejects_malformed_digests_before_docker(self) -> None:
        malformed = (
            "ghcr.io/olivium-dev/test:latest",
            "ghcr.io/olivium-dev/test@sha256:" + "a" * 63,
            "ghcr.io/olivium-dev/test@sha256:" + "G" * 64,
        )

        with mock.patch.object(operational_guest, "docker") as docker:
            for image in malformed:
                with self.subTest(image=image), self.assertRaisesRegex(
                    operational_guest.DeployError, "immutable digest"
                ):
                    operational_guest.pull_image(image)

        docker.assert_not_called()

    def test_coroot_agent_is_pinned_privileged_private_and_secret_file_backed(self) -> None:
        api_key = "coroot-ephemeral-test-key-not-real"
        completed = SimpleNamespace(returncode=1, stdout=b"", stderr=b"")
        running = {
            "Config": {
                "Image": operational_guest.COROOT_NODE_AGENT_IMAGE,
                "Env": [],
                "Cmd": ["-ec", 'export API_KEY="$api_key"'],
            },
            "HostConfig": {"Privileged": True, "PidMode": "host", "PortBindings": None},
            "State": {"Running": True, "Status": "running"},
            "NetworkSettings": {"IPAddress": "172.17.0.2"},
        }
        calls: list[tuple] = []

        def fake_docker(*arguments: str, **kwargs: object) -> SimpleNamespace:
            calls.append(arguments)
            if arguments[:2] == ("container", "inspect"):
                if sum(1 for call in calls if call[:2] == ("container", "inspect")) == 1:
                    return completed
                return SimpleNamespace(returncode=0, stdout=json.dumps([running]).encode(), stderr=b"")
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        with tempfile.TemporaryDirectory() as temporary_name:
            state_dir = Path(temporary_name)
            with (
                mock.patch.object(operational_guest, "docker", side_effect=fake_docker),
                mock.patch.object(
                    operational_guest,
                    "bounded_command_output",
                    return_value=SimpleNamespace(returncode=0, stdout=b"node_agent_info 1\n"),
                ) as bounded_output,
                mock.patch.object(operational_guest.urllib.request, "urlopen") as urlopen,
            ):
                urlopen.return_value.__enter__.return_value.status = 200
                urlopen.return_value.__enter__.return_value.read.return_value = b"node_agent_info 1\n"
                operational_guest.deploy_coroot_node_agent(
                    state_dir=state_dir,
                    api_key=api_key,
                    lease_id="bright-pikachu-42",
                    lock_hash="a" * 64,
                    deployment_id="jeeb-gh-1-1",
                )

            key_path = state_dir / "coroot" / "api-key"
            self.assertEqual(api_key, key_path.read_text())
            self.assertEqual(0o400, stat.S_IMODE(key_path.stat().st_mode))
            operational_guest.write_restricted_secret(key_path, api_key)

        run_call = next(call for call in calls if call and call[0] == "run")
        serialized = " ".join(run_call)
        self.assertIn(operational_guest.COROOT_NODE_AGENT_IMAGE, run_call)
        self.assertIn("--privileged", run_call)
        self.assertIn("host", run_call)
        self.assertNotIn(api_key, serialized)
        self.assertIn('export API_KEY="$api_key"', serialized)
        self.assertNotIn("COROOT_API_KEY", serialized)
        self.assertNotIn("--publish", run_call)
        self.assertIn("/run/secrets/coroot-api-key", serialized)
        exec_call = bounded_output.call_args.args[0]
        self.assertEqual(["docker", "exec", operational_guest.COROOT_CONTAINER_NAME], exec_call[:3])
        self.assertIn("/usr/bin/curl", exec_call)
        self.assertIn("http://127.0.0.1:10300/metrics", exec_call)
        self.assertNotIn("172.17.0.2", " ".join(exec_call))
        self.assertEqual(2_000_000, bounded_output.call_args.kwargs["output_limit"])
        self.assertEqual(10, bounded_output.call_args.kwargs["timeout"])
        self.assertEqual(2, urlopen.call_count)

    def test_coroot_readiness_rejects_the_windows_only_api_key_environment(self) -> None:
        running = {
            "Config": {
                "Image": operational_guest.COROOT_NODE_AGENT_IMAGE,
                "Env": [],
                "Cmd": ["-ec", 'export COROOT_API_KEY="$api_key"'],
            },
            "HostConfig": {"Privileged": True, "PidMode": "host", "PortBindings": None},
            "State": {"Running": True, "Status": "running"},
        }
        inspection = SimpleNamespace(
            returncode=0,
            stdout=json.dumps([running]).encode(),
            stderr=b"",
        )

        with mock.patch.object(operational_guest, "docker", return_value=inspection):
            with self.assertRaisesRegex(
                operational_guest.DeployError,
                "documented Linux API key environment",
            ):
                operational_guest.wait_coroot_node_agent(
                    "coroot-ephemeral-test-key-not-real"
                )

    def test_bounded_command_output_caps_output_and_enforces_timeout(self) -> None:
        oversized = operational_guest.bounded_command_output(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 4096)"],
            output_limit=64,
            timeout=2,
        )
        self.assertNotEqual(0, oversized.returncode)
        self.assertEqual(65, len(oversized.stdout))

        started = time.monotonic()
        timed_out = operational_guest.bounded_command_output(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            output_limit=64,
            timeout=1,
        )
        self.assertNotEqual(0, timed_out.returncode)
        self.assertLess(time.monotonic() - started, 1.8)

    def test_coroot_metrics_probe_retries_failures_before_success(self) -> None:
        running = {
            "Config": {
                "Image": operational_guest.COROOT_NODE_AGENT_IMAGE,
                "Env": [],
                "Cmd": ["-ec", 'export API_KEY="$api_key"'],
            },
            "HostConfig": {"Privileged": True, "PidMode": "host", "PortBindings": None},
            "State": {"Running": True, "Status": "running"},
        }
        inspection = SimpleNamespace(
            returncode=0,
            stdout=json.dumps([running]).encode(),
            stderr=b"",
        )
        attempts = [
            SimpleNamespace(returncode=-9, stdout=b""),
            SimpleNamespace(returncode=1, stdout=b""),
            SimpleNamespace(returncode=-9, stdout=b"x" * 2_000_001),
            SimpleNamespace(returncode=0, stdout=b"metrics without marker\n"),
            SimpleNamespace(returncode=0, stdout=b"node_agent_info 1\n"),
        ]
        with (
            mock.patch.object(operational_guest, "docker", return_value=inspection),
            mock.patch.object(operational_guest, "bounded_command_output", side_effect=attempts) as probe,
            mock.patch.object(operational_guest.time, "sleep"),
        ):
            operational_guest.wait_coroot_node_agent("coroot-ephemeral-test-key-not-real")
        self.assertEqual(5, probe.call_count)

    def test_coroot_metrics_probe_fails_at_the_deadline(self) -> None:
        running = {
            "Config": {
                "Image": operational_guest.COROOT_NODE_AGENT_IMAGE,
                "Env": [],
                "Cmd": ["-ec", 'export API_KEY="$api_key"'],
            },
            "HostConfig": {"Privileged": True, "PidMode": "host", "PortBindings": None},
            "State": {"Running": True, "Status": "running"},
        }
        inspection = SimpleNamespace(
            returncode=0,
            stdout=json.dumps([running]).encode(),
            stderr=b"",
        )
        clock = SimpleNamespace(now=0.0)

        def monotonic() -> float:
            return clock.now

        def sleep(seconds: float) -> None:
            clock.now += seconds

        with (
            mock.patch.object(operational_guest, "docker", return_value=inspection),
            mock.patch.object(
                operational_guest,
                "bounded_command_output",
                return_value=SimpleNamespace(returncode=1, stdout=b""),
            ),
            mock.patch.object(operational_guest.time, "sleep", side_effect=sleep),
            mock.patch.object(operational_guest.time, "monotonic", side_effect=monotonic),
        ):
            with self.assertRaisesRegex(
                operational_guest.DeployError,
                "namespace-local metrics endpoint is unavailable",
            ):
                operational_guest.wait_coroot_node_agent(
                    "coroot-ephemeral-test-key-not-real",
                    timeout=1,
                )
        self.assertEqual(1.0, clock.now)

    def test_coroot_metrics_probe_clamps_each_operation_to_the_deadline(self) -> None:
        running = {
            "Config": {
                "Image": operational_guest.COROOT_NODE_AGENT_IMAGE,
                "Env": [],
                "Cmd": ["-ec", 'export API_KEY="$api_key"'],
            },
            "HostConfig": {"Privileged": True, "PidMode": "host", "PortBindings": None},
            "State": {"Running": True, "Status": "running"},
        }
        inspection = SimpleNamespace(
            returncode=0,
            stdout=json.dumps([running]).encode(),
            stderr=b"",
        )
        clock = SimpleNamespace(now=0.0)
        observed: dict[str, float] = {}

        def monotonic() -> float:
            return clock.now

        def inspect(*arguments: str, **kwargs: object) -> SimpleNamespace:
            observed["inspect_timeout"] = float(kwargs["timeout"])
            clock.now = 89.0
            return inspection

        def probe(*args: object, **kwargs: object) -> SimpleNamespace:
            observed["probe_timeout"] = float(kwargs["timeout"])
            clock.now += observed["probe_timeout"]
            return SimpleNamespace(returncode=1, stdout=b"")

        with (
            mock.patch.object(operational_guest, "docker", side_effect=inspect),
            mock.patch.object(operational_guest, "bounded_command_output", side_effect=probe),
            mock.patch.object(operational_guest.time, "sleep") as sleep,
            mock.patch.object(operational_guest.time, "monotonic", side_effect=monotonic),
        ):
            with self.assertRaisesRegex(
                operational_guest.DeployError,
                "namespace-local metrics endpoint is unavailable",
            ):
                operational_guest.wait_coroot_node_agent(
                    "coroot-ephemeral-test-key-not-real",
                    timeout=90,
                )

        self.assertEqual(90.0, observed["inspect_timeout"])
        self.assertEqual(1.0, observed["probe_timeout"])
        self.assertEqual(90.0, clock.now)
        sleep.assert_not_called()

    def test_seed_data_is_dynamic_strict_and_bound_to_the_lock(self) -> None:
        config = operational_config()
        catalog = {
            "metadata": {"profile": "jeeb-full", "version": "1"},
            "services": [{"id": value} for value in SERVICE_IDS],
        }
        first_lock, first_hash = operational_orchestrate.deployment_lock(config, catalog, "jeeb-gh-123-1")
        config["seedData"]["users"][1]["wallets"][0]["balance"] = "777.25"
        second_lock, second_hash = operational_orchestrate.deployment_lock(config, catalog, "jeeb-gh-123-1")

        self.assertNotEqual(first_hash, second_hash)
        self.assertNotEqual(first_lock["seedData"]["sha256"], second_lock["seedData"]["sha256"])

    def test_seed_data_rejects_missing_jeeber_currency_and_float_money(self) -> None:
        missing_currency = seed_data()
        missing_currency["users"][1]["wallets"].pop()
        with self.assertRaisesRegex(operational_seed.SeedContractError, "currencyId 1 and 2"):
            operational_seed.validate_seed_data(missing_currency)

        float_money = seed_data()
        float_money["users"][0]["wallets"][0]["balance"] = 25.5
        with self.assertRaisesRegex(operational_seed.SeedContractError, "decimal string"):
            operational_seed.validate_seed_data(float_money)

    def test_seed_sql_escapes_editable_text_and_uses_real_databases(self) -> None:
        seed = seed_data()
        seed["users"][0]["username"] = "O'Neil Customer"
        seed["users"][0]["wallets"][0]["note"] = "customer's opening balance"

        user_sql = operational_seed.build_user_seed_sql(seed).decode()
        wallet_sql = operational_seed.build_wallet_seed_sql(seed).decode()

        self.assertIn("O''Neil Customer", user_sql)
        self.assertIn("customer''s opening balance", wallet_sql)
        self.assertIn('public."Users"', user_sql)
        self.assertIn("public.walletholder", wallet_sql)
        self.assertIn("public.wallets", wallet_sql)

    def test_guest_applies_and_verifies_seed_counts_and_balance(self) -> None:
        config = {"seedData": seed_data()}
        receipts = [{"users": 3}, {"wallets": 3, "balance": "138.25"}]
        with mock.patch.object(operational_guest, "execute_seed_sql", side_effect=receipts) as execute:
            counts = operational_guest.apply_seed_data(config, "jeeb-eph-test")

        self.assertEqual(
            {"users": 3, "regularUsers": 1, "jeebers": 1, "admins": 1, "wallets": 3},
            counts,
        )
        self.assertEqual("jeeb-user-management_staging", execute.call_args_list[0].args[1])
        self.assertEqual("jeeb-wallet_staging", execute.call_args_list[1].args[1])

    def test_guest_validates_every_seed_login_and_each_jeeber_wallet(self) -> None:
        seed = seed_data()
        roster = {
            "users": [
                {
                    "userId": seed["users"][0]["id"],
                    "name": "Regular User",
                    "role": "customer",
                    "roles": ["customer"],
                },
                {
                    "userId": seed["users"][1]["id"],
                    "name": "Seed Jeeber",
                    "role": "driver",
                    "roles": ["customer", "driver"],
                },
                {
                    "userId": seed["users"][2]["id"],
                    "name": "CMS Operator",
                    "role": "admin",
                    "roles": ["admin"],
                },
            ]
        }
        responses = [
            roster,
            {"authToken": "one.two.three"},
            {"authToken": "four.five.six"},
            {"authToken": "seven.eight.nine"},
            {"availableBalance": 112.75},
            {"capabilities": ["admin.portal.access", "cms.config.read"]},
        ]
        with (
            mock.patch.object(operational_guest, "gateway_json", side_effect=responses) as gateway,
            mock.patch.object(
                operational_guest,
                "service_environment",
                return_value={"SuperAdmin__PassCode": "not-printed"},
            ),
        ):
            operational_guest.validate_seed_gateway({"seedData": seed}, "jeeb-eph-test")

        self.assertEqual(6, gateway.call_count)
        login_payloads = [call.kwargs["payload"] for call in gateway.call_args_list[1:4]]
        self.assertEqual({user["id"] for user in seed["users"]}, {body["userId"] for body in login_payloads})
        self.assertEqual("/v1/jeeb/wallet", gateway.call_args_list[-2].args[0])
        self.assertEqual("/admin/session", gateway.call_args_list[-1].args[0])

    def test_environment_rewrites_stage_dependencies_to_the_lease(self) -> None:
        service = {
            "id": "jeeb-gateway",
            "stagingName": "jeeb-staging-jeeb-gateway",
        }
        template = {
            "env": [
                "OLD_API=http://192.168.2.20:10001",
                "PUBLIC=https://jeeb-staging.fds-1.com",
                "Redis__ConnectionString=192.168.2.20:6379",
            ]
        }

        result = operational_guest.transformed_environment(
            service,
            template,
            postgres_password="postgres-password",
            mongo_password="mongo-password",
            super_login_passcode="ephemeral-only-passcode",
            public_hostname="eph-bright-pikachu-42.fds-8.space",
            private_ip="192.168.2.160",
            gateway_routes=[
                {"configKey": "Services__Users__BaseUrl", "value": "http://user-management:8080"}
            ],
        )

        serialized = json.dumps(result, sort_keys=True)
        self.assertIn("http://user-management:8080", serialized)
        self.assertIn("eph-bright-pikachu-42.fds-8.space", serialized)
        for forbidden in operational_guest.FORBIDDEN:
            self.assertNotIn(forbidden, serialized)
        self.assertEqual("Ephemeral", result["ASPNETCORE_ENVIRONMENT"])
        self.assertEqual("Ephemeral", result["DOTNET_ENVIRONMENT"])
        self.assertEqual("false", result["Features__RealtimeWebSocketProxy__Enabled"])
        self.assertEqual("true", result["FeatureFlags__NotificationDurableWrite__Enabled"])
        self.assertEqual(
            "/run/secrets/push_gateway_api_key",
            result["PushNotificationServiceApi__GatewayApiKeyFile"],
        )

    def test_state_callback_uses_the_lease_private_ip(self) -> None:
        result = operational_guest.transformed_environment(
            {"id": "jeeb-state-service"},
            {"env": ["CaseManagement__GatewayCallbackUrl=http://192.168.2.20:10000/old"]},
            postgres_password="postgres-password",
            mongo_password="mongo-password",
            super_login_passcode="ephemeral-only-passcode",
            public_hostname="eph-bright-pikachu-42.fds-8.space",
            private_ip="192.168.2.160",
            gateway_routes=[],
        )

        self.assertEqual(
            "http://192.168.2.160:10000/internal/case-management/callback",
            result["CaseManagement__GatewayCallbackUrl"],
        )

    def test_forbidden_ip_matching_does_not_reject_a_longer_lease_address(self) -> None:
        for forbidden in ("192.168.2.20", "192.168.2.39", "192.168.2.50"):
            with self.subTest(forbidden=forbidden):
                self.assertTrue(
                    operational_guest.contains_forbidden_endpoint(
                        f"UPSTREAM=http://{forbidden}:8080/health",
                        forbidden,
                    )
                )
        self.assertFalse(
            operational_guest.contains_forbidden_endpoint(
                "CaseManagement__GatewayCallbackUrl=http://192.168.2.200:10000/callback",
                "192.168.2.20",
            )
        )

        result = operational_guest.transformed_environment(
            {"id": "jeeb-state-service"},
            {"env": ["CaseManagement__GatewayCallbackUrl=http://192.168.2.20:10000/old"]},
            postgres_password="postgres-password",
            mongo_password="mongo-password",
            super_login_passcode="ephemeral-only-passcode",
            public_hostname="eph-bright-pikachu-42.fds-8.space",
            private_ip="192.168.2.200",
            gateway_routes=[],
        )
        self.assertEqual(
            "http://192.168.2.200:10000/internal/case-management/callback",
            result["CaseManagement__GatewayCallbackUrl"],
        )

    def test_generic_postgres_url_disables_ssl_inside_the_lease(self) -> None:
        result = operational_guest.transformed_environment(
            {"id": "delivery-service"},
            {"env": ["DATABASE_URL=postgresql://staging.invalid/delivery"]},
            postgres_password="postgres-password",
            mongo_password="mongo-password",
            super_login_passcode="ephemeral-only-passcode",
            public_hostname="eph-bright-pikachu-42.fds-8.space",
            private_ip="192.168.2.160",
            gateway_routes=[],
        )

        self.assertEqual(
            "postgresql://oudaykhaled:postgres-password@postgresql:5432/delivery_staging?sslmode=disable",
            result["DATABASE_URL"],
        )

    def test_user_management_uses_the_protected_ephemeral_super_login_passcode(self) -> None:
        result = operational_guest.transformed_environment(
            {"id": "user-management"},
            {"env": ["SuperAdmin__PassCode=staging-value"]},
            postgres_password="postgres-password",
            mongo_password="mongo-password",
            super_login_passcode="ephemeral-only-passcode",
            public_hostname="eph-bright-pikachu-42.fds-8.space",
            private_ip="192.168.2.160",
            gateway_routes=[],
        )

        self.assertEqual("ephemeral-only-passcode", result["SuperAdmin__PassCode"])

    def test_offer_migration_ledger_matches_the_pinned_service_schema(self) -> None:
        completed = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        with (
            mock.patch.object(operational_guest, "wait_service", return_value="postgres-container"),
            mock.patch.object(operational_guest, "docker", return_value=completed) as docker,
        ):
            operational_guest.record_offer_migration_ledger("jeeb-eph-test")

        self.assertEqual(10, len(operational_guest.OFFER_SCHEMA_MIGRATIONS))
        call = docker.call_args
        self.assertIn("offer_service_staging", call.args[-1])
        sql = call.kwargs["stdin"].decode()
        for version in operational_guest.OFFER_SCHEMA_MIGRATIONS:
            self.assertIn(str(version), sql)
        self.assertIn("ON CONFLICT (version) DO NOTHING", sql)

    def test_nginx_routes_cms_and_gateway_traffic_without_exposing_private_ports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            config_path = Path(temporary_name) / "default"
            with mock.patch.object(operational_guest, "run") as run:
                operational_guest.configure_public_gateway(config_path)

            config = config_path.read_text(encoding="ascii")

        self.assertIn("location /gateway/", config)
        self.assertIn("proxy_pass http://127.0.0.1:10000/;", config)
        self.assertIn("location = /health", config)
        self.assertIn("proxy_pass http://127.0.0.1:10080/health;", config)
        self.assertIn("location ~ ^/(?:api|v1|admin|health)(?:/|$)", config)
        self.assertIn("proxy_pass http://127.0.0.1:10080;", config)
        self.assertIn("location = /.well-known/olivium-lease", config)
        self.assertIn("proxy_set_header Upgrade $http_upgrade;", config)
        self.assertEqual(
            [mock.call(["nginx", "-t"]), mock.call(["systemctl", "reload", "nginx"])],
            run.call_args_list,
        )

    def test_application_service_creation_is_explicitly_detached(self) -> None:
        service = {
            "id": "delivery-service",
            "image": f"ghcr.io/olivium-dev/delivery-service@sha256:{'a' * 64}",
            "stagingName": "jeeb-staging-delivery-service",
            "internalPort": 8080,
            "healthPath": "/health/ready",
        }
        with (
            mock.patch.object(operational_guest, "transformed_environment", return_value={}),
            mock.patch.object(operational_guest, "materialize_mounts", return_value=([], [])),
            mock.patch.object(operational_guest, "configure_application_healthcheck") as healthcheck,
            mock.patch.object(operational_guest, "docker") as docker,
        ):
            operational_guest.create_application(
                service,
                {},
                {},
                {"gatewayRouting": []},
                prefix="jeeb-eph-test",
                network="jeeb-eph-test",
                lease_id="bright-pikachu-42",
                lock_hash="b" * 64,
                deployment_id="jeeb-gh-1-1",
                postgres_password="postgres-password",
                mongo_password="mongo-password",
                super_login_passcode="ephemeral-only-passcode",
                openai_api_key="sk-ephemeral-test-key-not-real",
                push_gateway_api_key="ephemeral-push-key-not-real",
                push_notification_delivery_api_key="ephemeral-notification-key-not-real",
                public_hostname="eph-bright-pikachu-42.fds-8.space",
                private_ip="192.168.2.160",
                probe_config="jeeb-eph-test-http-health-probe",
            )

        self.assertIn("--detach=true", docker.call_args.args)
        healthcheck.assert_called_once_with("jeeb-eph-test-delivery-service", 8080, "/health/ready")

    def test_cms_service_creation_publishes_only_the_reserved_web_port(self) -> None:
        application = {
            "id": "jeeb-cms",
            "image": f"ghcr.io/olivium-dev/jeeb-cms@sha256:{'a' * 64}",
            "internalPort": 8080,
            "hostPort": 10080,
            "healthPath": "/health",
        }
        with (
            mock.patch.object(operational_guest, "configure_application_healthcheck") as healthcheck,
            mock.patch.object(operational_guest, "docker") as docker,
        ):
            operational_guest.create_web_application(
                application,
                prefix="jeeb-eph-test",
                network="jeeb-eph-test",
                lease_id="bright-pikachu-42",
                lock_hash="b" * 64,
                deployment_id="jeeb-gh-1-1",
                probe_config="jeeb-eph-test-http-health-probe",
            )

        command = docker.call_args.args
        self.assertIn("--detach=true", command)
        self.assertIn("published=10080,target=8080,mode=host", command)
        self.assertNotIn("published=10000,target=8080,mode=host", command)
        healthcheck.assert_called_once_with("jeeb-eph-test-jeeb-cms", 8080, "/health")

    def test_application_healthcheck_uses_engine_exec_form(self) -> None:
        inspected = [
            {
                "ID": "service-id",
                "Version": {"Index": 9},
                "Spec": {"TaskTemplate": {"ContainerSpec": {"Image": "image@sha256:digest"}}},
            }
        ]
        completed = SimpleNamespace(stdout=json.dumps(inspected).encode())
        with (
            mock.patch.object(operational_guest, "docker", return_value=completed),
            mock.patch.object(operational_guest, "docker_api_post", return_value={}) as api_post,
        ):
            operational_guest.configure_application_healthcheck(
                "jeeb-eph-test-cdn-service",
                8080,
                "/health/ready",
            )

        path, spec = api_post.call_args.args
        self.assertEqual(
            "/v1.41/services/service-id/update?version=9&registryAuthFrom=spec",
            path,
        )
        self.assertEqual(
            [
                "CMD",
                "/run/olivium/http-health-probe",
                "--url",
                "http://127.0.0.1:8080/health/ready",
            ],
            spec["TaskTemplate"]["ContainerSpec"]["Healthcheck"]["Test"],
        )

    def test_application_health_probe_is_exec_form_without_a_shell(self) -> None:
        completed = SimpleNamespace(returncode=0, stdout=b"ok", stderr=b"")
        with (
            mock.patch.object(operational_guest, "wait_service", return_value="container-id"),
            mock.patch.object(operational_guest, "docker", return_value=completed) as docker,
        ):
            container_id = operational_guest.wait_application(
                "jeeb-eph-test-jeeb-state-service",
                8080,
                "/health/ready",
                timeout=30,
            )

        self.assertEqual("container-id", container_id)
        docker.assert_called_once_with(
            "exec",
            "container-id",
            "/run/olivium/http-health-probe",
            "--url",
            "http://127.0.0.1:8080/health/ready",
            capture=True,
            check=False,
        )

    def test_materialized_mounts_preserve_non_root_ownership(self) -> None:
        template = {
            "secrets": {"state-token": "secret-value"},
            "configs": {"settings": "config-value"},
        }
        service = {
            "secrets": [
                {
                    "name": "state-token",
                    "target": "jeeb_state_service_token",
                    "uid": "64198",
                    "gid": "64198",
                    "mode": 0o400,
                }
            ],
            "configs": [
                {
                    "name": "settings",
                    "target": "/app/settings.json",
                    "uid": "1000",
                    "gid": "1001",
                    "mode": 0o440,
                }
            ],
        }

        with (
            mock.patch.object(operational_guest, "create_secret"),
            mock.patch.object(operational_guest, "create_config"),
        ):
            secrets, configs = operational_guest.materialize_mounts(
                template,
                service,
                prefix="jeeb-eph-test",
                lease_id="bright-pikachu-42",
                lock_hash="a" * 64,
                deployment_id="jeeb-gh-1-1",
                service_id="jeeb-state-service",
                postgres_password="postgres-password",
                openai_api_key="sk-ephemeral-test-key-not-real",
                push_gateway_api_key="ephemeral-push-key-not-real",
                push_notification_delivery_api_key="ephemeral-notification-key-not-real",
            )

        self.assertEqual("64198", secrets[0]["uid"])
        self.assertEqual("64198", secrets[0]["gid"])
        self.assertEqual(0o400, secrets[0]["mode"])
        self.assertEqual("1000", configs[0]["uid"])
        self.assertEqual("1001", configs[0]["gid"])
        self.assertEqual(
            "source=jeeb-eph-test-jeeb-state-service-secret-00,"
            "target=jeeb_state_service_token,uid=64198,gid=64198,mode=0400",
            operational_guest.mount_spec(secrets[0]),
        )

    def test_materialized_mounts_reject_invalid_ownership(self) -> None:
        template = {"secrets": {"state-token": "secret-value"}}
        service = {
            "secrets": [
                {
                    "name": "state-token",
                    "target": "jeeb_state_service_token",
                    "uid": "root",
                    "gid": "64198",
                    "mode": 0o400,
                }
            ]
        }
        with mock.patch.object(operational_guest, "create_secret"):
            with self.assertRaisesRegex(operational_guest.DeployError, "invalid secret UID"):
                operational_guest.materialize_mounts(
                    template,
                    service,
                    prefix="jeeb-eph-test",
                    lease_id="bright-pikachu-42",
                    lock_hash="a" * 64,
                    deployment_id="jeeb-gh-1-1",
                    service_id="jeeb-state-service",
                    postgres_password="postgres-password",
                    openai_api_key="sk-ephemeral-test-key-not-real",
                    push_gateway_api_key="ephemeral-push-key-not-real",
                    push_notification_delivery_api_key="ephemeral-notification-key-not-real",
                )

    def test_push_gateway_credential_is_shared_by_file_without_exposing_its_value(self) -> None:
        push_key = "ephemeral-push-key-not-real"
        notification_key = "ephemeral-notification-key-not-real"
        with (
            mock.patch.object(operational_guest, "create_secret") as create_secret,
            mock.patch.object(operational_guest, "create_config"),
        ):
            gateway_mounts, _ = operational_guest.materialize_mounts(
                {"secrets": {}, "configs": {}},
                {"secrets": [], "configs": []},
                prefix="jeeb-eph-test",
                lease_id="bright-pikachu-42",
                lock_hash="a" * 64,
                deployment_id="jeeb-gh-1-1",
                service_id="jeeb-gateway",
                postgres_password="postgres-password",
                openai_api_key="sk-ephemeral-test-key-not-real",
                push_gateway_api_key=push_key,
                push_notification_delivery_api_key=notification_key,
            )
            push_mounts, _ = operational_guest.materialize_mounts(
                {"secrets": {}, "configs": {}},
                {"secrets": [], "configs": []},
                prefix="jeeb-eph-test",
                lease_id="bright-pikachu-42",
                lock_hash="a" * 64,
                deployment_id="jeeb-gh-1-1",
                service_id="push-notification",
                postgres_password="postgres-password",
                openai_api_key="sk-ephemeral-test-key-not-real",
                push_gateway_api_key=push_key,
                push_notification_delivery_api_key=notification_key,
            )
            notification_mounts, _ = operational_guest.materialize_mounts(
                {"secrets": {}, "configs": {}},
                {"secrets": [], "configs": []},
                prefix="jeeb-eph-test",
                lease_id="bright-pikachu-42",
                lock_hash="a" * 64,
                deployment_id="jeeb-gh-1-1",
                service_id="notification-service",
                postgres_password="postgres-password",
                openai_api_key="sk-ephemeral-test-key-not-real",
                push_gateway_api_key=push_key,
                push_notification_delivery_api_key=notification_key,
            )

        self.assertEqual(4, create_secret.call_count)
        gateway_calls = [
            call for call in create_secret.call_args_list
            if call.args[0] == "jeeb-eph-test-push-gateway-api-key"
        ]
        notification_calls = [
            call for call in create_secret.call_args_list
            if call.args[0] == "jeeb-eph-test-push-notification-delivery-api-key"
        ]
        self.assertEqual(2, len(gateway_calls))
        self.assertEqual(2, len(notification_calls))
        self.assertTrue(all(call.args[1] == push_key.encode() for call in gateway_calls))
        self.assertTrue(
            all(call.args[1] == notification_key.encode() for call in notification_calls)
        )
        self.assertEqual("65532", gateway_mounts[0]["uid"])
        self.assertEqual("10001", push_mounts[0]["uid"])
        self.assertEqual("push_gateway_api_key", gateway_mounts[0]["target"])
        self.assertEqual("push_gateway_api_key", push_mounts[0]["target"])
        self.assertEqual("push_notification_delivery_api_key", push_mounts[1]["target"])
        self.assertEqual(
            "push_notification_delivery_api_key", notification_mounts[0]["target"]
        )

        push_environment = operational_guest.transformed_environment(
            {"id": "push-notification"},
            {"env": []},
            postgres_password="postgres-password",
            mongo_password="mongo-password",
            super_login_passcode="ephemeral-only-passcode",
            public_hostname="eph-test.fds-8.space",
            private_ip="192.168.2.160",
            gateway_routes=[],
        )
        self.assertEqual(
            "/run/secrets/push_gateway_api_key",
            push_environment["GATEWAY_API_KEY_FILE"],
        )
        self.assertEqual(
            "/run/secrets/push_notification_delivery_api_key",
            push_environment["NOTIFICATION_DELIVERY_API_KEY_FILE"],
        )
        self.assertEqual("strict", push_environment["PUSH_AUTH_MODE"])
        self.assertEqual("true", push_environment["PUSH_PIPELINE_REQUIRED"])

        notification_environment = operational_guest.transformed_environment(
            {"id": "notification-service"},
            {"env": []},
            postgres_password="postgres-password",
            mongo_password="mongo-password",
            super_login_passcode="ephemeral-only-passcode",
            public_hostname="eph-test.fds-8.space",
            private_ip="192.168.2.160",
            gateway_routes=[],
        )
        self.assertEqual("X-Api-Key", notification_environment["WEBHOOK_AUTH_HEADER_NAME"])
        self.assertEqual(
            "/run/secrets/push_notification_delivery_api_key",
            notification_environment["WEBHOOK_AUTH_HEADER_VALUE_FILE"],
        )

    def test_voice_environment_and_secret_are_real_provider_file_backed(self) -> None:
        service = {"id": "voice-transcription-service"}
        template_service = {
            "env": [
                "OPENAI_API_KEY=must-not-survive",
                "WHISPER_FAKE_TRANSCRIBE=1",
            ]
        }
        environment = operational_guest.transformed_environment(
            service,
            template_service,
            postgres_password="postgres-password",
            mongo_password="mongo-password",
            super_login_passcode="ephemeral-only-passcode",
            public_hostname="eph-test.fds-8.space",
            private_ip="192.168.2.160",
            gateway_routes=[],
            openai_api_key="sk-ephemeral-test-key-not-real",
        )
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertEqual("production", environment["ENVIRONMENT"])
        self.assertEqual("0", environment["WHISPER_FAKE_TRANSCRIBE"])
        self.assertEqual("0", environment["DURABLE_TRANSCRIPTION_ENABLED"])
        self.assertEqual(
            "/run/secrets/openai-ephemeral-sandbox-api-key",
            environment["OPENAI_API_KEY_FILE"],
        )

        with (
            mock.patch.object(operational_guest, "create_secret") as create_secret,
            mock.patch.object(operational_guest, "create_config"),
        ):
            mounts, _ = operational_guest.materialize_mounts(
                {"secrets": {}, "configs": {}},
                {"secrets": [], "configs": []},
                prefix="jeeb-eph-test",
                lease_id="bright-pikachu-42",
                lock_hash="a" * 64,
                deployment_id="jeeb-gh-1-1",
                service_id="voice-transcription-service",
                postgres_password="postgres-password",
                openai_api_key="sk-ephemeral-test-key-not-real",
                push_gateway_api_key="ephemeral-push-key-not-real",
                push_notification_delivery_api_key="ephemeral-notification-key-not-real",
            )
        create_secret.assert_called_once()
        self.assertEqual("openai-ephemeral-sandbox-api-key", mounts[0]["target"])
        self.assertEqual("65532", mounts[0]["uid"])
        self.assertEqual("65532", mounts[0]["gid"])
        self.assertEqual(0o400, mounts[0]["mode"])

        fake_environment = operational_guest.transformed_environment(
            service,
            template_service,
            postgres_password="postgres-password",
            mongo_password="mongo-password",
            super_login_passcode="ephemeral-only-passcode",
            public_hostname="eph-test.fds-8.space",
            private_ip="192.168.2.160",
            gateway_routes=[],
        )
        self.assertEqual("1", fake_environment["WHISPER_FAKE_TRANSCRIBE"])
        self.assertEqual("0", fake_environment["DURABLE_TRANSCRIPTION_ENABLED"])
        self.assertNotIn("OPENAI_API_KEY", fake_environment)
        self.assertNotIn("OPENAI_API_KEY_FILE", fake_environment)

    def test_guest_config_requires_exactly_the_catalog_services(self) -> None:
        config = operational_config()
        config["apiVersion"] = "olivium.dev/jeeb-operational-ephemeral/v1"
        catalog = {"services": [{"id": value} for value in SERVICE_IDS]}

        operational_guest.validate_config(config, catalog)
        config["services"].pop()

        with self.assertRaisesRegex(operational_guest.DeployError, "exactly 24"):
            operational_guest.validate_config(config, catalog)

    def test_only_the_exact_legacy_voice_revision_may_run_without_openai(self) -> None:
        config = operational_config()
        voice = next(item for item in config["services"] if item["id"] == "voice-transcription-service")
        voice["commit"] = operational_guest.LEGACY_FAKE_VOICE_COMMIT
        self.assertEqual("", operational_guest.validate_openai_credential(config, ""))

        voice["commit"] = "ac8943b5be33ae65ad44263b803d486bb09c5f9e"
        with self.assertRaisesRegex(operational_guest.DeployError, "non-legacy voice"):
            operational_guest.validate_openai_credential(config, "")
        self.assertEqual(
            "sk-ephemeral-test-key-not-real",
            operational_guest.validate_openai_credential(config, "sk-ephemeral-test-key-not-real"),
        )


if __name__ == "__main__":
    unittest.main()
