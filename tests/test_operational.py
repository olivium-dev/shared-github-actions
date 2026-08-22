from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import operational_guest  # noqa: E402
import operational_orchestrate  # noqa: E402
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


def operational_config() -> dict:
    digest = "a" * 64
    return {
        "services": [
            {
                "id": service_id,
                "repository": f"olivium-dev/{service_id}",
                "commit": "b" * 40,
                "ref": "main",
                "image": f"ghcr.io/olivium-dev/{service_id}@sha256:{digest}",
            }
            for service_id in SERVICE_IDS
        ]
    }


class OperationalContractTests(unittest.TestCase):
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
                    return '{"ok":true}'
                return ""

            with (
                mock.patch.object(operational_orchestrate, "transport", side_effect=fake_transport),
                mock.patch.dict(
                    os.environ,
                    {
                        "JEEB_EPHEMERAL_GHCR_TOKEN": "token-that-is-long-enough",
                        "JEEB_EPHEMERAL_STAGE_TEMPLATE_B64": "x" * 100,
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

            self.assertEqual(7, len(uploaded))
            self.assertFalse(any(command[0] == "scp" for command in commands))
            install = next(command[-1] for command in commands if command[-1].startswith("sudo chown "))
            self.assertNotIn("*", install)
            self.assertIn("operational_guest.py", install)

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

    def test_state_callback_uses_the_lease_private_ip(self) -> None:
        result = operational_guest.transformed_environment(
            {"id": "jeeb-state-service"},
            {"env": ["CaseManagement__GatewayCallbackUrl=http://192.168.2.20:10000/old"]},
            postgres_password="postgres-password",
            mongo_password="mongo-password",
            public_hostname="eph-bright-pikachu-42.fds-8.space",
            private_ip="192.168.2.160",
            gateway_routes=[],
        )

        self.assertEqual(
            "http://192.168.2.160:10000/internal/case-management/callback",
            result["CaseManagement__GatewayCallbackUrl"],
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
                )

    def test_guest_config_requires_exactly_the_catalog_services(self) -> None:
        config = operational_config()
        config["apiVersion"] = "olivium.dev/jeeb-operational-ephemeral/v1"
        catalog = {"services": [{"id": value} for value in SERVICE_IDS]}

        operational_guest.validate_config(config, catalog)
        config["services"].pop()

        with self.assertRaisesRegex(operational_guest.DeployError, "exactly 24"):
            operational_guest.validate_config(config, catalog)


if __name__ == "__main__":
    unittest.main()
