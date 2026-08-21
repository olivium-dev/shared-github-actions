from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import operational_guest  # noqa: E402
import operational_orchestrate  # noqa: E402


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
            gateway_routes=[
                {"configKey": "Services__Users__BaseUrl", "value": "http://user-management:8080"}
            ],
        )

        serialized = json.dumps(result, sort_keys=True)
        self.assertIn("http://user-management:8080", serialized)
        self.assertIn("eph-bright-pikachu-42.fds-8.space", serialized)
        for forbidden in operational_guest.FORBIDDEN:
            self.assertNotIn(forbidden, serialized)

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
