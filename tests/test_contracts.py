from __future__ import annotations

import argparse
import json
import os
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from helpers import make_contracts

from common import ContractError, canonical_sha256, read_json, write_json
from contracts import command_finalize_lock, validate_build_intent, validate_config, validate_final_lock


class ContractTests(unittest.TestCase):
    def test_build_intent_contains_no_predeclared_image_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, intent = make_contracts(root)
            validated = validate_build_intent(intent, validate_config(config, 2))
            self.assertTrue(all("imageRepository" in item for item in validated["services"]))
            self.assertTrue(all("image" not in item for item in validated["services"]))

            fabricated = deepcopy(intent)
            fabricated["services"][0]["image"] = f"{fabricated['services'][0]['imageRepository']}@sha256:{'f' * 64}"
            with self.assertRaisesRegex(ContractError, "unsupported fields"):
                validate_build_intent(fabricated, config)

    def test_final_lock_is_frozen_from_observed_push_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contracts = root / "contracts"
            config, intent = make_contracts(contracts)
            receipts = root / "receipts"
            observed = {}
            for index, service in enumerate(intent["services"], start=5):
                digest = f"sha256:{str(index) * 64}"
                observed[service["id"]] = digest
                receipt = {
                    "apiVersion": "olivium.dev/registry-receipt/v1",
                    "serviceId": service["id"],
                    "imageRepository": service["imageRepository"],
                    "image": f"{service['imageRepository']}@{digest}",
                    "manifestDigest": digest,
                    "artifactSha256": str(index + 1) * 64,
                    "provenanceDigest": f"sha256:{str(index + 2) * 64}",
                    "sourceArchiveSha256": str(index + 3) * 64,
                    "buildInputSha256": service["buildInputSha256"],
                    "runId": "offline-test",
                    "runAttempt": "1",
                }
                write_json(receipts / service["id"] / "receipt.json", receipt)

            output = root / "final-lock"
            command_finalize_lock(
                argparse.Namespace(
                    contracts=contracts,
                    receipts=receipts,
                    output=output,
                    shared_actions_sha="e" * 40,
                    expected_service_count=2,
                    github_output=False,
                )
            )
            final_lock = read_json(output / "deployment-lock.json")
            validate_final_lock(final_lock, config, intent)
            self.assertEqual(
                {item["id"]: item["image"].rsplit("@", 1)[1] for item in final_lock["services"]},
                observed,
            )
            self.assertEqual(final_lock["buildIntentSha256"], canonical_sha256(intent))

    def test_finalizer_rejects_receipt_digest_disagreement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contracts = root / "contracts"
            _, intent = make_contracts(contracts, 1)
            service = intent["services"][0]
            receipt = {
                "apiVersion": "olivium.dev/registry-receipt/v1",
                "serviceId": service["id"],
                "imageRepository": service["imageRepository"],
                "image": f"{service['imageRepository']}@sha256:{'1' * 64}",
                "manifestDigest": f"sha256:{'2' * 64}",
                "artifactSha256": "3" * 64,
                "provenanceDigest": f"sha256:{'4' * 64}",
                "sourceArchiveSha256": "5" * 64,
                "buildInputSha256": service["buildInputSha256"],
                "runId": "offline-test",
                "runAttempt": "1",
            }
            receipts = root / "receipts"
            write_json(receipts / "one" / "receipt.json", receipt)
            with self.assertRaisesRegex(ContractError, "image mismatch"):
                command_finalize_lock(
                    argparse.Namespace(
                        contracts=contracts,
                        receipts=receipts,
                        output=root / "out",
                        shared_actions_sha="e" * 40,
                        expected_service_count=1,
                        github_output=False,
                    )
                )


if __name__ == "__main__":
    unittest.main()
