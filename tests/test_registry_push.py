from __future__ import annotations

import unittest

from common import ContractError, sha256_bytes
from registry_push import GhcrClient


class RegistryPushTests(unittest.TestCase):
    def client_with_digests(self, put_digest: str, head_digest: str) -> GhcrClient:
        client = object.__new__(GhcrClient)
        client.repository = "olivium-dev/jeeb-ephemeral-deploy/service"

        def request(method: str, _path: str, **_kwargs: object):
            digest = put_digest if method == "PUT" else head_digest
            return (201 if method == "PUT" else 200), {"Docker-Content-Digest": digest}, b""

        client._request = request  # type: ignore[method-assign]
        return client

    def test_put_manifest_requires_registry_observation(self) -> None:
        manifest = b'{"schemaVersion":2}'
        digest = f"sha256:{sha256_bytes(manifest)}"
        self.assertEqual(self.client_with_digests(digest, digest).put_manifest("candidate", manifest, "application/json"), digest)

    def test_put_manifest_rejects_unconfirmed_digest(self) -> None:
        manifest = b'{"schemaVersion":2}'
        digest = f"sha256:{sha256_bytes(manifest)}"
        with self.assertRaisesRegex(ContractError, "GHCR HEAD"):
            self.client_with_digests(digest, "sha256:" + "0" * 64).put_manifest("candidate", manifest, "application/json")


if __name__ == "__main__":
    unittest.main()
