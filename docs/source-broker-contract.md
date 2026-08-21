# GitHub App Source Broker Contract

The broker is a trusted, manager-owned API boundary. It validates the same protected GitHub OIDC identity family as the manager and keeps the GitHub App private key and installation tokens off GitHub runners.

## `POST /v1/preflight`

The request contains `apiVersion: olivium.dev/source-broker/v1`, deployment ID, canonical build-intent hash, exact repository/commit pairs, required package-grant-set hash, and non-secret GitHub run identity.

The response must contain only:

```json
{
  "apiVersion": "olivium.dev/source-broker/v1",
  "ready": true,
  "installationId": "12345678",
  "repositories": [
    {
      "repository": "olivium-dev/example-service",
      "commit": "0000000000000000000000000000000000000001",
      "allowed": true
    }
  ],
  "packageGrantSetSha256": "64-lowercase-hex-characters",
  "expiresAt": "2026-08-21T18:00:00Z"
}
```

The set must exactly match the reviewed build intent. Missing and extra repositories both fail.

## `POST /v1/source-bundles`

The request names one reviewed service, repository, commit, build-input hash, deployment ID, build-intent hash, and caller run identity.

The response is a canonical gzip tar archive with:

- `Content-Type: application/vnd.olivium.source-bundle.v1+tar+gzip`
- `Digest: sha-256=<base64 digest>`
- `X-Olivium-Source-Id`
- `X-Olivium-Source-Repository`
- `X-Olivium-Source-Commit`

Archives may contain regular files and directories only. Absolute paths, traversal, symlinks, hard links, devices, and oversized archives are rejected. The broker must return source bytes, not a GitHub App token, checkout credential, redirect URL, or presigned URL.

## Broker Owner Gates

- Install a dedicated GitHub App with read-only Contents access to exactly the 24 approved repositories.
- Pin installation ID, repository IDs, caller repository ID, protected environment, reusable-workflow ref, and reusable-workflow SHA.
- Mint a fresh GitHub OIDC token per request and reject token replay.
- Prove current-repository GHCR write/read grants and issue a reviewed `packageGrantSetSha256`.
- Log request identity and hashes, never tokens or source contents.
- Rate-limit and cap archive size; do not execute repository code.
