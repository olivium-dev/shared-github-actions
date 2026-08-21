# Owner-Gated Prerequisites

Full deployment intentionally remains disabled until owners complete every item below.

1. **Shared workflow release**: Create `olivium-dev/shared-github-actions`, protect its default branch, commit this tree, review one commit, and use that exact SHA in the caller and manager workflow allowlist. Grant caller repositories Actions access to the reusable workflow.
2. **Protected caller environment**: Create `jeeb-ephemeral` with required reviewers, protected-branch restrictions, and no self-approval. The caller ref must produce GitHub OIDC `ref_protected=true`.
3. **Manager OIDC policy**: Pin organization owner ID, caller repository name/ID, environment, audience, GitHub-hosted runner, reusable-workflow ref, and reusable-workflow SHA. Keep one-time `jti` replay rejection enabled.
4. **Manager capabilities**: The capability endpoint must prove strict Proxmox host-key pinning, template/profile/capacity checks, scoped Cloudflare Tunnel/DNS/Access permissions, allowed zone, and a working short-lived Access-grant provider. Capability mode can validate this before the GitHub App exists.
5. **GitHub App broker**: Install a dedicated App with read-only Contents access to exactly the 24 reviewed source repositories. Implement the documented archive API without returning installation tokens, credentials, redirects, or links.
6. **GHCR grants**: Link every target package beneath the caller repository prefix and grant its `GITHUB_TOKEN` read/write package access. Publish a broker-verified `packageGrantSetSha256` covering the exact package/repository IDs.
7. **Reviewed contracts**: Commit and protect the canonical 24-service config and pre-build intent. Resolve catalog duplication first. Every source must use a full commit SHA and a reviewed credential-free test/build recipe.
8. **Static health probe**: Publish an immutable, static amd64 HTTP probe implementing the reviewed CLI. Record exact URL, SHA-256, and byte size at or below 500,000 bytes. Review its provenance and license.
9. **Guest profile**: Certify a clean single-node Swarm, pinned Docker package/daemon settings, regenerated SSH host keys, ephemeral authorized key replacement, IPv4/IPv6 firewalling, and no foreign services. Provide a loopback-only TLS registry with a pinned CA trusted by Docker.
10. **Runtime contract**: Supply all digest-pinned infrastructure images, exact service aliases, native readiness endpoints, resource limits, non-secret environment, secret file adapters, database bootstrap, migration order, gateway routes, and rollback behavior.
11. **Ephemeral secrets**: Populate only the explicitly named `JEEB_RUNTIME_SECRETS_JSON` environment secret. Values must be sandbox/ephemeral credentials, exactly match `runtime.secrets`, and never contain staging or production credentials.
12. **Cleanup acceptance**: Independently prove pre-active abort, heartbeat expiry, TTL expiry, and absence of VM, DNS, tunnel, connector, Access grant, manager key/state, and endpoints after cleanup.

## Current Blocking State

- The GitHub App source grants and broker are not provisioned.
- Cross-package GHCR grants and their evidence hash are not provisioned.
- The reviewed static health-probe release is not supplied.
- The canonical 24-service config/build intent and runtime secret map are not supplied in the deployment repository.
- The manager Access-grant provider and live exact-SHA OIDC allowlist still require owner deployment/approval.
- The guest profile still requires certification for the loopback TLS registry and full runtime contract.

Until these are complete, full deploy mode fails before lease allocation. Capability-only mode requires only items 1-4 and performs no external mutation beyond the read-only capability request.
