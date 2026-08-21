# Reusable Workflow Usage

Replace `<FULL_SHARED_ACTIONS_SHA>` with one reviewed 40-character commit SHA. The `uses` ref, `shared_actions_sha`, `expected_job_workflow_ref`, and manager allowlist must identify that same commit.

## Capability-only proof

This path checks the exact protected OIDC identity and calls only manager `GET /api/automation/v1/capabilities` for the approved zone. It performs no application source resolution, build, package write, or lease allocation.

```yaml
name: Prove ephemeral manager capabilities

on:
  workflow_dispatch:

permissions: {}

jobs:
  prove:
    permissions:
      contents: read
      id-token: write
    uses: olivium-dev/shared-github-actions/.github/workflows/deploy-jeeb-ephemeral.yml@<FULL_SHARED_ACTIONS_SHA>
    with:
      operation: capability
      shared_actions_sha: <FULL_SHARED_ACTIONS_SHA>
      expected_job_workflow_ref: olivium-dev/shared-github-actions/.github/workflows/deploy-jeeb-ephemeral.yml@<FULL_SHARED_ACTIONS_SHA>
      environment: jeeb-ephemeral
      manager_url: https://ephemeral.fds-8.space
      manager_audience: olivium-ephemeral-manager
      zone: fds-8.space
```

Success returns `capability_ok=true`. The manager independently rejects the wrong owner/repository IDs, environment, protected-ref status, workflow ref, workflow SHA, audience, runner type, or replayed token.

## Full deployment

```yaml
name: Deploy Jeeb ephemeral

on:
  workflow_dispatch:

permissions: {}

jobs:
  deploy:
    permissions:
      contents: read
      id-token: write
      packages: write
    uses: olivium-dev/shared-github-actions/.github/workflows/deploy-jeeb-ephemeral.yml@<FULL_SHARED_ACTIONS_SHA>
    with:
      operation: deploy
      shared_actions_sha: <FULL_SHARED_ACTIONS_SHA>
      expected_job_workflow_ref: olivium-dev/shared-github-actions/.github/workflows/deploy-jeeb-ephemeral.yml@<FULL_SHARED_ACTIONS_SHA>
      environment: jeeb-ephemeral
      manager_url: https://ephemeral.fds-8.space
      manager_audience: olivium-ephemeral-manager
      zone: fds-8.space
      config_path: jeeb-ephemeral.json
      build_intent_path: jeeb-build-intent.json
      source_broker_url: https://ephemeral.fds-8.space/source-broker
      source_broker_audience: olivium-source-broker
      registry_prefix: ghcr.io/olivium-dev/jeeb-ephemeral-deploy
      package_grant_set_sha256: <64-lowercase-hex>
      cloudflared_version: <exact-release>
      cloudflared_sha256: <64-lowercase-hex>
      health_probe_url: <immutable-https-url>
      health_probe_sha256: <64-lowercase-hex>
      health_probe_size: <exact-bytes-at-most-500000>
      enable_deployment: true
      github_app_grants_ready: true
      package_grants_ready: true
      manager_oidc_ready: true
      cloudflare_access_ready: true
    secrets:
      runtime_secrets_json: ${{ secrets.JEEB_RUNTIME_SECRETS_JSON }}
```

Do not use `secrets: inherit`. All four readiness booleans are necessary but not sufficient: the manager and source-broker preflights must independently prove the corresponding capabilities before work continues.
