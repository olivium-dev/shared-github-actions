# Jeeb Ephemeral Reusable Workflow

This directory is a standalone candidate for `olivium-dev/shared-github-actions`. Its currently enabled reusable path:

- proves the protected GitHub OIDC identity and manager Cloudflare/Proxmox capabilities without allocating anything.

The workflow is [deploy-jeeb-ephemeral.yml](.github/workflows/deploy-jeeb-ephemeral.yml). Full deployment remains deliberately refused while the canonical v3 build/runtime path is unified and live-certified. The trusted manager origin and OIDC audience are fixed in this repository; callers cannot redirect bearer tokens to another host.

## Trust Boundaries

- Reviewed `config.json` and `build-intent.json` contain exact source commits and build instructions, but no fabricated application image digests.
- The planned GitHub App broker returns exact source archives, never installation tokens.
- Untrusted test/build jobs receive no repository permissions, OIDC token, runtime secrets, GHCR token, or Cloudflare credentials.
- Separate source-free jobs push each observed OCI digest with only the current repository `GITHUB_TOKEN` and `packages: write`.
- A trusted finalizer freezes those verified push receipts into `deployment-lock.json` before lease allocation.
- Only protected, exact-identity lifecycle jobs can mint OIDC. OIDC request variables are removed from SSH subprocess environments.
- The disabled full path is being hardened to use an ephemeral Ed25519 key, manager-supplied Ed25519 host pin, strict host checking, and a short-lived manager-issued Cloudflare Access grant.
- Runtime secrets and GHCR credentials travel only through process environment/stdin and are never written to workflow artifacts.
- All application health checks use the pinned static HTTP probe mounted `0555`; service images do not need `curl`.

## Offline Verification

```bash
python3 -m unittest discover -s shared-actions/tests -p 'test_*.py' -v
python3 shared-actions/scripts/workflow_policy.py \
  shared-actions/.github/workflows/deploy-jeeb-ephemeral.yml
python3 -m py_compile shared-actions/scripts/*.py shared-actions/tests/*.py
```

These checks use a loopback fake manager and perform no GitHub, Cloudflare, Proxmox, GHCR, Docker, or SSH mutations.

## Documentation

- [Workflow usage](docs/deploy-jeeb-ephemeral.md)
- [Owner-gated prerequisites](docs/owner-gates.md)
- [Source broker API](docs/source-broker-contract.md)
- [Contract lifecycle](docs/contracts.md)
