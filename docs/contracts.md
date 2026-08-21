# Contract Lifecycle

## 1. Reviewed deployment config

`jeeb-ephemeral.json` identifies the 24 application services, exact source commits, credential-free test/build argv, runtime dependency graph, non-secret environment, Docker secret mounts, migrations, resource limits, and health endpoints.

Application health contracts are typed HTTP endpoints. The runtime generates their Docker health command with `/run/olivium/bin/http-probe`; arbitrary curl commands are not accepted. Reviewed native exec health commands are infrastructure-only.

## 2. Reviewed build intent

`jeeb-build-intent.json` uses `apiVersion: olivium.dev/build-intent/v1`. It binds:

- canonical deployment-config and catalog hashes;
- exact repository names and 40-character source commits;
- canonical build-input hashes;
- target GHCR repositories without tags or digests;
- digest-pinned infrastructure images; and
- the immutable static health-probe URL, SHA-256, byte size, amd64 architecture, and static-link assertion.

An application `image`, tag, or digest is prohibited here. This avoids requiring a build result before the build has happened.

## 3. Observed build artifact

Each credential-free build produces one OCI layout and records its observed manifest digest, broker archive hash, build-input hash, test/build transcript hashes, and provenance statement. It does not compare the new digest with a predeclared value.

## 4. Verified push receipt

The source-free push job accepts only the OCI archive and provenance metadata. It uploads the observed manifest to the reviewed GHCR repository and requires the registry digest to remain byte-for-byte equal to the artifact manifest digest. The receipt binds source archive, build input, OCI artifact, image manifest, and provenance digests.

## 5. Final deployment lock

After every push succeeds, `finalize-lock` requires the exact service receipt set and emits `olivium.dev/deployment-lock/v1`. The final lock freezes:

- all source and build-intent evidence;
- every application `repository@sha256` reference;
- OCI artifact and provenance digests;
- all infrastructure-image digests;
- the health-probe pin; and
- the GitHub run and reusable-workflow SHA that generated it.

The manager receives the canonical SHA-256 of this final lock. Runtime assembly and lease allocation reject build intent as deployment authority.
