# `jeeb-migrate` — opt-in pre-start DB migrate (JEB-1490 generalized)

A composite action that applies an **idempotent** SQL migration to the **native host
Postgres** over the caller's already-established **cloudflared SSH** alias, **before**
`docker service update`, then runs a **readiness check that fails the deploy on an
absent column/table** (fail-closed). It generalizes the per-repo JEB-1490 ad-hoc psql
steps (`user-management`, `push-notification`) into one reusable, language-agnostic unit.

- **Opt-in.** No-op unless `run_migrations: 'true'`. Services with no schema omit it.
- **No app auto-migrate.** This is the *only* place migrations run. Keep `SKIP_DB_INIT=true`;
  never add `Database.Migrate()` / `Base.metadata.create_all()` to the app supervisor.
- **Fail-closed.** `ON_ERROR_STOP=1` + a post-migrate readiness assertion abort the deploy
  **before** the new image rolls — the old container keeps serving the old (additive-compatible)
  schema. Migrations MUST be expand-only/additive so image and schema roll back independently.
- **Secrets never inlined.** DB creds arrive as inputs (wired from `secrets.JEEB_DB_*`); the
  password is passed to the remote via env → `PGPASSWORD`, never on argv, never echoed. An unset
  required secret **fails the run** (no literal fallback).

## Why a composite action (not a `workflow_call`)

The migrate must run in the **same job** that wrote `~/.ssh/config` `Host jeeb`
(`ProxyCommand = cloudflared access ssh`). A reusable *workflow* runs on a separate
runner and could not see that in-job SSH/cloudflared config. So this slots **inside**
the existing single deploy job, between the SSH-setup step and `docker service update`.

## Two accepted migration shapes

| `migrations_path` resolves to | Behavior | Example repo |
|---|---|---|
| a single `.sql` **file** | applied once with `psql -f` | `user-management` → `Migrations/migrations.sql` |
| a **directory** of `*.sql` | applied in **sorted (lexical)** order | `push-notification` → `migrations/` |

## Usage (caller `deploy-to-jeeb.yml`, between SSH setup and deploy)

```yaml
# pin to a SHA (preferred) or a moving tag — NEVER @main
- name: Pre-start migrate (idempotent; fail-closed)
  uses: olivium-dev/shared-github-actions/actions/jeeb-migrate@<sha40>
  with:
    run_migrations: 'true'
    ssh_host_alias: jeeb                         # the alias your SSH-setup step wrote
    migrations_path: Migrations/migrations.sql   # file (UM) OR a dir of *.sql (PN: migrations)
    db_host:     ${{ secrets.JEEB_DB_HOST }}
    db_port:     ${{ secrets.JEEB_DB_PORT }}
    db_name:     ${{ inputs.db_name }}
    db_user:     ${{ secrets.JEEB_DB_USERNAME }}
    db_password: ${{ secrets.JEEB_DB_PASSWORD }}
    readiness_table:  Users                       # quoted-identifier table is fine (no quotes here)
    readiness_column: ActiveRole                  # FAIL the deploy if this column is absent post-migrate
```

A service that has nothing to migrate simply omits the step, or passes
`run_migrations: 'false'` — the action is a clean no-op.

## How the readiness check fails-fast

After applying the SQL, the action queries `information_schema`:
- if `readiness_column` is set → it asserts exactly one row in
  `information_schema.columns` for `(readiness_schema, readiness_table, readiness_column)`;
- otherwise → it asserts the table exists in `information_schema.tables`.

If the assertion fails (e.g. a migration silently didn't add the expected column), the
step prints `::error::READINESS FAILED …` and `exit 1` — the deploy aborts **before**
`docker service update`, so a drifted schema can never serve traffic. This is the
generalized form of the `Users.ActiveRole present? (expect 1)` check from the UM step.

## K1 (`jeeb-state-service`) — first schema deploy

`jeeb-state-service` (ADR-001-rev2, .NET 8) is **net-new**, so its first deploy *creates*
the `jeeb_state` schema (refresh-token families, KYC, ratings, disputes, idempotency keys,
…). It consumes this action verbatim:

```yaml
- uses: olivium-dev/shared-github-actions/actions/jeeb-migrate@<sha40>
  with:
    run_migrations: 'true'
    migrations_path: migrations          # checked-in idempotent CREATE TABLE IF NOT EXISTS / ADD COLUMN IF NOT EXISTS
    db_host:     ${{ secrets.JEEB_STATE_DB_HOST }}
    db_name:     jeeb_state
    db_user:     ${{ secrets.JEEB_STATE_DB_USERNAME }}
    db_password: ${{ secrets.JEEB_STATE_DB_PASSWORD }}
    readiness_table:  idempotency_keys   # asserts the keystone table exists after the first migrate
```

On the **first** deploy the rollback-marker query prints `(table … not present yet — fresh db)`,
the `CREATE TABLE IF NOT EXISTS` statements build the schema, and the readiness check proves
`idempotency_keys` exists before the service rolls — exactly the gate K1 needs for its first
schema deploy (depends on F2 having provisioned the `jeeb_state` database + least-priv role).
```
