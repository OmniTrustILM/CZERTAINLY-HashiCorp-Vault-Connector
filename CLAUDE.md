# CLAUDE.md

Guidance for agents working in this repository.

## Repo map

| Path                     | Purpose                                                                                   |
|--------------------------|--------------------------------------------------------------------------------------------|
| `cmd`                    | Entry point (`main.go`): loads config, connects to Postgres via GORM, creates/selects the schema, runs migrations, wires the authority, discovery, health, and connector-info controllers plus the secret provider's own router, and starts the HTTP server. |
| `internal/config`        | Environment-variable contract: `Config` and `Get()`.                                       |
| `internal/vault`         | Vault HTTP client and login methods (AppRole, Kubernetes, JWT/OIDC) used by the authority and discovery providers. |
| `internal/authority`     | Authority Provider (`/v1` and `/v2` `authorityProvider`): certificate issuance, renewal, revocation, identification, and CA/CRL download. 1,932 LOC excluding tests — one of the two largest packages in the repo. |
| `internal/discovery`     | Discovery Provider (`/v1/discoveryProvider`): scans a Vault instance's PKI mounts for certificates. |
| `internal/secret`        | Secret Provider (`/v1/secretProvider`, a v2 interface): reads, writes, and manages Vault KV secrets, with its own `vault/` client subpackage and `model/` DTOs. 5,745 LOC — the largest package in the repo. |
| `internal/db`            | GORM Postgres connection setup, auto-migration, and the authority-instance/discovery repositories. |
| `internal/health`        | Health-check API.                                                                          |
| `internal/connectorInfo` | Connector info API (function groups, kinds, and endpoint introspection).                   |
| `internal/metrics`       | Prometheus request-count/duration middleware.                                              |
| `internal/model`         | Generated OpenAPI model DTOs and router plumbing shared by all three providers.             |
| `internal/logger`        | zap logger singleton; level driven by `LOG_LEVEL`.                                          |
| `internal/utils`         | Small shared helpers.                                                                       |
| `migrations`             | SQL migration files consumed by `golang-migrate` (`file://migrations`): `authority_instances`, `certificates`, `discoveries`, `discovery_certificates`. |
| `api/connector-api`      | OpenAPI specs that `internal/model` is generated from (see `generate.sh`).                  |

## Commands

- Build: `go build ./...`
- Unit tests: `go test -race ./...` — this repository has no `test/integration` suite or testcontainers harness; all tests run under this one command.
- Run a single test: `go test -run TestName ./internal/authority/`
- Format check: `gofmt -l .` (no output means the tree is clean)
- Vet: `go vet ./...`
- Lint: `golangci-lint run --timeout=5m` (config in `.golangci.yml`, v2 format). The checkstyle output formatter writes `golangci-lint-report.xml`, which the Sonar workflows consume — treat a missing report file as a failure, since Sonar would otherwise silently report zero lint issues.
- govulncheck: `go tool govulncheck ./...` (version pinned via the `tool` directive in `go.mod`, verified by `go.sum`).
- Local Sonar analysis: `./scripts/sonar-local.sh` — requires `SONAR_TOKEN` in the environment; runs `go test -race` with coverage and `golangci-lint` first, then `sonar-scanner` against SonarCloud with the quality gate set to block.
- Code generation: `./generate.sh` regenerates `internal/model` from the OpenAPI specs under `api/connector-api`.
- Docker image: `docker build --build-arg VERSION=<version> -t hashicorp-vault-connector .` — stamps `main.version`; there is no `COMMIT` build arg.

Run every command above from the repo root before considering a change done.

## Architecture

This is an **ILM framework connector** for HashiCorp Vault. It exposes REST APIs that the ILM platform calls to manage certificates (PKI secrets engine) and secrets (KV) in Vault.

### Providers

Three function groups are implemented (all labeled `HVault`):

- **Authority Provider** (`/v1/authorityProvider/*`, `/v2/authorityProvider/*`) — issue, renew, revoke, and identify certificates; download CA certificates and CRLs.
- **Discovery Provider** (`/v1/discoveryProvider/*`) — discover certificates stored in Vault instances.
- **Secret Provider** (`/v1/secretProvider/*`, a v2 interface) — read, write, and manage Vault KV secrets.

### Request flow

`cmd/main.go` wires together all services and controllers → Gorilla Mux router with correlation-ID and metrics middleware → service layer → `internal/vault` (authority/discovery) or `internal/secret/vault` (secret provider) → HashiCorp Vault API.

### Database

PostgreSQL (≥12) with schema `hvault` (configurable via `DATABASE_SCHEMA`). Tables: `authority_instances`, `certificates`, `discoveries`, `discovery_certificates`. Migrations live in `migrations/` and run automatically at startup via `golang-migrate`.

### Vault authentication

AppRole (RoleID + SecretID), Kubernetes service account token, and JWT/OIDC are all supported — selected per authority instance via connector attributes.

## Conventions

- Every third-party GitHub Action reference is pinned to a full commit SHA
  with the human-readable version as a trailing comment, e.g.
  `owner/action@<full-sha> # vX.Y.Z`. Never reference a third-party action
  by a mutable tag or branch. Org-internal `OmniTrustILM/.github` reusable
  workflows and composite actions are the deliberate exception: they stay on
  the org's release tags or `@main` (org-controlled, kept in sync by the
  org's template-sync process).
- Renovate is the only dependency bot for this repository. It is configured
  org-wide in `OmniTrustILM/.github/renovate.json`. This repository
  deliberately carries no `.github/dependabot.yml`: running both bots opens
  a duplicate pull request for every single update. Don't add one back.
  Dependabot *security* updates are a repository security setting rather
  than a config file, so they are unaffected by that choice.
- `SERVER_PORT`, `LOG_LEVEL`, `DATABASE_HOST`, `DATABASE_PORT`,
  `DATABASE_NAME`, `DATABASE_USER`, `DATABASE_PASSWORD`, `DATABASE_SCHEMA`,
  `DATABASE_SSL_MODE`, and `DATABASE_PROPS` are a frozen deployment contract
  read by `internal/config`. Never rename, remove, or repurpose one; add a
  new variable instead.
- `internal/model` is generated from the OpenAPI specs under
  `api/connector-api` (regenerate via `generate.sh`) — don't hand-edit its
  files directly. It's excluded from Sonar *coverage* but not from
  *analysis*: it's generated, but edited by hand often enough that its
  smells are still worth seeing.
- Commit messages are one plain, descriptive line. No co-author trailers
  and no mention of AI assistance or tooling.

## Quality gates

A change is not done until all of these pass:

- **SonarCloud** — `sonar.yml` and `sonar_push.yml` run with
  `sonar.qualitygate.wait=true`, so a failing gate fails the check.
  Coverage, duplication, and new-issue thresholds are whatever quality gate
  is assigned to this project on SonarCloud; check the project directly
  rather than assuming another repository's numbers apply here.
- **CodeQL** (`codeql.yml`) — `go` and `actions` language analysis, no new
  findings.
- **govulncheck** (`go tool govulncheck ./...`, version pinned via the
  go.mod tool directive) — no known vulnerabilities in the module or its
  dependencies.
- **Dependency review** — no newly introduced dependency with a `high`+
  severity advisory.
- **golangci-lint** (`golangci-lint run --timeout=5m`) — zero issues
  against this repo's `.golangci.yml`.

## Local-only paths

These may exist in a checkout but must never be committed (covered by
`.gitignore`):

- `.idea/` — JetBrains IDE project files.
- `.mirrord/` — local mirrord configuration for running against a shared
  cluster.
- `.worktrees/` — local git worktrees.

Check `git status` before staging and make sure none of these are included.
