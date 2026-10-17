# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository. `AGENTS.md` has the same content for other coding agents; keep the two in sync.

## Project overview

PasteVault is an end-to-end encrypted paste and file sharing app with an agent-ready CLI. The repository holds:

- **Server** (`src/`): a Fastify REST API (TypeScript) with accounts (better-auth), API tokens, agent identities, sealed shares, secret requests and an audit log. Prisma with SQLite (default) or PostgreSQL.
- **Web app** (`frontend/`): Next.js 16 (App Router, React 19) with the Monaco editor and all client-side crypto.
- **npm launcher** (`src/cli.ts`, published as `pastevault`): `npx pastevault up` serves the API and the web app together.
- **Native CLI** (`cmd/pastevault`, Go): `pastevault put/get`, account commands, agent keys, secret requests, the local secret store, `run`/`inject`, and the MCP server (`pastevault mcp`).
- **Agent integrations** (`integrations/`, `.claude-plugin/`): the Claude Code plugin and marketplace, Codex and Gemini packaging, and the agent skill.

Docs: `docs/cli-reference.md` (every CLI command, JSON shape and exit code), `docs/agents.md` (agents and MCP setup), `docs/security-model.md` (threat model), `docs/distribution.md` (releases).

## Commands

### Server (repo root)
- `npm run dev`: API in watch mode (port 3001)
- `npm run build`: compile TypeScript to `dist/`
- `npm run typecheck`, `npm run lint`

### Web app
- `cd frontend && npm run dev`: dev server (port 3002)
- `cd frontend && npm run build`
- `cd frontend && npm run typecheck`, `cd frontend && npm run lint`

### Full build and launcher
- `npm run build:cli`: build the server and the web app (needed before e2e tests)
- `npx pastevault up [--port 3000 --host 0.0.0.0]`, or `node dist/cli.js up` after a build

### Database
- `npm run db:push`, `npm run db:migrate`, `npm run db:generate`

### Go CLI
- `go build -o pastevault ./cmd/pastevault`
- `go test ./cmd/... ./internal/...`, `go vet ./cmd/... ./internal/...`, `gofmt -l cmd internal`
- Golden files: `go test ./cmd/pastevault -update` and `go test ./internal/mcpserver -run TestToolListMatchesGolden -update`

### Tests
- `npm run test:crypto`: crypto vectors (`testdata/crypto/vectors.json`) checked against the web code, Go and the TS tests
- `npm run test:e2e`: builds, then runs every `tests/e2e-*.mjs` suite against a real server (Go CLI included); `node tests/run-e2e.mjs mcp agents` runs a subset. `E2E_POSTGRES_URL=postgres://… ` enables Postgres for suites that support it.
- `E2E_POSTGRES_URL=… node tests/check-postgres-migrations.mjs`: migrations match `schema.postgres.prisma`
- `node scripts/check-integrations.mjs`: plugin/extension manifests, skill frontmatter and version sync
- CI runs all of these (`.github/workflows/e2e.yml`, `test-cli.yml`).

## Architecture

### Server (`src/`)
- Entry points: `src/index.ts` (API only) and `src/cli.ts` (launcher serving the API and the built web app). Both register routes through `src/routes/register.ts`; add new route plugins there.
- Routes: `pastes.ts`, `file-shares.ts` (also `/api/capabilities`), `account.ts` (owned shares, events, audit), `tokens.ts` (`/me`, API tokens), `agents.ts`, `secret-requests.ts`, `auth.ts` (better-auth proxy).
- Auth: `src/lib/principal.ts` resolves a session or a `pv_pat_` API token into a principal with scopes (`requirePrincipal`, `requireSession`); never resolve sessions another way (it carries the CSRF origin check).
- Libraries: `audit.ts`, `agents.ts`, `api-tokens.ts`, `secret-requests.ts`, `account-shares.ts`, `pastes-db.ts`, `file-shares-db.ts`, `account-schema.ts` (startup DDL), `schema-utils.ts`, `cleanup.ts` (cron: expiry, audit retention, request wipes), `config.ts` (zod-validated env), `validation.ts` (zod schemas, `HttpError`), `origins.ts` (CORS and trusted origins).

### Web app (`frontend/src/`)
- Pages: `/` (editor, share to agent), `/p/[slug]`, `/f/[slug]`, `/r/[code]` (answer a secret request), `/account`, `/device` (CLI login approval).
- Crypto: `lib/crypto.ts` (pastes), `lib/file-shares.ts` (chunks, manifests), `lib/wrap.ts` (PVWRAP1 key wrap), `lib/fingerprint.ts`, `lib/pins.ts` (browser key pins). `wrap.ts` and `fingerprint.ts` must not use `@/` imports (loaded by `tsx --test`).
- Radix UI + Tailwind CSS 4 + shadcn/ui patterns, React Query, next-intl (six locales in `frontend/messages/`; add every string to all of them).

### Go (`cmd/pastevault`, `internal/`)
- `cmd/pastevault`: one file per command group (`cmd_put.go`, `cmd_get.go`, `cmd_agent.go`, `cmd_request.go`, `cmd_run.go`, `cmd_mcp.go`, ...); `cli.go` holds dispatch, `--json` output and exit-code mapping.
- `internal/pastevault`: API client, crypto, PVWRAP1, fingerprints, agent identities and pins, handles, dotenv, request payloads, errors and exit codes.
- `internal/secrets` (request flows, handle resolution), `internal/store` (local secret store), `internal/envmask` (output masking for `run`), `internal/mcpserver` (MCP tools over the in-process CLI), `internal/update` (signed self-update).

### Database (`prisma/`)
Models: `Paste`, `FileShare`, `OwnedShare`, `ApiToken`, `AgentIdentity`, `SecretRequest`, `AuditEvent`, plus the better-auth tables (`User`, `Session`, `Account`, `Verification`) and `DeviceCode`. Every schema change goes into all three schema files (`schema.prisma`, `schema.sqlite.prisma`, `schema.postgres.prisma`), the startup DDL (`account-schema.ts`, `pastes-db.ts`, `file-shares-db.ts`) and a Postgres migration. Create rows through the Prisma model API.

### Encryption
- XChaCha20-Poly1305 with a random 32-byte key; the key lives in the link fragment `#k=` and never reaches the server. AAD binds the slug and version (`pastevault:<slug>:v1`).
- Password mode: PBKDF2-SHA256, 600,000 iterations, server-stored salt.
- Sealed shares and secret requests: PVWRAP1 (X25519, HKDF-SHA256, XChaCha20-Poly1305 key wrap with context and recipient fingerprint in the AAD). Fingerprints are `pvk1_…`.
- Formats and vectors: `docs/cli-reference.md#formats-and-test-vectors`; any crypto change must keep `npm run test:crypto` green.

## Configuration

Server environment (see `src/lib/config.ts`):

```env
DATABASE_URL=file:./pastevault.db        # or a postgresql:// URL
DATABASE_PROVIDER=sqlite                  # or postgresql
PORT=3001
CORS_ORIGIN=http://localhost:3000
DISABLE_AUTH=false                        # true: no accounts, tokens, agents, requests or audit
DISABLE_SIGNUP=false
TRUST_PROXY=false                         # true, hop count, or IP/CIDR list
RATE_LIMIT_MAX=2000
RATE_LIMIT_WINDOW_MS=60000
MAX_PASTE_SIZE_BYTES=1048576
CLEANUP_INTERVAL_MINUTES=60
AUDIT_IP_MODE=off                         # or truncated
AUDIT_RETENTION_DAYS=90
SECRET_REQUEST_MIN_TTL_SECONDS=60
MAX_SECRET_REQUEST_BYTES=                 # default MAX_PASTE_SIZE_BYTES
```

Web app: `NEXT_PUBLIC_API_URL=http://localhost:3001/api` (include `/api`).

CLI: `PASTEVAULT_SERVER`, `PASTEVAULT_PUBLIC_URL`, `PASTEVAULT_TOKEN`, `PASTEVAULT_CONFIG_DIR`, `PASTEVAULT_AGENT`, `PASTEVAULT_AGENT_KEY`, `PASTEVAULT_JSON` (see the CLI reference).

## Development workflow

1. `npm ci && (cd frontend && npm ci)`, then `npm run db:push` for a local SQLite database.
2. `npm run dev` and `cd frontend && npm run dev`, or `npm run build:cli && node dist/cli.js up`.
3. Before finishing: typecheck and lint (root and `frontend`), `gofmt`/`go vet`/`go test` for Go changes, `npm run test:crypto` for crypto changes, and the relevant e2e suites.
4. Secret handling rules: never log keys, tokens, passwords or secret values; CLI error messages must not contain them; files with secret content are written `0600`.

## Deployment

- npm package: `npm run prepublishOnly` (builds the server and web app).
- Docker: `docker-compose.all.yml`.
- Native CLI: GoReleaser on GitHub releases (`docs/distribution.md`).
