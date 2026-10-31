# go-admin-server

Go backend for [react-admin-starter](https://github.com/braver-braver/react-admin-starter). It implements the frontend's `/api/v1` contract — cookie sessions, CSRF, RBAC with per-capability data scopes, dynamic navigation, system management, business users, uploads and audit logs — and is meant as a production base that further business modules are added to.

## Quick start

```bash
docker compose up -d db
export DATABASE_URL='postgres://admin:admin@localhost:5432/admin?sslmode=disable'
go run ./cmd/server seed-demo          # demo accounts, password Demo1234!
COOKIE_SECURE=false go run ./cmd/server
```

Demo accounts match the frontend mock: `admin@example.com`, `viewer@example.com`, `guest@example.com`. For a real installation skip `seed-demo` and set `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD` on first start; that creates the protected recovery administrator.

Serve the frontend and the API from one origin: route `/api/*` to this server and everything else to the frontend's `index.html` (see the frontend's `docs/auth-and-api.md`).

| Command | Does |
| --- | --- |
| `server` | Migrate (unless `MIGRATE_ON_START=false`), bootstrap the administrator if configured, serve |
| `server migrate` | Apply migrations and exit |
| `server seed-demo` | Demo configuration and 120 business users; empty database only |

Configuration is environment variables only; see [.env.example](.env.example). PostgreSQL must be built with ICU (official images are): business lists sort with a `zh-Hans-CN` collation, like the mock.

## Layout

```
cmd/server            entry point, configuration, graceful shutdown
internal/authz        authorization kernel: pure functions, no I/O
internal/store        PostgreSQL (pgx) and embedded goose migrations
internal/httpapi      routes, guards, handlers and the contract tests
internal/auth         argon2id passwords, session tokens
internal/apierr       the { error: { code, message } } type
api/openapi.yaml      contract copy the tests validate against
```

## Design

| Topic | Choice |
| --- | --- |
| HTTP | Standard `net/http` routing. The route table mirrors the frontend's `operations.ts`; a test checks it against `api/openapi.yaml` both ways |
| Check order | `X-Requested-With` → Origin → session → capability → CSRF → body, exactly as the contract and mock define it |
| Database | PostgreSQL with pgx; migrations embedded and applied on start |
| Sessions | Server-side, only the SHA-256 of the cookie token is stored; `HttpOnly; SameSite=Lax; Secure`; rotated on login, deleted on logout |
| Revocation | Every request recomputes the principal from the live configuration. A password reset, disabling or re-enabling bumps the account's `credential_version`, which invalidates its sessions |
| Passwords | argon2id (64 MiB, t=2); unknown emails cost the same time as wrong passwords |
| Authorization | `internal/authz`, a rule-for-rule port of the mock (`src/mocks/data/system.ts`) |
| System writes | One transaction under an advisory lock: load the configuration, `authz.Apply`, write the diff, bump `system_state.revision`, append the audit record |
| Config cache | Each server caches the configuration until `system_state.revision` changes, which is safe across instances |
| Lists | Data scope, filters and search apply in SQL before counting, sorting and paging |
| Batches | Rows are locked and checked together; one out-of-scope id rejects the whole batch |

### Authorization kernel

- `Snapshot.Principal(id)` computes capabilities, per-capability `dataScopes`, routes and the summary scope. Disabled accounts, roles and departments (including disabled ancestors) grant nothing.
- Data scopes are unioned only across roles that grant the same capability: read-all plus write-self never becomes write-all.
- `Principal.CanAccess` checks one record; `Principal.Filter` turns the same scope into a SQL row filter.
- `Apply` validates strict bodies, references, hierarchy, protected records, unique codes and emails, and delegation limits: for the actor, for every account holding a changed role, and for indirect widening through department moves.

Intentional difference from the mock: an updated system record keeps its list position instead of moving to the end.

## Tests

```bash
go test ./...                                    # kernel only
TEST_DATABASE_URL='postgres://postgres@localhost:5432/postgres?sslmode=disable' go test ./...
```

With `TEST_DATABASE_URL` (a role that may create databases), every test gets its own database cloned from a seeded template. The HTTP tests check every response: the `{data}` / `{error}` envelope, `Cache-Control: no-store`, success bodies against `api/openapi.yaml`, and each error code against the frontend's error table. They cover login and rotation, CSRF and header checks, cross-site origins, rate limiting, server-side paging and clamping, scoped lists and atomic batches, live revocation after role, password and status changes, serialized concurrent writes and uploads.

The frontend's own Playwright suites (`app.e2e.ts`, `system.e2e.ts`) also pass against this server behind a same-origin proxy. They assume a fresh mock per test, so against a persistent database each test needs a freshly seeded one.

## Additions beyond the contract

These should be added to the frontend contract:

| Addition | Why |
| --- | --- |
| `429 RATE_LIMITED` on login | Login throttling per IP and per email |
| `500 INTERNAL` | Unexpected failures, without internal details |
| `403 FORBIDDEN` for a disallowed `Origin` / `Sec-Fetch-Site: cross-site` | CSRF defence in depth for writes |
| `GET /api/v1/uploads/{id}` (needs `users:read`) | Uploads return a persistent URL, as the contract asks of real servers |
| Uploads accept PNG, JPEG, GIF and WebP only, by content sniffing | SVG is an `image/*` type but can carry script on the API origin |
