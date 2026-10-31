# react-admin-starter-server

Go backend for [react-admin-starter](https://github.com/braver-braver/react-admin-starter). It implements the frontend's `/api/v1` contract (`docs/api.openapi.yaml`) and is intended as a production base: further business modules are added here.

> Status: the authorization kernel (`internal/authz`) is implemented and tested. The HTTP layer, PostgreSQL storage and migrations are next.

## Decisions

| Topic | Choice | Why |
| --- | --- | --- |
| Repository | Separate from the frontend | The frontend stays backend-agnostic (its AGENTS.md); this repo pins a contract version |
| HTTP | `net/http` (Go 1.22+ routing) + oapi-codegen strict server | Contract drift becomes a compile error; the `{data}` / `{error}` envelope and exact statuses need no framework workarounds |
| Database | PostgreSQL, pgx/v5, sqlc, goose migrations | Type-safe queries; recursive CTEs for the department tree |
| Sessions | Server-side sessions in PostgreSQL (token hash only), `HttpOnly; Secure; SameSite=Lax` | Rotation on login, revocation via `credential_version`; no Redis |
| Other clients | Cookie sessions only for now | The session layer leaves room for opaque bearer tokens later, sharing the session table and authorization |
| Passwords | argon2id | — |
| Authorization | Hand-written pure kernel, no Casbin | Per-capability data scopes and delegation limits do not fit a generic policy engine |

## Authorization kernel

`internal/authz` is a rule-for-rule port of the reference mock (`src/mocks/data/system.ts`):

- `Snapshot.Principal(id)` computes an account's capabilities, per-capability `dataScopes`, routes and summary scope from the live configuration. Disabled accounts, roles and departments (including disabled ancestors) grant nothing.
- Data scopes are unioned only across roles that grant the same capability: read-all plus write-self never becomes write-all.
- `Principal.CanAccess` checks one record; `Principal.Filter` gives the same scope as a row filter, so lists filter in SQL before sorting, paging and counting.
- `Apply(snapshot, change)` validates a system-management write (strict bodies, references, hierarchy, protected records, unique codes and emails, delegation limits for the actor, every affected assignee and indirect widening through department moves) and returns the configuration after it. Callers serialize `Apply` (a transaction-scoped advisory lock), exactly like the mock's write queue.

Intentional difference from the mock: an updated record keeps its position in list order instead of moving to the end.

## Development

```bash
go test ./...
```
