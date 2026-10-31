# Engineering guidelines

## Purpose

Go backend for [react-admin-starter](https://github.com/braver-braver/react-admin-starter): it implements that frontend's `/api/v1` contract and is the base that business modules are built on. The frontend's contract (`src/contract/`, `docs/api.openapi.yaml`, `docs/auth-and-api.md`, `docs/system-management.md`) is the specification; where this repo and the frontend's reference mock disagree, the mock's behaviour wins unless README lists the difference.

## Architecture rules

- Layers: `authz` (pure kernel, no I/O) ← `store` (PostgreSQL) ← `httpx` (module toolkit) ← `modules/*` and `httpapi` (platform operations, guards) ← `cmd/server`. Do not import upward.
- Business features are modules (`docs/modules.md`). The platform packages must not know any module's tables or capabilities.
- Guards are declarative: an `httpx.Op` names its capability; handlers never re-check session, permission or CSRF. Handlers do check data scope.
- Authorization is computed per capability. Never merge scopes across capabilities, never trust anything the client sends about roles, departments or routes, and recompute the principal from the live configuration on every request.
- Lists filter by scope and query in SQL before counting, sorting and paging. Batches lock and check every row and reject all-or-nothing.
- Every write that changes data appends its audit record in the same transaction. Never write passwords, hashes, tokens or CSRF values to audit records or logs.
- System-configuration changes go through `authz.Apply` under the store's advisory lock; never write the system tables directly.
- Response envelope `{data}` / `{error:{code,message}}`, correct status codes, Chinese messages that can be shown to users. Error codes come from the frontend's error table; propose new codes there.
- Prefer the standard library. Add a dependency only when it removes real complexity, and say why in the commit.
- Migrations are append-only. Core migrations use sequential versions; modules use timestamp versions.

## Contract changes

A change to any request, response, status or error code is a contract change: update the frontend's `src/contract/` and `docs/api.openapi.yaml` in the same piece of work, and copy the OpenAPI document to `api/openapi.yaml` here. After v1.0, breaking changes need `/api/v2`.

## Development practice

- Run before every commit: `gofmt -l .` (empty), `go vet ./...`, `go test -race ./...` with `TEST_DATABASE_URL` set. CI does the same.
- New behaviour needs a test at the HTTP level (`internal/httpapi`) and, for authorization rules, in `internal/authz`. Port the corresponding frontend mock test when one exists.
- Conventional Commits; keep changes focused and reviewable.
- Document decisions and deviations from the mock in README; document module conventions in `docs/modules.md`.
- Never commit secrets, real credentials or production data. Demo credentials exist only in `seed-demo`.
