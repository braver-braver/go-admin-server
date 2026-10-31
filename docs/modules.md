# Adding a business module

A module is a Go package under `internal/modules/<name>` that implements `httpx.Module`. The platform gives it authentication, CSRF, capability checks, data scopes, audit, migrations and installation; the module supplies its tables, queries and handlers.

`internal/modules/users` is the complete CRUD example; `internal/modules/tickets` adds a workflow (status machine, assignment, timeline) and records with two owners (creator and assignee, via `store.ScopeSQLAny`). `internal/httpapi/module_test.go` contains a ~60-line module (`notes`) that shows the minimum.

## 1. Name the capabilities and pages

```go
func (m *Module) Catalog() authz.Catalog {
	return authz.Catalog{
		Capabilities: []authz.Capability{
			{Code: "orders:read", Method: "GET", Path: "/api/v1/orders", Name: "查看订单"},
			{Code: "orders:write", Method: "POST / PUT / DELETE", Path: "/api/v1/orders/*", Name: "维护订单"},
		},
		Routes: []authz.Route{
			{ID: "orders", Path: "/orders", Name: "订单管理", Permission: "orders:read", Menu: authz.MenuBusiness},
		},
	}
}
```

- Capability codes are `<resource>:<action>`, lower case, matching `^[a-z][a-z0-9:_-]{1,79}$`. Use `read` and `write` unless an action needs its own grant (e.g. `orders:approve`).
- Each route `ID` must equal the route id the frontend registers in `src/features/system/catalog.ts`; `Path` is the frontend path. `Permission` is the capability needed to open the page.
- On start the server adds missing capabilities as protected permission records and missing pages as enabled menus in `Menu` (default directory). Only the super administrator gets them; administrators grant them to roles in 系统管理. Removing a capability from code never deletes data.
- Duplicate codes or ids across modules panic at start.

## 2. Write the migration

`internal/modules/<name>/migrations/<timestamp>_<name>.sql`, a goose file with a **timestamp version** (`20261105093000_orders.sql`) so versions never collide with other modules:

```sql
-- +goose Up
CREATE TABLE orders (
    id            text PRIMARY KEY,
    department_id text NOT NULL REFERENCES departments (id) ON DELETE RESTRICT,
    created_by    text NOT NULL,   -- account id: the "self" data scope
    ...
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX orders_department_idx ON orders (department_id);
CREATE INDEX orders_created_by_idx ON orders (created_by);
-- +goose Down
DROP TABLE orders;
```

Records that data scopes apply to need `department_id` and `created_by`. Expose the directory with `//go:embed migrations/*.sql` and return it from `Migrations()`. Never edit a migration after it has shipped; add a new one.

## 3. Declare the operations

```go
func (m *Module) Operations() []httpx.Op {
	return []httpx.Op{
		{Method: "GET", Path: "/orders", ID: "listOrders", Permission: "orders:read", Handle: m.list},
		{Method: "POST", Path: "/orders", ID: "createOrder", Permission: "orders:write", Handle: m.create},
		{Method: "PUT", Path: "/orders/{id}", ID: "updateOrder", Permission: "orders:write", Handle: m.update},
	}
}
```

Before `Handle` runs, the server has checked, in the contract's order: `X-Requested-With` and Origin for writes, the session, `Permission`, and the CSRF token for writes. A handler never repeats these checks; it does check **data scope**, which depends on the record.

`ID` is the operationId the operation will have in the frontend's OpenAPI contract. Add each operation to the frontend contract (`src/contract/operations.ts`) in the same change.

## 4. Write the handlers

```go
func (m *Module) list(c *httpx.Ctx) {
	var args []any
	where := store.ScopeSQL(c.User().Filter("orders:read"), "o.department_id", "o.created_by", &args)
	// add filters to where/args, then count, then page:
	var total int
	if err := m.st.DB().QueryRow(c.Context(), `SELECT count(*) FROM orders o WHERE `+where, args...).Scan(&total); err != nil {
		c.Fail(err)
		return
	}
	meta := store.ClampPage(c.Page(), total)
	// SELECT ... WHERE where ORDER BY <whitelisted column> LIMIT/OFFSET from meta
	c.OK(store.List[Order]{Items: items, Meta: meta})
}

func (m *Module) update(c *httpx.Ctx) {
	err := m.st.Tx(c.Context(), func(tx pgx.Tx) error {
		// SELECT ... FOR UPDATE; 404 if missing
		if !c.User().CanAccess(authz.Record{DepartmentID: o.DepartmentID, CreatedBy: o.CreatedBy}, "orders:write") {
			return apierr.ScopeDenied
		}
		// when the department changes, also require c.User().CanWriteDepartment("orders:write", newDept)
		// UPDATE ...
		return store.Audit(c.Context(), tx, c.Session.Actor(), "order.updated", target, detail)
	})
	...
}
```

Rules that keep modules consistent with the platform:

| Rule | How |
| --- | --- |
| Filter by scope before counting, sorting and paging | `store.ScopeSQL` in the `WHERE` of both the count and the page query |
| Check single records against the write scope, before and after a move | `Principal.CanAccess`, `Principal.CanWriteDepartment` |
| Reject a batch atomically if any record is out of scope | Lock the rows (`FOR UPDATE`), check all, then change; return `apierr.BatchScopeDenied` |
| Audit in the same transaction | `store.Audit(ctx, tx, ...)`; add the action to the frontend's audit action list |
| Respond with the envelope | `c.OK`, `c.Data(201, v)`, `c.Fail(err)`; lists use `store.List` |
| Errors | `apierr.New(status, CODE, 中文消息)`; new codes go into the frontend's `src/contract/errors.ts` |
| Lenient list parameters | `c.Page()` (defaults, clamping to 100), `c.Multi(key)` for repeated keys; sort only by a whitelist |
| IDs | `httpx.NewID()` |

## 5. Optional hooks

- `DepartmentInUse(ctx, q, departmentID)` (`httpx.DepartmentReferencer`): return true while the module has records in a department, so the department cannot be deleted.
- `SeedDemo(ctx)` (`httpx.DemoSeeder`): demo rows for `server seed-demo`.

## 6. Register it

Add one line to `cmd/server/modules.go`:

```go
return []httpx.Module{
	users.New(st, uploadDir),
	orders.New(st),
}
```

## 7. Test it

Use the HTTP harness in `internal/httpapi` (`newTestEnvWith` installs extra modules into the seeded test database): check that the guards hold, that a department-scoped role sees only its rows with correct totals, that batches are atomic and that writes are audited. Responses of operations in `api/openapi.yaml` are validated against it automatically.

Then add the pages in the frontend and run its Playwright suites against this server (see the README).
