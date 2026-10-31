package authz

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
)

// Ported from react-admin-starter src/mocks/data/system.test.ts.

type env struct {
	t    *testing.T
	db   *Snapshot
	next int
}

func newEnv(t *testing.T) *env { return &env{t: t, db: Demo()} }

func (e *env) change(actor, resource, id string, body any, remove bool) (any, *RuleError) {
	e.t.Helper()
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			e.t.Fatal(err)
		}
	}
	e.next++
	res, rerr := Apply(e.db, Change{
		Resource: resource, ID: id, NewID: fmt.Sprintf("new-%d", e.next), Remove: remove, Body: raw,
		ActorID: actor, ActorCredentialVersion: e.db.CredentialVersions[actor],
	})
	if rerr != nil {
		return nil, rerr
	}
	e.db = res.After
	return res.Record, nil
}

func (e *env) must(actor, resource, id string, body any) any {
	e.t.Helper()
	rec, err := e.change(actor, resource, id, body, false)
	if err != nil {
		e.t.Fatalf("%s %s %q: %v", resource, id, body, err)
	}
	return rec
}

func (e *env) reject(status int, actor, resource, id string, body any, remove bool) {
	e.t.Helper()
	_, err := e.change(actor, resource, id, body, remove)
	if err == nil || err.Status != status {
		e.t.Fatalf("%s %s: want %d, got %v", resource, id, status, err)
	}
}

func (e *env) principal(id string) *Principal {
	e.t.Helper()
	p, ok := e.db.Principal(id)
	if !ok {
		e.t.Fatalf("no principal %s", id)
	}
	return p
}

func roleBody(scope string) map[string]any {
	depts := []string{}
	if scope == ScopeCustom {
		depts = []string{"sales"}
	}
	return map[string]any{
		"name": "部门经办人", "code": "operator", "enabled": true,
		"permissionIds": []string{"users:read", "users:write"}, "menuIds": []string{"users"},
		"scope": scope, "departmentIds": depts,
	}
}

func with(base map[string]any, kv ...any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for i := 0; i < len(kv); i += 2 {
		out[kv[i].(string)] = kv[i+1]
	}
	return out
}

func accountFields(a Account) map[string]any {
	return map[string]any{"name": a.Name, "email": a.Email, "enabled": a.Enabled,
		"departmentId": a.DepartmentID, "roleIds": a.RoleIDs}
}

func roleFields(r Role) map[string]any {
	return map[string]any{"name": r.Name, "code": r.Code, "enabled": r.Enabled, "permissionIds": r.PermissionIDs,
		"menuIds": r.MenuIDs, "scope": r.Scope, "departmentIds": r.DepartmentIDs}
}

// operator creates a role with the given scope and an account in operations.
func (e *env) operator(scope string) (Role, Account) {
	role := e.must(AdminAccountID, ResRoles, "", roleBody(scope)).(Role)
	acct := e.must(AdminAccountID, ResAccounts, "", map[string]any{
		"name": "运营经办", "email": "operator@example.com", "password": "Operator123!",
		"enabled": true, "departmentId": "operations", "roleIds": []string{role.ID},
	}).(Account)
	return role, acct
}

func TestDataScopeModes(t *testing.T) {
	for _, scope := range []string{ScopeAll, ScopeDepartment, ScopeDescendants, ScopeSelf, ScopeCustom} {
		t.Run(scope, func(t *testing.T) {
			e := newEnv(t)
			_, acct := e.operator(scope)
			u := e.principal(acct.ID)
			check := func(r Record, want bool) {
				t.Helper()
				if got := u.CanAccess(r, "users:read"); got != want {
					t.Errorf("%+v: got %v want %v", r, got, want)
				}
			}
			check(Record{DepartmentID: "operations", CreatedBy: "other"}, scope == ScopeAll || scope == ScopeDepartment || scope == ScopeDescendants)
			check(Record{DepartmentID: "support", CreatedBy: "other"}, scope == ScopeAll || scope == ScopeDescendants)
			check(Record{DepartmentID: "sales", CreatedBy: "other"}, scope == ScopeAll || scope == ScopeCustom)
			check(Record{DepartmentID: "sales", CreatedBy: u.ID}, scope == ScopeAll || scope == ScopeCustom || scope == ScopeSelf)
		})
	}
}

func TestUnionAndImmediateRevocation(t *testing.T) {
	e := newEnv(t)
	role, acct := e.operator(ScopeDepartment)
	second := e.must(AdminAccountID, ResRoles, "", with(roleBody(ScopeCustom), "code", "sales_reader", "permissionIds", []string{"users:read"})).(Role)
	e.must(AdminAccountID, ResAccounts, acct.ID, with(accountFields(acct), "roleIds", []string{role.ID, second.ID}))
	u := e.principal(acct.ID)
	if !u.CanAccess(Record{DepartmentID: "operations"}, "users:read") || !u.CanAccess(Record{DepartmentID: "sales"}, "users:read") {
		t.Fatal("union of roles not applied")
	}
	e.must(AdminAccountID, ResRoles, role.ID, with(roleFields(role), "enabled", false))
	u = e.principal(acct.ID)
	if u.Has("users:write") || u.CanAccess(Record{DepartmentID: "operations"}, "users:read") {
		t.Fatal("disabled role still grants")
	}
}

func TestReadAllPlusWriteSelfIsNotWriteAll(t *testing.T) {
	e := newEnv(t)
	role, acct := e.operator(ScopeSelf)
	reader := e.must(AdminAccountID, ResRoles, "", with(roleBody(ScopeAll), "code", "global_reader", "permissionIds", []string{"users:read"})).(Role)
	e.must(AdminAccountID, ResAccounts, acct.ID, with(accountFields(acct), "roleIds", []string{role.ID, reader.ID}))
	u := e.principal(acct.ID)
	other := Record{DepartmentID: "sales", CreatedBy: "other"}
	if !u.CanAccess(other, "users:read") || u.CanAccess(other, "users:write") {
		t.Fatal("scopes leaked across capabilities")
	}
	if !u.CanAccess(Record{DepartmentID: "sales", CreatedBy: u.ID}, "users:write") {
		t.Fatal("self write lost")
	}
	if f := u.Filter("users:write"); f.All || f.SelfID != u.ID {
		t.Fatalf("filter %+v", f)
	}
}

func TestHiddenVersusDisabledMenus(t *testing.T) {
	e := newEnv(t)
	var users Menu
	for _, m := range e.db.Menus {
		if m.ID == "users" {
			users = m
		}
	}
	body := map[string]any{"name": users.Name, "parentId": users.ParentID, "kind": users.Kind, "routeId": users.RouteID,
		"enabled": true, "visible": false, "order": users.Order}
	e.must(AdminAccountID, ResMenus, "users", body)
	admin := e.principal(AdminAccountID)
	if slices.ContainsFunc(e.db.Navigation(admin), func(m Menu) bool { return m.ID == "users" }) {
		t.Fatal("hidden menu still in navigation")
	}
	if !slices.Contains(admin.Routes, "/users") {
		t.Fatal("hidden menu must keep its route")
	}
	e.must(AdminAccountID, ResMenus, "users", with(body, "enabled", false))
	if slices.Contains(e.principal(AdminAccountID).Routes, "/users") {
		t.Fatal("disabled menu must revoke its route")
	}
	e.reject(409, AdminAccountID, ResMenus, "system-menus", nil, true)
}

func TestStructuralRules(t *testing.T) {
	e := newEnv(t)
	e.reject(422, AdminAccountID, ResMenus, "", map[string]any{"name": "外部脚本", "parentId": "", "kind": "page",
		"routeId": "https://evil.invalid", "order": 1, "enabled": true, "visible": true}, false)
	ops, _ := e.db.Department("operations")
	e.reject(422, AdminAccountID, ResDepartments, "operations", map[string]any{"name": ops.Name, "code": ops.Code,
		"parentId": "support", "enabled": true}, false)
	e.reject(409, AdminAccountID, ResDepartments, "operations", nil, true)
	admin, _ := e.db.Account(AdminAccountID)
	e.reject(409, AdminAccountID, ResAccounts, AdminAccountID, with(accountFields(admin), "enabled", false), false)
	e.reject(409, AdminAccountID, ResRoles, AdminRoleID, nil, true)
}

func TestNoEscalationAndStaleSessions(t *testing.T) {
	e := newEnv(t)
	role, acct := e.operator(ScopeDepartment)
	e.must(AdminAccountID, ResRoles, role.ID, with(roleFields(role), "permissionIds", []string{"users:read", "system:accounts:write"}))
	e.reject(403, acct.ID, ResAccounts, "", map[string]any{"name": "越权账号", "email": "escalate@example.com",
		"password": "Escalate123!", "enabled": false, "departmentId": "operations", "roleIds": []string{"viewer"}}, false)
	e.reject(403, acct.ID, ResAccounts, acct.ID, with(accountFields(acct), "roleIds", []string{AdminRoleID}), false)

	// A session issued before a credential change is rejected.
	_, err := Apply(e.db, Change{Resource: ResAccounts, ID: acct.ID, Body: mustJSON(t, accountFields(acct)),
		ActorID: AdminAccountID, ActorCredentialVersion: -1})
	if err == nil || err.Status != 401 {
		t.Fatalf("stale session: %v", err)
	}
}

func TestRoleScopeEscalationWithGlobalRoleManagement(t *testing.T) {
	for _, tc := range []struct {
		scope string
		depts []string
	}{{ScopeAll, []string{}}, {ScopeDescendants, []string{}}, {ScopeCustom, []string{"sales"}}} {
		t.Run(tc.scope, func(t *testing.T) {
			e := newEnv(t)
			role, acct := e.operator(ScopeDepartment)
			manager := e.must(AdminAccountID, ResRoles, "", map[string]any{"name": "角色维护员", "code": "role_maintainer",
				"enabled": true, "permissionIds": []string{"system:roles:write"}, "menuIds": []string{"dashboard"},
				"scope": "all", "departmentIds": []string{}}).(Role)
			e.must(AdminAccountID, ResAccounts, acct.ID, with(accountFields(acct), "roleIds", []string{role.ID, manager.ID}))
			limited := e.principal(acct.ID)
			if !limited.DataScopes["system:roles:write"].All || limited.DataScopes["users:read"].All {
				t.Fatal("unexpected setup scopes")
			}
			e.reject(403, acct.ID, ResRoles, role.ID, with(roleFields(role), "scope", tc.scope, "departmentIds", tc.depts), false)
			e.reject(403, acct.ID, ResRoles, "", with(roleBody(tc.scope), "code", "forbidden_role", "departmentIds", tc.depts), false)
			if e.principal(acct.ID).CanAccess(Record{DepartmentID: "sales"}, "users:read") {
				t.Fatal("scope widened")
			}
		})
	}
}

func TestDepartmentReparentCannotWidenScopes(t *testing.T) {
	e := newEnv(t)
	// A descendants-scoped account in operations; an actor that manages
	// departments globally but only reads users in operations' subtree.
	_, acct := e.operator(ScopeDescendants)
	mgr := e.must(AdminAccountID, ResRoles, "", map[string]any{"name": "部门维护员", "code": "dept_maintainer",
		"enabled": true, "permissionIds": []string{"system:departments:write", "system:departments:read"},
		"menuIds": []string{"dashboard"}, "scope": "all", "departmentIds": []string{}}).(Role)
	actor := e.must(AdminAccountID, ResAccounts, "", map[string]any{"name": "部门维护", "email": "dept@example.com",
		"password": "Dept12345!", "enabled": true, "departmentId": "operations", "roleIds": []string{mgr.ID}}).(Account)
	_ = acct
	// Moving sales under operations would give the operator sales data.
	sales, _ := e.db.Department("sales")
	_, err := e.change(actor.ID, ResDepartments, "sales", map[string]any{"name": sales.Name, "code": sales.Code,
		"parentId": "operations", "enabled": true}, false)
	if err == nil || err.Status != 403 || err.Message != "调整部门后授予的数据范围超出当前管理员授权。" {
		t.Fatalf("reparent: %v", err)
	}
	// The administrator may do it.
	e.must(AdminAccountID, ResDepartments, "sales", map[string]any{"name": sales.Name, "code": sales.Code,
		"parentId": "operations", "enabled": true})
}

func TestCredentialVersions(t *testing.T) {
	e := newEnv(t)
	_, acct := e.operator(ScopeDepartment)
	v0 := e.db.CredentialVersions[acct.ID]
	e.must(AdminAccountID, ResAccounts, acct.ID, with(accountFields(acct), "enabled", false))
	if e.db.CredentialVersions[acct.ID] != v0+1 {
		t.Fatal("disabling must revoke sessions")
	}
	if _, ok := e.db.Principal(acct.ID); ok {
		t.Fatal("disabled account has a principal")
	}
	res, err := Apply(e.db, Change{Resource: ResAccounts, ID: acct.ID, ActorID: AdminAccountID,
		Body: mustJSON(t, with(accountFields(acct), "password", "NewPass123!"))})
	if err != nil || res.Password == nil || res.After.CredentialVersions[acct.ID] != v0+2 {
		t.Fatalf("password reset: %v %+v", err, res)
	}
}

func TestStrictBodies(t *testing.T) {
	e := newEnv(t)
	e.reject(422, AdminAccountID, ResRoles, "", with(roleBody(ScopeAll), "extra", 1), false)
	e.reject(422, AdminAccountID, ResRoles, "", with(roleBody(ScopeCustom), "departmentIds", []string{}), false)
	e.reject(422, AdminAccountID, ResRoles, "", with(roleBody(ScopeAll), "code", "Bad Code"), false)
	e.reject(422, AdminAccountID, ResRoles, "", with(roleBody(ScopeAll), "menuIds", []string{"users", "users"}), false)
	e.reject(422, AdminAccountID, ResRoles, "", with(roleBody(ScopeAll), "name", nil), false)
	e.reject(422, AdminAccountID, ResAccounts, "", map[string]any{"name": "x", "email": "y@example.com",
		"enabled": true, "departmentId": "operations", "roleIds": []string{"viewer"}}, false) // no password
	e.must(AdminAccountID, ResRoles, "", roleBody(ScopeAll))
	e.reject(409, AdminAccountID, ResRoles, "", roleBody(ScopeAll), false) // duplicate code
}

func TestAdminRoleTracksCatalog(t *testing.T) {
	e := newEnv(t)
	p := e.must(AdminAccountID, ResPermissions, "", map[string]any{"name": "报表", "code": "reports:read", "description": ""}).(Permission)
	if !e.principal(AdminAccountID).Has(p.Code) {
		t.Fatal("admin must hold new permissions")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
