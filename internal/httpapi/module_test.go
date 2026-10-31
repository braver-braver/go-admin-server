package httpapi

import (
	"context"
	"io/fs"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/braver-braver/go-admin-server/internal/authz"
	"github.com/braver-braver/go-admin-server/internal/httpx"
	"github.com/braver-braver/go-admin-server/internal/store"
)

// notes is a minimal module, written the way docs/modules.md describes, to
// prove that a module added to an existing installation works end to end.
type notes struct{ st *store.Store }

func (n *notes) Name() string { return "notes" }

func (n *notes) Catalog() authz.Catalog {
	return authz.Catalog{
		Capabilities: []authz.Capability{{Code: "notes:read", Method: "GET", Path: "/api/v1/notes", Name: "查看笔记"}},
		Routes:       []authz.Route{{ID: "notes", Path: "/notes", Name: "笔记", Permission: "notes:read", Menu: authz.MenuBusiness}},
	}
}

func (n *notes) Operations() []httpx.Op {
	return []httpx.Op{{Method: "GET", Path: "/notes", ID: "listNotes", Permission: "notes:read", Handle: func(c *httpx.Ctx) {
		var args []any
		where := store.ScopeSQL(c.User().Filter("notes:read"), "department_id", "created_by", &args)
		var count int
		if err := n.st.DB().QueryRow(c.Context(), `SELECT count(*) FROM notes WHERE `+where, args...).Scan(&count); err != nil {
			c.Fail(err)
			return
		}
		c.OK(map[string]int{"count": count})
	}}}
}

func (n *notes) Migrations() fs.FS {
	return fstest.MapFS{"20261102000000_notes.sql": {Data: []byte(`-- +goose Up
CREATE TABLE notes (id text PRIMARY KEY, department_id text NOT NULL, created_by text NOT NULL);
INSERT INTO notes VALUES ('n1', 'sales', 'admin'), ('n2', 'operations', 'admin');
-- +goose Down
DROP TABLE notes;
`)}}
}

func (n *notes) DepartmentInUse(ctx context.Context, q store.Querier, id string) (bool, error) {
	var used bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM notes WHERE department_id = $1)`, id).Scan(&used)
	return used, err
}

func TestModuleInstalledIntoAnExistingInstallation(t *testing.T) {
	e := newTestEnvWith(t, func(st *store.Store) []httpx.Module { return []httpx.Module{&notes{st: st}} })
	admin := e.client().login("admin@example.com")
	viewer := e.client().login("viewer@example.com")

	// The super administrator receives the new capability and page at once.
	r := admin.do("GET", "/notes", nil)
	if r.status != 200 || r.dataMap()["count"] != 2.0 {
		t.Fatalf("admin notes %d %s", r.status, r.raw)
	}
	user := admin.do("GET", "/auth/session", nil).dataMap()["user"].(map[string]any)
	if !slices.Contains(user["routes"].([]any), any("/notes")) {
		t.Fatal("new page not routed for the administrator")
	}
	// Nobody else does until an administrator grants it.
	expect(t, viewer.do("GET", "/notes", nil), 403, "FORBIDDEN")
	expect(t, admin.do("POST", "/notes", nil), 400, "INVALID_METHOD")

	// The permission is listed (protected) and the page sits in its directory.
	perms := admin.do("GET", "/system/permissions?search=notes:read", nil).dataMap()["items"].([]any)
	if len(perms) != 1 || perms[0].(map[string]any)["protected"] != true {
		t.Fatalf("permission record %v", perms)
	}
	menus := admin.do("GET", "/system/menus?search=笔记", nil).dataMap()["items"].([]any)
	if len(menus) != 1 || menus[0].(map[string]any)["parentId"] != authz.MenuBusiness {
		t.Fatalf("menu record %v", menus)
	}

	// Granting it to a department-scoped role applies the module's data scope.
	role := admin.do("POST", "/system/roles", map[string]any{"name": "笔记读者", "code": "notes_reader", "enabled": true,
		"permissionIds": []string{perms[0].(map[string]any)["id"].(string)}, "menuIds": []string{menus[0].(map[string]any)["id"].(string)},
		"scope": "department", "departmentIds": []string{}})
	expect(t, role, 201, "")
	acct := admin.do("POST", "/system/accounts", map[string]any{"name": "销售", "email": "seller@example.com", "password": "Seller1234!",
		"enabled": true, "departmentId": "sales", "roleIds": []string{role.dataMap()["id"].(string)}})
	expect(t, acct, 201, "")
	seller := e.client()
	expect(t, seller.loginWith("seller@example.com", "Seller1234!"), 200, "")
	if r := seller.do("GET", "/notes", nil); r.dataMap()["count"] != 1.0 {
		t.Fatalf("scoped notes %s", r.raw)
	}

	// The module's department reference blocks deleting a department in use.
	dept := admin.do("POST", "/system/departments", map[string]any{"name": "临时", "code": "temp", "parentId": "root", "enabled": true})
	expect(t, dept, 201, "")
	id := dept.dataMap()["id"].(string)
	if _, err := e.store.DB().Exec(context.Background(), `INSERT INTO notes VALUES ('n3', $1, 'admin')`, id); err != nil {
		t.Fatal(err)
	}
	expect(t, admin.do("DELETE", "/system/departments/"+id, nil), 409, "SYSTEM_RULE")

	// Installing again changes nothing.
	if changed, err := e.store.InstallCatalog(context.Background(), Catalog(e.server.modules)); err != nil || changed {
		t.Fatalf("reinstall changed=%v err=%v", changed, err)
	}
}
