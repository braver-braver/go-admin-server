// Package users is the example business module: server-paged CRUD of business
// users with data scopes, bulk operations, invitations and avatar uploads. It
// is also the template for new modules; see docs/modules.md.
package users

import (
	"context"
	"embed"
	"io/fs"

	"github.com/braver-braver/go-admin-server/internal/authz"
	"github.com/braver-braver/go-admin-server/internal/httpx"
	"github.com/braver-braver/go-admin-server/internal/store"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Capabilities of this module.
const (
	CapRead  = "users:read"
	CapWrite = "users:write"
)

type Module struct {
	repo      *Repo
	uploadDir string
}

// New builds the module. uploadDir holds avatar files.
func New(st *store.Store, uploadDir string) *Module {
	return &Module{repo: &Repo{st: st}, uploadDir: uploadDir}
}

func (m *Module) Name() string { return "users" }

func (m *Module) Catalog() authz.Catalog {
	return authz.Catalog{
		Capabilities: []authz.Capability{
			{Code: CapRead, Method: "GET", Path: "/api/v1/users", Name: "查看业务用户"},
			{Code: CapWrite, Method: "POST / PUT / PATCH / DELETE", Path: "/api/v1/users/*", Name: "维护业务用户"},
		},
		Routes: []authz.Route{
			{ID: "users", Path: "/users", Name: "用户管理", Permission: CapRead, Menu: authz.MenuBusiness},
		},
	}
}

func (m *Module) Operations() []httpx.Op {
	return []httpx.Op{
		{Method: "GET", Path: "/users", ID: "listUsers", Permission: CapRead, Handle: m.listUsers},
		{Method: "POST", Path: "/users", ID: "createUser", Permission: CapWrite, Handle: m.createUser},
		{Method: "PUT", Path: "/users/{id}", ID: "updateUser", Permission: CapWrite, Handle: m.updateUser},
		{Method: "DELETE", Path: "/users/{id}", ID: "deleteUser", Permission: CapWrite, Handle: m.deleteUser},
		{Method: "POST", Path: "/users/batch-delete", ID: "batchDeleteUsers", Permission: CapWrite, Handle: m.batchDeleteUsers},
		{Method: "PATCH", Path: "/users/status", ID: "updateUsersStatus", Permission: CapWrite, Handle: m.updateUsersStatus},
		{Method: "POST", Path: "/users/invite", ID: "inviteUser", Permission: CapWrite, Handle: m.inviteUser},
		{Method: "POST", Path: "/users/invite-batch", ID: "batchInviteUsers", Permission: CapWrite, Handle: m.batchInviteUsers},
		{Method: "POST", Path: "/uploads", ID: "uploadFile", Permission: CapWrite, Handle: m.upload},
		// Extension, not yet in the contract: avatars are shown to readers.
		{Method: "GET", Path: "/uploads/{id}", ID: "downloadFile", Permission: CapRead, Handle: m.download},
	}
}

func (m *Module) Migrations() fs.FS {
	sub, _ := fs.Sub(migrations, "migrations")
	return sub
}

// DepartmentInUse blocks deleting a department that still has business users.
func (m *Module) DepartmentInUse(ctx context.Context, q store.Querier, departmentID string) (bool, error) {
	var used bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE department_id = $1)`, departmentID).Scan(&used)
	return used, err
}

// SeedDemo adds 120 deterministic business users across the demo departments.
func (m *Module) SeedDemo(ctx context.Context) error {
	_, err := m.repo.SeedDemoUsers(ctx, 120, authz.AdminAccountID, []string{"root", "operations", "support", "sales"})
	return err
}

var (
	_ httpx.Module               = (*Module)(nil)
	_ httpx.DepartmentReferencer = (*Module)(nil)
	_ httpx.DemoSeeder           = (*Module)(nil)
)
