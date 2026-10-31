package authz

import (
	"slices"
	"strings"
)

// Built-in ids that are protected from edits or deletion.
const (
	RootDepartmentID = "root"
	AdminAccountID   = "admin"
)

// SyncCatalog adds what the code provides but the configuration lacks: a
// protected permission record per capability and an enabled page menu per
// route, placed in the route's default directory. New pages are granted to
// the super administrator only; other roles get them when an administrator
// says so. Records whose code was removed are left alone. It returns a new
// snapshot and whether anything changed.
func SyncCatalog(s *Snapshot, cat Catalog) (*Snapshot, bool) {
	out := s.Clone()
	out.Catalog = cat
	changed := false
	for _, c := range cat.Capabilities {
		if slices.ContainsFunc(out.Permissions, func(p Permission) bool { return p.Code == c.Code }) {
			continue
		}
		id := c.Code
		if out.permission(id) != nil {
			id = "cap-" + c.Code
		}
		out.Permissions = append(out.Permissions, Permission{
			Resource: ResPermissions, ID: id, Code: c.Code, Name: c.Name,
			Description: c.Method + " " + c.Path, Protected: true,
		})
		changed = true
	}
	// Root pages first, then the rest in catalog order; Order follows suit.
	routes := slices.Clone(cat.Routes)
	nested := func(r Route) int {
		if r.Menu == "" {
			return 0
		}
		return 1
	}
	slices.SortStableFunc(routes, func(a, b Route) int { return nested(a) - nested(b) })
	for i, r := range routes {
		if slices.ContainsFunc(out.Menus, func(m Menu) bool { return m.Kind == "page" && m.RouteID == r.ID }) {
			continue
		}
		parent := r.Menu
		if d := out.menu(parent); parent != "" && (d == nil || d.Kind != "directory") {
			parent = ""
		}
		id := r.ID
		if out.menu(id) != nil {
			id = "page-" + r.ID
		}
		out.Menus = append(out.Menus, Menu{
			Resource: ResMenus, ID: id, Name: r.Name, Kind: "page", RouteID: r.ID, ParentID: parent,
			Enabled: true, Visible: true, Order: i,
			Protected: r.ID == DashboardRouteID || r.ID == "system-menus",
		})
		changed = true
	}
	if changed {
		syncAdminRole(out)
	}
	return out, changed
}

// syncAdminRole gives the super administrator role every permission and menu.
func syncAdminRole(s *Snapshot) {
	admin := s.role(AdminRoleID)
	if admin == nil {
		return
	}
	admin.PermissionIDs = make([]string, 0, len(s.Permissions))
	for _, p := range s.Permissions {
		admin.PermissionIDs = append(admin.PermissionIDs, p.ID)
	}
	admin.MenuIDs = make([]string, 0, len(s.Menus))
	for _, m := range s.Menus {
		admin.MenuIDs = append(admin.MenuIDs, m.ID)
	}
}

// Bootstrap returns the configuration of a fresh installation: the two menu
// directories, the root department, the protected super administrator role
// and the built-in recovery account, plus everything in the catalog.
func Bootstrap(cat Catalog, adminName, adminEmail string) *Snapshot {
	s := &Snapshot{
		Catalog: cat,
		Menus: []Menu{
			{Resource: ResMenus, ID: MenuBusiness, Name: "业务示例", Kind: "directory", Enabled: true, Visible: true, Order: 20},
			{Resource: ResMenus, ID: MenuSystem, Name: "系统管理", Kind: "directory", Enabled: true, Visible: true, Order: 10, Protected: true},
		},
		Roles: []Role{{
			Resource: ResRoles, ID: AdminRoleID, Name: "超级管理员", Code: "admin", Enabled: true,
			Scope: ScopeAll, PermissionIDs: []string{}, MenuIDs: []string{}, DepartmentIDs: []string{}, Protected: true,
		}},
		Departments: []Department{
			{Resource: ResDepartments, ID: RootDepartmentID, Name: "组织总部", Code: "root", Enabled: true, Protected: true},
		},
		Accounts: []Account{{
			Resource: ResAccounts, ID: AdminAccountID, Name: adminName, Email: strings.ToLower(adminEmail),
			Enabled: true, DepartmentID: RootDepartmentID, RoleIDs: []string{AdminRoleID}, Protected: true,
		}},
		CredentialVersions: map[string]int{AdminAccountID: 0},
	}
	out, _ := SyncCatalog(s, cat)
	return out
}

// Demo extends Bootstrap with the demo roles, departments and accounts of the
// reference mock (viewer@example.com, guest@example.com), for development
// only. The viewer role's grants are kept to what the catalog provides.
func Demo(cat Catalog) *Snapshot {
	s := Bootstrap(cat, "演示管理员", "admin@example.com")
	known := func(ids []string, exists func(string) bool) []string {
		out := []string{}
		for _, id := range ids {
			if exists(id) {
				out = append(out, id)
			}
		}
		return out
	}
	hasPerm := func(id string) bool { return s.permission(id) != nil }
	hasMenu := func(id string) bool { return s.menu(id) != nil }
	s.Roles = append(s.Roles,
		Role{Resource: ResRoles, ID: "viewer", Name: "只读用户", Code: "viewer", Enabled: true,
			PermissionIDs: known([]string{"users:read", "permissions:read"}, hasPerm),
			MenuIDs:       known([]string{DashboardRouteID, "users", "current-permissions"}, hasMenu),
			Scope:         ScopeAll, DepartmentIDs: []string{}},
		Role{Resource: ResRoles, ID: "guest", Name: "受限访客", Code: "guest", Enabled: true,
			PermissionIDs: []string{}, MenuIDs: []string{DashboardRouteID}, Scope: ScopeSelf, DepartmentIDs: []string{}},
	)
	s.Departments = append(s.Departments,
		Department{Resource: ResDepartments, ID: "operations", Name: "运营部", Code: "operations", ParentID: RootDepartmentID, Enabled: true},
		Department{Resource: ResDepartments, ID: "support", Name: "客户支持组", Code: "support", ParentID: "operations", Enabled: true},
		Department{Resource: ResDepartments, ID: "sales", Name: "销售部", Code: "sales", ParentID: RootDepartmentID, Enabled: true},
	)
	s.Accounts = append(s.Accounts,
		Account{Resource: ResAccounts, ID: "demo-viewer", Name: "演示只读用户", Email: "viewer@example.com",
			Enabled: true, DepartmentID: "operations", RoleIDs: []string{"viewer"}},
		Account{Resource: ResAccounts, ID: "demo-guest", Name: "演示受限用户", Email: "guest@example.com",
			Enabled: true, DepartmentID: "operations", RoleIDs: []string{"guest"}},
	)
	s.CredentialVersions["demo-viewer"] = 0
	s.CredentialVersions["demo-guest"] = 0
	return s
}
