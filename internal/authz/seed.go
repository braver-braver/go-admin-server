package authz

import "strings"

// Built-in ids that are protected from edits or deletion.
const (
	RootDepartmentID = "root"
	AdminAccountID   = "admin"
)

// Bootstrap returns the minimal configuration a fresh installation needs: the
// capability catalog, the registered menus, the protected super administrator
// role, the root department and the built-in recovery account.
func Bootstrap(adminName, adminEmail string) *Snapshot {
	s := &Snapshot{CredentialVersions: map[string]int{}}
	for _, c := range CapabilityCatalog {
		s.Permissions = append(s.Permissions, Permission{
			Resource: ResPermissions, ID: c.Code, Code: c.Code, Name: c.Name,
			Description: c.Method + " " + c.Path, Protected: true,
		})
	}
	s.Menus = []Menu{
		{Resource: ResMenus, ID: "business", Name: "业务示例", Kind: "directory", Enabled: true, Visible: true, Order: 20},
		{Resource: ResMenus, ID: "system", Name: "系统管理", Kind: "directory", Enabled: true, Visible: true, Order: 10, Protected: true},
	}
	for i, r := range RouteCatalog {
		parent := "business"
		switch {
		case strings.HasPrefix(r.ID, "system-"):
			parent = "system"
		case r.ID == DashboardRouteID:
			parent = ""
		}
		s.Menus = append(s.Menus, Menu{
			Resource: ResMenus, ID: r.ID, Name: r.Name, Kind: "page", RouteID: r.ID, ParentID: parent,
			Enabled: true, Visible: true, Order: i,
			Protected: r.ID == DashboardRouteID || r.ID == "system-menus",
		})
	}
	admin := Role{
		Resource: ResRoles, ID: AdminRoleID, Name: "超级管理员", Code: "admin", Enabled: true,
		Scope: ScopeAll, DepartmentIDs: []string{}, Protected: true,
	}
	for _, p := range s.Permissions {
		admin.PermissionIDs = append(admin.PermissionIDs, p.ID)
	}
	for _, m := range s.Menus {
		admin.MenuIDs = append(admin.MenuIDs, m.ID)
	}
	s.Roles = []Role{admin}
	s.Departments = []Department{
		{Resource: ResDepartments, ID: RootDepartmentID, Name: "组织总部", Code: "root", Enabled: true, Protected: true},
	}
	s.Accounts = []Account{{
		Resource: ResAccounts, ID: AdminAccountID, Name: adminName, Email: strings.ToLower(adminEmail),
		Enabled: true, DepartmentID: RootDepartmentID, RoleIDs: []string{AdminRoleID}, Protected: true,
	}}
	s.CredentialVersions[AdminAccountID] = 0
	return s
}

// Demo extends Bootstrap with the demo roles, departments and accounts of the
// reference mock (viewer@example.com, guest@example.com), for development only.
func Demo() *Snapshot {
	s := Bootstrap("演示管理员", "admin@example.com")
	s.Roles = append(s.Roles,
		Role{Resource: ResRoles, ID: "viewer", Name: "只读用户", Code: "viewer", Enabled: true,
			PermissionIDs: []string{"users:read", "permissions:read"},
			MenuIDs:       []string{"dashboard", "users", "current-permissions"},
			Scope:         ScopeAll, DepartmentIDs: []string{}},
		Role{Resource: ResRoles, ID: "guest", Name: "受限访客", Code: "guest", Enabled: true,
			PermissionIDs: []string{}, MenuIDs: []string{"dashboard"}, Scope: ScopeSelf, DepartmentIDs: []string{}},
	)
	s.Departments = append(s.Departments,
		Department{Resource: ResDepartments, ID: "operations", Name: "运营部", Code: "operations", ParentID: "root", Enabled: true},
		Department{Resource: ResDepartments, ID: "support", Name: "客户支持组", Code: "support", ParentID: "operations", Enabled: true},
		Department{Resource: ResDepartments, ID: "sales", Name: "销售部", Code: "sales", ParentID: "root", Enabled: true},
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
