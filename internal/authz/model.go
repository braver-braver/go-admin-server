// Package authz is the authorization kernel: it turns the system configuration
// (accounts, roles, permissions, menus, departments) into a principal with
// per-capability data scopes and routes, and decides whether a system
// configuration change is allowed.
//
// Everything here is a pure function over a Snapshot. The storage layer loads a
// snapshot inside a serialized transaction, calls Apply, and persists the
// result, which mirrors the reference mock in react-admin-starter
// (src/mocks/data/system.ts) rule for rule.
package authz

import "slices"

// Resource names of the system-management API.
const (
	ResAccounts    = "accounts"
	ResRoles       = "roles"
	ResPermissions = "permissions"
	ResMenus       = "menus"
	ResDepartments = "departments"
)

// Resources lists the system resources in API order.
var Resources = []string{ResAccounts, ResRoles, ResPermissions, ResMenus, ResDepartments}

// Data scope modes a role can carry.
const (
	ScopeAll         = "all"
	ScopeDepartment  = "department"
	ScopeDescendants = "descendants"
	ScopeSelf        = "self"
	ScopeCustom      = "custom"
)

// AdminRoleID is the built-in super administrator role. It always holds every
// permission and menu and is reserved for the built-in recovery account.
const AdminRoleID = "admin"

// DashboardRouteID is reachable by every signed-in account.
const DashboardRouteID = "dashboard"

type Account struct {
	Resource     string   `json:"resource"`
	ID           string   `json:"id"`
	Protected    bool     `json:"protected"`
	Name         string   `json:"name"`
	Email        string   `json:"email"`
	Enabled      bool     `json:"enabled"`
	DepartmentID string   `json:"departmentId"`
	RoleIDs      []string `json:"roleIds"`
}

type Role struct {
	Resource      string   `json:"resource"`
	ID            string   `json:"id"`
	Protected     bool     `json:"protected"`
	Name          string   `json:"name"`
	Code          string   `json:"code"`
	Enabled       bool     `json:"enabled"`
	PermissionIDs []string `json:"permissionIds"`
	MenuIDs       []string `json:"menuIds"`
	Scope         string   `json:"scope"`
	DepartmentIDs []string `json:"departmentIds"`
}

type Permission struct {
	Resource    string `json:"resource"`
	ID          string `json:"id"`
	Protected   bool   `json:"protected"`
	Name        string `json:"name"`
	Code        string `json:"code"`
	Description string `json:"description"`
}

type Menu struct {
	Resource  string `json:"resource"`
	ID        string `json:"id"`
	Protected bool   `json:"protected"`
	Name      string `json:"name"`
	ParentID  string `json:"parentId"`
	Kind      string `json:"kind"` // "directory" or "page"
	RouteID   string `json:"routeId"`
	Enabled   bool   `json:"enabled"`
	Visible   bool   `json:"visible"`
	Order     int    `json:"order"`
}

type Department struct {
	Resource  string `json:"resource"`
	ID        string `json:"id"`
	Protected bool   `json:"protected"`
	Name      string `json:"name"`
	Code      string `json:"code"`
	ParentID  string `json:"parentId"`
	Enabled   bool   `json:"enabled"`
}

// Snapshot is the complete system configuration. Slices keep insertion order,
// which is also the order lists are returned in.
type Snapshot struct {
	Accounts    []Account
	Roles       []Role
	Permissions []Permission
	Menus       []Menu
	Departments []Department
	// Catalog is the code-defined capabilities and pages; not stored.
	Catalog Catalog
	// CredentialVersions is bumped whenever an account's password is reset or
	// the account is disabled/re-enabled; sessions carry the version they were
	// issued with and become invalid when it changes.
	CredentialVersions map[string]int
}

// Clone returns a deep copy, so a candidate change never touches the original.
func (s *Snapshot) Clone() *Snapshot {
	c := &Snapshot{
		Catalog:            s.Catalog,
		Accounts:           slices.Clone(s.Accounts),
		Roles:              slices.Clone(s.Roles),
		Permissions:        slices.Clone(s.Permissions),
		Menus:              slices.Clone(s.Menus),
		Departments:        slices.Clone(s.Departments),
		CredentialVersions: make(map[string]int, len(s.CredentialVersions)),
	}
	for i := range c.Accounts {
		c.Accounts[i].RoleIDs = slices.Clone(c.Accounts[i].RoleIDs)
	}
	for i := range c.Roles {
		r := &c.Roles[i]
		r.PermissionIDs = slices.Clone(r.PermissionIDs)
		r.MenuIDs = slices.Clone(r.MenuIDs)
		r.DepartmentIDs = slices.Clone(r.DepartmentIDs)
	}
	for k, v := range s.CredentialVersions {
		c.CredentialVersions[k] = v
	}
	return c
}

func (s *Snapshot) account(id string) *Account {
	for i := range s.Accounts {
		if s.Accounts[i].ID == id {
			return &s.Accounts[i]
		}
	}
	return nil
}

// Account returns a copy of the account with the given id.
func (s *Snapshot) Account(id string) (Account, bool) {
	if a := s.account(id); a != nil {
		return *a, true
	}
	return Account{}, false
}

// AccountByEmail finds an account by its lower-cased email.
func (s *Snapshot) AccountByEmail(email string) (Account, bool) {
	for _, a := range s.Accounts {
		if a.Email == email {
			return a, true
		}
	}
	return Account{}, false
}

func (s *Snapshot) department(id string) *Department {
	for i := range s.Departments {
		if s.Departments[i].ID == id {
			return &s.Departments[i]
		}
	}
	return nil
}

// Department returns a copy of the department with the given id.
func (s *Snapshot) Department(id string) (Department, bool) {
	if d := s.department(id); d != nil {
		return *d, true
	}
	return Department{}, false
}

func (s *Snapshot) menu(id string) *Menu {
	for i := range s.Menus {
		if s.Menus[i].ID == id {
			return &s.Menus[i]
		}
	}
	return nil
}

func (s *Snapshot) role(id string) *Role {
	for i := range s.Roles {
		if s.Roles[i].ID == id {
			return &s.Roles[i]
		}
	}
	return nil
}

func (s *Snapshot) permission(id string) *Permission {
	for i := range s.Permissions {
		if s.Permissions[i].ID == id {
			return &s.Permissions[i]
		}
	}
	return nil
}

// Route is a page the frontend has registered. Server configuration can only
// select these by id; it can never ship code, component paths or links.
type Route struct {
	ID         string
	Path       string
	Name       string
	Permission string // capability required to view the page; empty = none
	// Menu is the directory a newly installed page is placed in ("" = root).
	Menu string
}

// Capability is one entry of the API capability catalog. Every endpoint is
// bound to one of these codes; creating a permission record never grants
// access to an endpoint on its own.
type Capability struct {
	Code   string
	Method string
	Path   string
	Name   string
}

// Catalog is what the code provides: the capabilities its endpoints check and
// the pages the frontend registers (src/features/system/catalog.ts). The core
// contributes system management; each business module contributes its own.
type Catalog struct {
	Capabilities []Capability
	Routes       []Route
}

// Directory menus that pages are placed in by default.
const (
	MenuSystem   = "system"
	MenuBusiness = "business"
)

// CoreCatalog is the catalog of the platform itself.
func CoreCatalog() Catalog {
	c := Catalog{
		Capabilities: []Capability{
			{"permissions:read", "GET", "/api/v1/auth/permissions", "查看自身权限"},
			{"audit:read", "GET", "/api/v1/audit-logs", "查询审计日志"},
		},
		Routes: []Route{
			{ID: DashboardRouteID, Path: "/", Name: "工作台"},
			{ID: "current-permissions", Path: "/permissions", Name: "权限示例", Permission: "permissions:read", Menu: MenuBusiness},
			{ID: "audit", Path: "/audit", Name: "审计日志", Permission: "audit:read", Menu: MenuBusiness},
		},
	}
	names := map[string]string{
		ResAccounts: "登录用户", ResRoles: "角色", ResPermissions: "权限",
		ResMenus: "菜单", ResDepartments: "部门",
	}
	pages := map[string]string{
		ResAccounts: "登录用户管理", ResRoles: "角色管理", ResPermissions: "权限管理",
		ResMenus: "菜单管理", ResDepartments: "部门管理",
	}
	for _, r := range Resources {
		c.Capabilities = append(c.Capabilities,
			Capability{"system:" + r + ":read", "GET", "/api/v1/system/" + r, "查看" + names[r]},
			Capability{"system:" + r + ":write", "POST / PUT / DELETE", "/api/v1/system/" + r + "/*", "维护" + names[r]},
		)
		c.Routes = append(c.Routes, Route{ID: "system-" + r, Path: "/system/" + r, Name: pages[r],
			Permission: "system:" + r + ":read", Menu: MenuSystem})
	}
	return c
}

// Merge combines catalogs. Duplicate capability codes or route ids are a
// programming error and panic at startup.
func Merge(catalogs ...Catalog) Catalog {
	var out Catalog
	codes, routes := map[string]bool{}, map[string]bool{}
	for _, c := range catalogs {
		for _, cap := range c.Capabilities {
			if codes[cap.Code] {
				panic("authz: duplicate capability " + cap.Code)
			}
			codes[cap.Code] = true
			out.Capabilities = append(out.Capabilities, cap)
		}
		for _, r := range c.Routes {
			if routes[r.ID] {
				panic("authz: duplicate route " + r.ID)
			}
			routes[r.ID] = true
			out.Routes = append(out.Routes, r)
		}
	}
	for _, r := range out.Routes {
		if r.Permission != "" && !codes[r.Permission] {
			panic("authz: route " + r.ID + " needs unknown capability " + r.Permission)
		}
	}
	return out
}

func (s *Snapshot) route(id string) (Route, bool) {
	for _, r := range s.Catalog.Routes {
		if r.ID == id {
			return r, true
		}
	}
	return Route{}, false
}
