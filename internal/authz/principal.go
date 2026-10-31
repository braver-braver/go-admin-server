package authz

import (
	"cmp"
	"slices"
	"strings"
)

// DataScope is the data an account may touch through one capability.
type DataScope struct {
	All         bool     `json:"all"`
	Self        bool     `json:"self"`
	Departments []string `json:"departments"`
}

// Principal is the authenticated account with its live grants. Its JSON form is
// the `user` of the Session contract.
type Principal struct {
	ID           string               `json:"id"`
	Email        string               `json:"email"`
	Name         string               `json:"name"`
	Roles        []string             `json:"roles"`
	Permissions  []string             `json:"permissions"`
	DataScopes   map[string]DataScope `json:"dataScopes"`
	Routes       []string             `json:"routes"`
	DepartmentID string               `json:"departmentId"`
	// DataScope is only an overall summary; authorization reads DataScopes.
	DataScope DataScope `json:"dataScope"`
}

// Has reports whether the principal holds a capability. Unknown capabilities
// are denied.
func (p *Principal) Has(permission string) bool {
	return p != nil && slices.Contains(p.Permissions, permission)
}

// ActiveDepartment reports whether a department and all of its ancestors exist
// and are enabled. A cycle counts as inactive.
func (s *Snapshot) ActiveDepartment(id string) bool {
	visited := map[string]bool{}
	for id != "" {
		if visited[id] {
			return false
		}
		visited[id] = true
		d := s.department(id)
		if d == nil || !d.Enabled {
			return false
		}
		id = d.ParentID
	}
	return true
}

// Descendants returns id and every department below it.
func (s *Snapshot) Descendants(id string) map[string]bool {
	result := map[string]bool{id: true}
	for changed := true; changed; {
		changed = false
		for _, d := range s.Departments {
			if result[d.ParentID] && !result[d.ID] {
				result[d.ID] = true
				changed = true
			}
		}
	}
	return result
}

// accountRoles returns the enabled roles of an account, in snapshot order.
func (s *Snapshot) accountRoles(a *Account) []Role {
	var roles []Role
	for _, r := range s.Roles {
		if r.Enabled && slices.Contains(a.RoleIDs, r.ID) {
			roles = append(roles, r)
		}
	}
	return roles
}

func hasAdmin(roles []Role) bool {
	return slices.ContainsFunc(roles, func(r Role) bool { return r.ID == AdminRoleID })
}

// dataScope unions the scopes of the given roles for an account. Departments
// that are disabled, or sit under a disabled ancestor, are dropped.
func (s *Snapshot) dataScope(a *Account, roles []Role) DataScope {
	scope := DataScope{Departments: []string{}}
	var ordered []string
	seen := map[string]bool{}
	add := func(id string) {
		if !seen[id] {
			seen[id] = true
			ordered = append(ordered, id)
		}
	}
	for _, r := range roles {
		switch r.Scope {
		case ScopeAll:
			scope.All = true
		case ScopeSelf:
			scope.Self = true
		case ScopeDepartment:
			add(a.DepartmentID)
		case ScopeDescendants:
			add(a.DepartmentID)
			// Walk the snapshot in order so the result is deterministic.
			below := s.Descendants(a.DepartmentID)
			for _, d := range s.Departments {
				if below[d.ID] {
					add(d.ID)
				}
			}
		case ScopeCustom:
			for _, id := range r.DepartmentIDs {
				add(id)
			}
		}
	}
	for _, id := range ordered {
		if s.ActiveDepartment(id) {
			scope.Departments = append(scope.Departments, id)
		}
	}
	return scope
}

// Principal computes an account's live grants. It returns false when the
// account is missing, disabled, or belongs to an inactive department.
func (s *Snapshot) Principal(id string) (*Principal, bool) {
	a := s.account(id)
	if a == nil || !a.Enabled || !s.ActiveDepartment(a.DepartmentID) {
		return nil, false
	}
	roles := s.accountRoles(a)
	admin := hasAdmin(roles)
	granted := map[string]bool{}
	for _, r := range roles {
		for _, pid := range r.PermissionIDs {
			granted[pid] = true
		}
	}
	p := &Principal{
		ID:           a.ID,
		Email:        a.Email,
		Name:         a.Name,
		Roles:        []string{},
		Permissions:  []string{},
		DataScopes:   map[string]DataScope{},
		Routes:       []string{},
		DepartmentID: a.DepartmentID,
		DataScope:    s.dataScope(a, roles),
	}
	for _, r := range roles {
		p.Roles = append(p.Roles, r.Code)
	}
	for _, perm := range s.Permissions {
		if admin || granted[perm.ID] {
			p.Permissions = append(p.Permissions, perm.Code)
		}
	}
	// Scopes are computed per capability, only across roles that grant that
	// capability: read-all plus write-self never becomes write-all.
	for _, code := range p.Permissions {
		var capabilityID string
		for _, perm := range s.Permissions {
			if perm.Code == code {
				capabilityID = perm.ID
				break
			}
		}
		var granting []Role
		for _, r := range roles {
			if r.ID == AdminRoleID || (capabilityID != "" && slices.Contains(r.PermissionIDs, capabilityID)) {
				granting = append(granting, r)
			}
		}
		p.DataScopes[code] = s.dataScope(a, granting)
	}
	for _, m := range s.navigation(p, roles, false) {
		if m.Kind == "page" {
			if r, ok := routeByID(m.RouteID); ok {
				p.Routes = append(p.Routes, r.Path)
			}
		}
	}
	return p, true
}

// Navigation returns the menus an account may see in the sidebar: enabled and
// visible pages it is granted, plus their parent directories.
func (s *Snapshot) Navigation(p *Principal) []Menu {
	a := s.account(p.ID)
	if a == nil {
		return []Menu{}
	}
	return s.navigation(p, s.accountRoles(a), true)
}

func (s *Snapshot) navigation(p *Principal, roles []Role, visibleOnly bool) []Menu {
	admin := hasAdmin(roles)
	grants := map[string]bool{}
	for _, r := range roles {
		for _, id := range r.MenuIDs {
			grants[id] = true
		}
	}
	allowed := map[string]bool{}
	parents := map[string]bool{}
	for _, m := range s.Menus {
		parent := s.menu(m.ParentID)
		if m.Kind != "page" || !m.Enabled || (parent != nil && !parent.Enabled) {
			continue
		}
		if visibleOnly && (!m.Visible || (parent != nil && !parent.Visible)) {
			continue
		}
		if m.RouteID != DashboardRouteID && !admin && !grants[m.ID] && !grants[m.ParentID] {
			continue
		}
		route, ok := routeByID(m.RouteID)
		if !ok || (route.Permission != "" && !p.Has(route.Permission)) {
			continue
		}
		allowed[m.ID] = true
		parents[m.ParentID] = true
	}
	result := []Menu{}
	for _, m := range s.Menus {
		if allowed[m.ID] || parents[m.ID] {
			result = append(result, m)
		}
	}
	slices.SortStableFunc(result, func(a, b Menu) int {
		return cmp.Or(cmp.Compare(a.Order, b.Order), strings.Compare(a.ID, b.ID))
	})
	return result
}

// Record is the ownership of a business record used for data-scope checks.
type Record struct {
	ID           string // account records: the account id counts as "self"
	DepartmentID string
	CreatedBy    string
}

// CanAccess reports whether the principal may touch a record through a
// capability. A missing scope denies.
func (p *Principal) CanAccess(r Record, permission string) bool {
	if p == nil {
		return false
	}
	scope, ok := p.DataScopes[permission]
	if !ok {
		return false
	}
	return scope.All ||
		(r.DepartmentID != "" && slices.Contains(scope.Departments, r.DepartmentID)) ||
		(scope.Self && ((r.CreatedBy != "" && r.CreatedBy == p.ID) || (r.ID != "" && r.ID == p.ID)))
}

// CanWriteDepartment reports whether new business records may be placed in a
// department through users:write.
func (p *Principal) CanWriteDepartment(departmentID string) bool {
	scope, ok := p.DataScopes["users:write"]
	return ok && (scope.All || slices.Contains(scope.Departments, departmentID) ||
		(scope.Self && p.DepartmentID == departmentID))
}

// ScopeFilter describes a data scope as a row filter, for storage layers that
// filter in SQL before sorting, paging and counting.
type ScopeFilter struct {
	All           bool
	DepartmentIDs []string
	// SelfID is the actor id when "self" applies, otherwise empty.
	SelfID string
}

// Filter returns the row filter of a capability. A principal without the
// capability gets a filter that matches nothing.
func (p *Principal) Filter(permission string) ScopeFilter {
	scope, ok := p.DataScopes[permission]
	if !ok {
		return ScopeFilter{DepartmentIDs: []string{}}
	}
	f := ScopeFilter{All: scope.All, DepartmentIDs: slices.Clone(scope.Departments)}
	if scope.Self {
		f.SelfID = p.ID
	}
	return f
}
