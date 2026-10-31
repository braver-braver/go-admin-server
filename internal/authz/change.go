package authz

import "slices"

// Error codes produced by the kernel (see src/contract/errors.ts).
const (
	CodeSystemRule    = "SYSTEM_RULE"
	CodeInvalidFields = "INVALID_FIELDS"
)

// RuleError is a rejected change. Status is the HTTP status to send.
type RuleError struct {
	Status  int
	Code    string
	Message string
}

func (e *RuleError) Error() string { return e.Message }

func rule(status int, message string) *RuleError {
	return &RuleError{Status: status, Code: CodeSystemRule, Message: message}
}

func deny(message string) *RuleError     { return rule(403, message) }
func conflict(message string) *RuleError { return rule(409, message) }
func invalid(message string) *RuleError  { return rule(422, message) }

// Change is one system-management write.
type Change struct {
	Resource string
	// ID is the target record; empty for a create.
	ID string
	// NewID is the id given to a created record.
	NewID  string
	Remove bool
	// Body is the raw JSON body of a create or update.
	Body []byte
	// ActorID and ActorCredentialVersion identify the session that asked.
	ActorID                string
	ActorCredentialVersion int
	// DepartmentInUse is set by the caller when a department to delete still
	// owns business records, which live outside the snapshot.
	DepartmentInUse bool
}

// PasswordReset asks the caller to hash and store a new password.
type PasswordReset struct {
	AccountID string
	Password  string
}

// Result is an accepted change.
type Result struct {
	// After is the full configuration once the change is applied.
	After *Snapshot
	// Record is the created or updated record; nil for a delete.
	Record any
	// Password is set when an account password must be (re)hashed.
	Password *PasswordReset
}

// Apply validates a system-management change against the live configuration
// and returns the configuration after it. Callers must serialize Apply calls
// (the reference mock queues writes; the database layer takes a lock).
func Apply(before *Snapshot, c Change) (*Result, *RuleError) {
	if c.Resource == ResDepartments && c.Remove && c.DepartmentInUse {
		return nil, conflict("该部门仍有关联业务用户，不能删除。")
	}
	actor, ok := before.Principal(c.ActorID)
	if !ok || before.CredentialVersions[c.ActorID] != c.ActorCredentialVersion {
		return nil, rule(401, "登录状态已变化，请重新登录。")
	}
	writeCap := "system:" + c.Resource + ":write"
	if !actor.Has(writeCap) {
		return nil, deny("没有执行该操作的权限。")
	}
	db := before.Clone()
	exists, protected := db.exists(c.Resource, c.ID)
	if c.ID != "" && !exists {
		return nil, rule(404, "记录不存在，请刷新后重试。")
	}
	if c.Resource != ResAccounts && !actor.DataScopes[writeCap].All {
		return nil, deny("系统配置需要全部数据范围。")
	}
	if c.Resource == ResAccounts && exists {
		a := db.account(c.ID)
		if !actor.CanAccess(Record{ID: a.ID, DepartmentID: a.DepartmentID}, writeCap) {
			return nil, deny("不能访问其他部门的账号。")
		}
	}
	if protected && (c.Remove || c.Resource != ResPermissions) {
		return nil, conflict("内置恢复入口和超级管理员不可变更。")
	}

	res := &Result{After: db}
	var err *RuleError
	if c.Remove {
		err = db.remove(c.Resource, c.ID)
	} else {
		id := c.ID
		if id == "" {
			id = c.NewID
		}
		switch c.Resource {
		case ResAccounts:
			err = db.putAccount(actor, c, id, protected, res)
		case ResRoles:
			err = db.putRole(actor, c, id, protected, res)
		case ResPermissions:
			err = db.putPermission(c, id, protected, res)
		case ResMenus:
			err = db.putMenu(c, id, protected, res)
		case ResDepartments:
			err = db.putDepartment(c, id, protected, res)
		default:
			err = rule(404, "未知系统资源。")
		}
	}
	if err != nil {
		return nil, err
	}
	if c.Resource == ResDepartments && exists && !c.Remove {
		if err := assertDepartmentChangeWithinGrants(actor, before, db); err != nil {
			return nil, err
		}
	}
	// The super administrator role always holds every permission and menu.
	syncAdminRole(db)
	return res, nil
}

// exists reports whether a record exists and whether it is protected.
func (s *Snapshot) exists(resource, id string) (bool, bool) {
	if id == "" {
		return false, false
	}
	switch resource {
	case ResAccounts:
		if r := s.account(id); r != nil {
			return true, r.Protected
		}
	case ResRoles:
		if r := s.role(id); r != nil {
			return true, r.Protected
		}
	case ResPermissions:
		if r := s.permission(id); r != nil {
			return true, r.Protected
		}
	case ResMenus:
		if r := s.menu(id); r != nil {
			return true, r.Protected
		}
	case ResDepartments:
		if r := s.department(id); r != nil {
			return true, r.Protected
		}
	}
	return false, false
}

func (s *Snapshot) remove(resource, id string) *RuleError {
	referenced := false
	for _, a := range s.Accounts {
		if (resource == ResRoles && slices.Contains(a.RoleIDs, id)) ||
			(resource == ResDepartments && a.DepartmentID == id) {
			referenced = true
		}
	}
	for _, r := range s.Roles {
		if r.ID == AdminRoleID {
			continue
		}
		if (resource == ResPermissions && slices.Contains(r.PermissionIDs, id)) ||
			(resource == ResMenus && slices.Contains(r.MenuIDs, id)) ||
			(resource == ResDepartments && slices.Contains(r.DepartmentIDs, id)) {
			referenced = true
		}
	}
	if resource == ResMenus {
		referenced = referenced || slices.ContainsFunc(s.Menus, func(m Menu) bool { return m.ParentID == id })
	}
	if resource == ResDepartments {
		referenced = referenced || slices.ContainsFunc(s.Departments, func(d Department) bool { return d.ParentID == id })
	}
	if referenced {
		return conflict("该记录仍被引用，请先解除关联或处理下级。")
	}
	switch resource {
	case ResAccounts:
		s.Accounts = slices.DeleteFunc(s.Accounts, func(a Account) bool { return a.ID == id })
		delete(s.CredentialVersions, id)
	case ResRoles:
		s.Roles = slices.DeleteFunc(s.Roles, func(r Role) bool { return r.ID == id })
	case ResPermissions:
		s.Permissions = slices.DeleteFunc(s.Permissions, func(p Permission) bool { return p.ID == id })
	case ResMenus:
		s.Menus = slices.DeleteFunc(s.Menus, func(m Menu) bool { return m.ID == id })
	case ResDepartments:
		s.Departments = slices.DeleteFunc(s.Departments, func(d Department) bool { return d.ID == id })
	}
	return nil
}

// references rejects ids that do not exist.
func (s *Snapshot) references(ids []string, resource string) *RuleError {
	for _, id := range ids {
		if ok, _ := s.exists(resource, id); !ok {
			return invalid("所选关联记录不存在，请刷新后重试。")
		}
	}
	return nil
}

// upsert replaces a record in place or appends it.
func upsert[T any](list []T, id string, idOf func(T) string, record T) []T {
	for i := range list {
		if idOf(list[i]) == id {
			list[i] = record
			return list
		}
	}
	return append(list, record)
}

func (s *Snapshot) putAccount(actor *Principal, c Change, id string, protected bool, res *Result) *RuleError {
	in, err := ParseAccount(c.Body)
	if err != nil {
		return err
	}
	if err := s.references(in.RoleIDs, ResRoles); err != nil {
		return err
	}
	if err := s.references([]string{in.DepartmentID}, ResDepartments); err != nil {
		return err
	}
	if !s.ActiveDepartment(in.DepartmentID) {
		return invalid("请选择启用的部门。")
	}
	if slices.Contains(in.RoleIDs, AdminRoleID) {
		return deny("超级管理员角色仅保留给内置恢复账号。")
	}
	for _, other := range s.Accounts {
		if other.ID != c.ID && other.Email == in.Email {
			return conflict("该邮箱已存在。")
		}
	}
	if c.ID == "" && in.Password == nil {
		return invalid("创建登录用户必须设置初始密码。")
	}
	record := Account{
		Resource: ResAccounts, ID: id, Protected: protected, Name: in.Name, Email: in.Email,
		Enabled: in.Enabled, DepartmentID: in.DepartmentID, RoleIDs: in.RoleIDs,
	}
	existing := s.account(c.ID)
	if existing != nil && existing.DepartmentID != record.DepartmentID && !actor.DataScopes["system:accounts:write"].All {
		return deny("调整登录账号所属部门需要全部账号管理范围。")
	}
	if !actor.CanAccess(Record{ID: record.ID, DepartmentID: record.DepartmentID}, "system:accounts:write") {
		return deny("账号部门超出当前数据范围。")
	}
	// Validate what the account would hold once enabled, with its roles
	// enabled: a disabled account or role must not smuggle in grants.
	candidate := s.Clone()
	enabled := record
	enabled.Enabled = true
	candidate.Accounts = upsert(candidate.Accounts, id, func(a Account) string { return a.ID }, enabled)
	for i := range candidate.Roles {
		if slices.Contains(in.RoleIDs, candidate.Roles[i].ID) {
			candidate.Roles[i].Enabled = true
		}
	}
	if recipient, ok := candidate.Principal(id); ok {
		if err := assertDelegation(actor, recipient); err != nil {
			return err
		}
	}
	if existing != nil && existing.Enabled != in.Enabled && in.Password == nil {
		s.CredentialVersions[id]++
	}
	if in.Password != nil {
		if v, ok := s.CredentialVersions[id]; ok {
			s.CredentialVersions[id] = v + 1
		} else {
			s.CredentialVersions[id] = 0
		}
		res.Password = &PasswordReset{AccountID: id, Password: *in.Password}
	}
	s.Accounts = upsert(s.Accounts, id, func(a Account) string { return a.ID }, record)
	res.Record = record
	return nil
}

func (s *Snapshot) putRole(actor *Principal, c Change, id string, protected bool, res *Result) *RuleError {
	in, err := ParseRole(c.Body)
	if err != nil {
		return err
	}
	if err := firstError(
		s.references(in.PermissionIDs, ResPermissions),
		s.references(in.MenuIDs, ResMenus),
		s.references(in.DepartmentIDs, ResDepartments),
	); err != nil {
		return err
	}
	for _, pid := range in.PermissionIDs {
		if p := s.permission(pid); p != nil && !actor.Has(p.Code) {
			return deny("不能授予自己未持有的权限。")
		}
	}
	record := Role{
		Resource: ResRoles, ID: id, Protected: protected, Name: in.Name, Code: in.Code, Enabled: in.Enabled,
		PermissionIDs: in.PermissionIDs, MenuIDs: in.MenuIDs, Scope: in.Scope, DepartmentIDs: in.DepartmentIDs,
	}
	if err := s.uniqueCode(ResRoles, c.ID, record.Code); err != nil {
		return err
	}
	candidate := s.Clone()
	candidate.Roles = upsert(candidate.Roles, id, func(r Role) string { return r.ID }, record)
	// A new role must not exceed the actor's own bounds even before it is
	// assigned: check the actor as if it held the role.
	if a := candidate.account(actor.ID); a != nil {
		hypothetical := candidate.Clone()
		ha := hypothetical.account(actor.ID)
		ha.RoleIDs = append(ha.RoleIDs, record.ID)
		if p, ok := hypothetical.Principal(actor.ID); ok {
			if err := assertDelegation(actor, p); err != nil {
				return err
			}
		}
	}
	// A shared role changes every assignee's grants: check each of them.
	for _, a := range s.Accounts {
		if !slices.Contains(a.RoleIDs, record.ID) {
			continue
		}
		if recipient, ok := candidate.Principal(a.ID); ok {
			if err := assertDelegation(actor, recipient); err != nil {
				return err
			}
		}
	}
	s.Roles = upsert(s.Roles, id, func(r Role) string { return r.ID }, record)
	res.Record = record
	return nil
}

func (s *Snapshot) putPermission(c Change, id string, protected bool, res *Result) *RuleError {
	in, err := ParsePermission(c.Body)
	if err != nil {
		return err
	}
	if existing := s.permission(c.ID); existing != nil && existing.Protected && in.Code != existing.Code {
		return conflict("内置权限代码不可修改。")
	}
	record := Permission{
		Resource: ResPermissions, ID: id, Protected: protected, Name: in.Name, Code: in.Code, Description: in.Description,
	}
	if err := s.uniqueCode(ResPermissions, c.ID, record.Code); err != nil {
		return err
	}
	s.Permissions = upsert(s.Permissions, id, func(p Permission) string { return p.ID }, record)
	res.Record = record
	return nil
}

func (s *Snapshot) putMenu(c Change, id string, protected bool, res *Result) *RuleError {
	in, err := ParseMenu(c.Body)
	if err != nil {
		return err
	}
	if in.ParentID != "" {
		parent := s.menu(in.ParentID)
		if parent == nil || parent.Kind != "directory" || in.Kind != "page" || in.ParentID == c.ID {
			return invalid("目录必须位于根层，页面只能挂在根层或目录下。")
		}
	}
	if in.Kind == "directory" && in.RouteID != "" {
		return invalid("目录不绑定页面。")
	}
	if _, ok := s.route(in.RouteID); in.Kind == "page" && !ok {
		return invalid("只能绑定已注册页面。")
	}
	if in.Kind == "page" && slices.ContainsFunc(s.Menus, func(m Menu) bool { return m.ID != c.ID && m.RouteID == in.RouteID }) {
		return conflict("该页面已有菜单，请编辑现有菜单。")
	}
	if existing := s.menu(c.ID); existing != nil && existing.Kind == "directory" && in.Kind != "directory" &&
		slices.ContainsFunc(s.Menus, func(m Menu) bool { return m.ParentID == c.ID }) {
		return conflict("请先移走目录中的页面。")
	}
	record := Menu{
		Resource: ResMenus, ID: id, Protected: protected, Name: in.Name, ParentID: in.ParentID, Kind: in.Kind,
		RouteID: in.RouteID, Enabled: in.Enabled, Visible: in.Visible, Order: in.Order,
	}
	s.Menus = upsert(s.Menus, id, func(m Menu) string { return m.ID }, record)
	res.Record = record
	return nil
}

func (s *Snapshot) putDepartment(c Change, id string, protected bool, res *Result) *RuleError {
	in, err := ParseDepartment(c.Body)
	if err != nil {
		return err
	}
	if in.ParentID == "" {
		return invalid("新部门必须选择上级部门。")
	}
	if err := s.references([]string{in.ParentID}, ResDepartments); err != nil {
		return err
	}
	if !s.ActiveDepartment(in.ParentID) {
		return invalid("上级部门必须启用。")
	}
	if c.ID != "" && s.Descendants(c.ID)[in.ParentID] {
		return invalid("上级部门不能是自身或下级部门。")
	}
	record := Department{
		Resource: ResDepartments, ID: id, Protected: protected, Name: in.Name, Code: in.Code,
		ParentID: in.ParentID, Enabled: in.Enabled,
	}
	if err := s.uniqueCode(ResDepartments, c.ID, record.Code); err != nil {
		return err
	}
	s.Departments = upsert(s.Departments, id, func(d Department) string { return d.ID }, record)
	res.Record = record
	return nil
}

func (s *Snapshot) uniqueCode(resource, id, code string) *RuleError {
	taken := false
	switch resource {
	case ResRoles:
		taken = slices.ContainsFunc(s.Roles, func(r Role) bool { return r.ID != id && r.Code == code })
	case ResPermissions:
		taken = slices.ContainsFunc(s.Permissions, func(p Permission) bool { return p.ID != id && p.Code == code })
	case ResDepartments:
		taken = slices.ContainsFunc(s.Departments, func(d Department) bool { return d.ID != id && d.Code == code })
	}
	if taken {
		return conflict("该代码已存在。")
	}
	return nil
}

// assertDelegation rejects grants the actor does not hold itself: capabilities,
// wider per-capability data scopes, or pages.
func assertDelegation(actor, recipient *Principal) *RuleError {
	for _, perm := range recipient.Permissions {
		if !actor.Has(perm) {
			return deny("不能授予自己未持有的权限。")
		}
		own, ok1 := actor.DataScopes[perm]
		granted, ok2 := recipient.DataScopes[perm]
		if !ok1 || !ok2 || (!own.All && (granted.All ||
			slices.ContainsFunc(granted.Departments, func(d string) bool { return !slices.Contains(own.Departments, d) }) ||
			(granted.Self && !(own.Self && actor.ID == recipient.ID)))) {
			return deny("不能授予超出自身的数据范围。")
		}
	}
	for _, route := range recipient.Routes {
		if !slices.Contains(actor.Routes, route) {
			return deny("不能授予自己无权访问的页面。")
		}
	}
	return nil
}

// assertDepartmentChangeWithinGrants rejects a reparenting or enable/disable
// that would indirectly give any account permissions, data or pages beyond the
// actor's own grants (descendant scopes follow the tree).
func assertDepartmentChangeWithinGrants(actor *Principal, before, after *Snapshot) *RuleError {
	for _, a := range after.Accounts {
		previous, hadPrevious := before.Principal(a.ID)
		next, ok := after.Principal(a.ID)
		if !ok {
			continue
		}
		for _, perm := range next.Permissions {
			if !(hadPrevious && previous.Has(perm)) && !actor.Has(perm) {
				return deny("不能通过部门变更授予自己未持有的权限。")
			}
			afterScope, ok := next.DataScopes[perm]
			if !ok {
				continue
			}
			var beforeScope DataScope
			if hadPrevious {
				beforeScope = previous.DataScopes[perm]
			}
			gainedAll := afterScope.All && !beforeScope.All
			gainedSelf := afterScope.Self && !beforeScope.Self
			var gained []string
			if !beforeScope.All {
				for _, d := range afterScope.Departments {
					if !slices.Contains(beforeScope.Departments, d) {
						gained = append(gained, d)
					}
				}
			}
			if !gainedAll && !gainedSelf && len(gained) == 0 {
				continue
			}
			authorized, ok := actor.DataScopes[perm]
			if !ok || (gainedAll && !authorized.All) ||
				(gainedSelf && !authorized.All && !(authorized.Self && actor.ID == a.ID)) ||
				(!authorized.All && slices.ContainsFunc(gained, func(d string) bool { return !slices.Contains(authorized.Departments, d) })) {
				return deny("调整部门后授予的数据范围超出当前管理员授权。")
			}
		}
		for _, route := range next.Routes {
			if !(hadPrevious && slices.Contains(previous.Routes, route)) && !slices.Contains(actor.Routes, route) {
				return deny("不能通过部门变更授予自己无权访问的页面。")
			}
		}
	}
	return nil
}
