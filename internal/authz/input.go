package authz

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Request bodies of the system-management API. They mirror the strict Zod
// objects in src/contract/system.ts: unknown fields, null values and missing
// required fields are rejected; strings are trimmed where the contract trims.

type AccountInput struct {
	Name         string   `json:"name"`
	Email        string   `json:"email"`
	Enabled      bool     `json:"enabled"`
	DepartmentID string   `json:"departmentId"`
	RoleIDs      []string `json:"roleIds"`
	Password     *string  `json:"password,omitempty"`
}

type RoleInput struct {
	Name          string   `json:"name"`
	Code          string   `json:"code"`
	Enabled       bool     `json:"enabled"`
	PermissionIDs []string `json:"permissionIds"`
	MenuIDs       []string `json:"menuIds"`
	Scope         string   `json:"scope"`
	DepartmentIDs []string `json:"departmentIds"`
}

type PermissionInput struct {
	Name        string `json:"name"`
	Code        string `json:"code"`
	Description string `json:"description"`
}

type MenuInput struct {
	Name     string `json:"name"`
	ParentID string `json:"parentId"`
	Kind     string `json:"kind"`
	RouteID  string `json:"routeId"`
	Enabled  bool   `json:"enabled"`
	Visible  bool   `json:"visible"`
	Order    int    `json:"order"`
}

type DepartmentInput struct {
	Name     string `json:"name"`
	Code     string `json:"code"`
	ParentID string `json:"parentId"`
	Enabled  bool   `json:"enabled"`
}

const msgCheckInput = "请检查输入。"

var (
	codePattern  = regexp.MustCompile(`^[a-z][a-z0-9:_-]{1,79}$`)
	emailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
)

// invalidFields is returned for a body that fails schema validation.
func invalidFields(message string) *RuleError {
	return &RuleError{Status: 422, Code: CodeInvalidFields, Message: message}
}

// decodeStrict decodes a JSON object into dst after checking that it holds
// only allowed keys, every required key, and no nulls.
func decodeStrict(body []byte, fields []string, optional map[string]bool, dst any) *RuleError {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || raw == nil {
		return invalidFields(msgCheckInput)
	}
	allowed := map[string]bool{}
	for _, f := range fields {
		allowed[f] = true
		if _, ok := raw[f]; !ok && !optional[f] {
			return invalidFields(msgCheckInput)
		}
	}
	for key, value := range raw {
		if !allowed[key] || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return invalidFields(msgCheckInput)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return invalidFields(msgCheckInput)
	}
	return nil
}

func checkName(name *string) *RuleError {
	*name = strings.TrimSpace(*name)
	switch n := utf8.RuneCountInString(*name); {
	case n < 1:
		return invalidFields("请输入名称。")
	case n > 80:
		return invalidFields("名称最多 80 字。")
	}
	return nil
}

func checkCode(code string) *RuleError {
	if !codePattern.MatchString(code) {
		return invalidFields("代码使用小写字母、数字、冒号、下划线或连字符。")
	}
	return nil
}

func checkIDs(ids []string, min int, minMessage string) *RuleError {
	if ids == nil {
		return invalidFields(msgCheckInput)
	}
	if len(ids) < min {
		return invalidFields(minMessage)
	}
	if len(ids) > 200 {
		return invalidFields(msgCheckInput)
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if l := utf8.RuneCountInString(id); l < 1 || l > 100 {
			return invalidFields(msgCheckInput)
		}
		if seen[id] {
			return invalidFields("不能重复选择。")
		}
		seen[id] = true
	}
	return nil
}

func maxLen(value string, n int) *RuleError {
	if utf8.RuneCountInString(value) > n {
		return invalidFields(msgCheckInput)
	}
	return nil
}

func firstError(errs ...*RuleError) *RuleError {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// ParseAccount validates an account body. The password is optional here; the
// create rule is enforced in Apply, exactly like the reference mock.
func ParseAccount(body []byte) (AccountInput, *RuleError) {
	var in AccountInput
	if err := decodeStrict(body, []string{"name", "email", "enabled", "departmentId", "roleIds", "password"},
		map[string]bool{"password": true}, &in); err != nil {
		return in, err
	}
	if err := checkName(&in.Name); err != nil {
		return in, err
	}
	if !emailPattern.MatchString(in.Email) {
		return in, invalidFields("请输入有效邮箱。")
	}
	in.Email = strings.ToLower(in.Email)
	if l := utf8.RuneCountInString(in.DepartmentID); l < 1 || l > 100 {
		return in, invalidFields(msgCheckInput)
	}
	if err := checkIDs(in.RoleIDs, 1, "至少选择一个角色。"); err != nil {
		return in, err
	}
	if in.Password != nil {
		if utf8.RuneCountInString(*in.Password) < 8 {
			return in, invalidFields("密码至少 8 位。")
		}
		if utf8.RuneCountInString(*in.Password) > 128 {
			return in, invalidFields(msgCheckInput)
		}
	}
	return in, nil
}

func ParseRole(body []byte) (RoleInput, *RuleError) {
	var in RoleInput
	if err := decodeStrict(body, []string{"name", "code", "enabled", "permissionIds", "menuIds", "scope", "departmentIds"}, nil, &in); err != nil {
		return in, err
	}
	if err := firstError(
		checkName(&in.Name),
		checkCode(in.Code),
		checkIDs(in.PermissionIDs, 0, ""),
		checkIDs(in.MenuIDs, 0, ""),
	); err != nil {
		return in, err
	}
	switch in.Scope {
	case ScopeAll, ScopeDepartment, ScopeDescendants, ScopeSelf, ScopeCustom:
	default:
		return in, invalidFields(msgCheckInput)
	}
	if err := checkIDs(in.DepartmentIDs, 0, ""); err != nil {
		return in, err
	}
	if in.Scope == ScopeCustom && len(in.DepartmentIDs) == 0 {
		return in, invalidFields("请选择数据范围部门。")
	}
	return in, nil
}

func ParsePermission(body []byte) (PermissionInput, *RuleError) {
	var in PermissionInput
	if err := decodeStrict(body, []string{"name", "code", "description"}, nil, &in); err != nil {
		return in, err
	}
	in.Description = strings.TrimSpace(in.Description)
	return in, firstError(checkName(&in.Name), checkCode(in.Code), maxLen(in.Description, 200))
}

func ParseMenu(body []byte) (MenuInput, *RuleError) {
	var in MenuInput
	if err := decodeStrict(body, []string{"name", "parentId", "kind", "routeId", "enabled", "visible", "order"}, nil, &in); err != nil {
		return in, err
	}
	if err := firstError(checkName(&in.Name), maxLen(in.ParentID, 100)); err != nil {
		return in, err
	}
	if in.Kind != "directory" && in.Kind != "page" {
		return in, invalidFields(msgCheckInput)
	}
	if err := maxLen(in.RouteID, 100); err != nil {
		return in, err
	}
	if in.Order < 0 || in.Order > 9999 {
		return in, invalidFields(msgCheckInput)
	}
	return in, nil
}

func ParseDepartment(body []byte) (DepartmentInput, *RuleError) {
	var in DepartmentInput
	if err := decodeStrict(body, []string{"name", "code", "parentId", "enabled"}, nil, &in); err != nil {
		return in, err
	}
	return in, firstError(checkName(&in.Name), checkCode(in.Code), maxLen(in.ParentID, 100))
}
