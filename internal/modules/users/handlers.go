package users

import (
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/braver-braver/go-admin-server/internal/apierr"
	"github.com/braver-braver/go-admin-server/internal/httpx"
	"github.com/braver-braver/go-admin-server/internal/store"
)

var (
	userEmail      = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	userRoles      = []string{"superadmin", "admin", "manager", "cashier"}
	userStatuses   = []string{"active", "inactive", "invited", "suspended"}
	fieldsRequired = "请完整填写必填字段。"
)

func invalidUser(message string) *apierr.Error {
	return apierr.New(422, "INVALID_USER_FIELDS", message)
}

// parseUser mirrors userWriteSchema: unknown fields are ignored and a missing
// required field is reported before any other problem.
func parseUser(body []byte) (UserFields, bool, error) {
	var raw map[string]any
	_ = json.Unmarshal(body, &raw)
	text := func(key string) (string, bool) {
		v, ok := raw[key].(string)
		v = strings.TrimSpace(v)
		return v, ok && v != ""
	}
	var f UserFields
	var ok [6]bool
	f.FirstName, ok[0] = text("firstName")
	f.LastName, ok[1] = text("lastName")
	f.Username, ok[2] = text("username")
	f.Email, ok[3] = text("email")
	f.PhoneNumber, ok[4] = text("phoneNumber")
	f.Role, ok[5] = text("role")
	if slices.Contains(ok[:], false) {
		return f, false, invalidUser(fieldsRequired)
	}
	if !userEmail.MatchString(f.Email) {
		return f, false, invalidUser("邮箱格式不正确。")
	}
	if !slices.Contains(userRoles, f.Role) {
		return f, false, invalidUser("角色不在允许范围内。")
	}
	if v, present := raw["password"]; present {
		pw, isString := v.(string)
		if !isString || utf8.RuneCountInString(pw) < 8 || utf8.RuneCountInString(pw) > 128 {
			return f, false, invalidUser("密码至少需要 8 位字符。")
		}
	}
	optional := func(key string) (string, bool, error) {
		v, present := raw[key]
		if !present {
			return "", false, nil
		}
		s, isString := v.(string)
		if !isString {
			return "", true, invalidUser("请检查输入。")
		}
		return strings.TrimSpace(s), true, nil
	}
	var err error
	if f.DepartmentID, _, err = optional("departmentId"); err != nil {
		return f, false, err
	}
	var avatarSet bool
	if f.AvatarURL, avatarSet, err = optional("avatarUrl"); err != nil {
		return f, false, err
	}
	return f, avatarSet, nil
}

func (m *Module) listUsers(c *httpx.Ctx) {
	sess := c.Session
	q := c.R.URL.Query()
	multi := func(key string, allowed []string) []string {
		var out []string
		for _, v := range q[key] {
			if v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	sortBy := q.Get("sortBy")
	if _, ok := SortKeys()[sortBy]; !ok {
		sortBy = "username"
	}
	order := "asc"
	if q.Get("sortOrder") == "desc" {
		order = "desc"
	}
	list, err := m.repo.ListUsers(c.Context(), sess.User.Filter("users:read"), UsersQuery{
		Page:   store.Page{Page: httpx.PositiveInt(q.Get("page"), 1), PageSize: min(100, httpx.PositiveInt(q.Get("pageSize"), 10))},
		Search: strings.TrimSpace(q.Get("username")),
		Status: multi("status", userStatuses), Role: multi("role", userRoles),
		SortBy: sortBy, SortOrder: order,
	})
	if err != nil {
		c.Fail(err)
		return
	}
	httpx.WriteData(c.W, http.StatusOK, list)
}

func (m *Module) createUser(c *httpx.Ctx) {
	sess := c.Session
	f, _, err := parseUser(c.Body())
	if err != nil {
		c.Fail(err)
		return
	}
	u, err := m.repo.CreateUser(c.Context(), sess.User, sess.Snap, sess.Actor(), httpx.NewID(), f)
	if err != nil {
		c.Fail(err)
		return
	}
	httpx.WriteData(c.W, http.StatusCreated, u)
}

func (m *Module) updateUser(c *httpx.Ctx) {
	sess := c.Session
	body := c.Body()
	u, err := m.repo.UpdateUser(c.Context(), sess.User, sess.Snap, sess.Actor(), c.R.PathValue("id"),
		func() (UserFields, bool, error) { return parseUser(body) })
	if err != nil {
		c.Fail(err)
		return
	}
	httpx.WriteData(c.W, http.StatusOK, u)
}

func (m *Module) deleteUser(c *httpx.Ctx) {
	sess := c.Session
	if err := m.repo.DeleteUser(c.Context(), sess.User, sess.Actor(), c.R.PathValue("id")); err != nil {
		c.Fail(err)
		return
	}
	httpx.WriteData(c.W, http.StatusOK, map[string]bool{"success": true})
}

func (m *Module) batchDeleteUsers(c *httpx.Ctx) {
	sess := c.Session
	n, err := m.repo.BatchDeleteUsers(c.Context(), sess.User, sess.Actor(), httpx.IDs(c.Object()))
	if err != nil {
		c.Fail(err)
		return
	}
	httpx.WriteData(c.W, http.StatusOK, map[string]int{"deletedCount": n})
}

func (m *Module) updateUsersStatus(c *httpx.Ctx) {
	sess := c.Session
	raw := c.Object()
	status, _ := raw["status"].(string)
	if status != "active" && status != "inactive" {
		httpx.WriteError(c.W, apierr.New(422, "INVALID_STATUS", "状态只允许启用或停用。"))
		return
	}
	n, err := m.repo.SetUsersStatus(c.Context(), sess.User, sess.Actor(), httpx.IDs(raw), status)
	if err != nil {
		c.Fail(err)
		return
	}
	httpx.WriteData(c.W, http.StatusOK, map[string]int{"updatedCount": n})
}

func (m *Module) inviteUser(c *httpx.Ctx) {
	sess := c.Session
	raw := c.Object()
	email, _ := raw["email"].(string)
	email = strings.TrimSpace(email)
	if !userEmail.MatchString(email) {
		httpx.WriteError(c.W, apierr.New(422, "INVALID_EMAIL", "请输入有效邮箱。"))
		return
	}
	role, _ := raw["role"].(string)
	if !slices.Contains(userRoles, role) {
		httpx.WriteError(c.W, apierr.New(422, "INVALID_ROLE", "角色不在允许范围内。"))
		return
	}
	u, err := m.repo.InviteUser(c.Context(), sess.User, sess.Actor(), httpx.NewID(), email, role)
	if err != nil {
		c.Fail(err)
		return
	}
	httpx.WriteData(c.W, http.StatusCreated, u)
}

func (m *Module) batchInviteUsers(c *httpx.Ctx) {
	sess := c.Session
	n, err := m.repo.BatchInviteUsers(c.Context(), sess.User, sess.Actor(), httpx.IDs(c.Object()))
	if err != nil {
		c.Fail(err)
		return
	}
	httpx.WriteData(c.W, http.StatusOK, map[string]int{"invitedCount": n})
}
