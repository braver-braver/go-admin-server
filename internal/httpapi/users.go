package httpapi

import (
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/braver-braver/go-admin-server/internal/apierr"
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
func parseUser(body []byte) (store.UserFields, bool, error) {
	var raw map[string]any
	_ = json.Unmarshal(body, &raw)
	text := func(key string) (string, bool) {
		v, ok := raw[key].(string)
		v = strings.TrimSpace(v)
		return v, ok && v != ""
	}
	var f store.UserFields
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

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	sess := s.guard(w, r, "users:read")
	if sess == nil {
		return
	}
	q := r.URL.Query()
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
	if _, ok := store.SortKeys()[sortBy]; !ok {
		sortBy = "username"
	}
	order := "asc"
	if q.Get("sortOrder") == "desc" {
		order = "desc"
	}
	list, err := s.store.ListUsers(r.Context(), sess.user.Filter("users:read"), store.UsersQuery{
		Page:   store.Page{Page: positiveInt(q.Get("page"), 1), PageSize: pageSizeOf(q.Get("pageSize"))},
		Search: strings.TrimSpace(q.Get("username")),
		Status: multi("status", userStatuses), Role: multi("role", userRoles),
		SortBy: sortBy, SortOrder: order,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeData(w, http.StatusOK, list)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	sess := s.guard(w, r, "users:write")
	if sess == nil {
		return
	}
	f, _, err := parseUser(readJSON(w, r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	u, err := s.store.CreateUser(r.Context(), sess.user, sess.snap, sess.actor(), newID(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeData(w, http.StatusCreated, u)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	sess := s.guard(w, r, "users:write")
	if sess == nil {
		return
	}
	body := readJSON(w, r)
	u, err := s.store.UpdateUser(r.Context(), sess.user, sess.snap, sess.actor(), r.PathValue("id"),
		func() (store.UserFields, bool, error) { return parseUser(body) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeData(w, http.StatusOK, u)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	sess := s.guard(w, r, "users:write")
	if sess == nil {
		return
	}
	if err := s.store.DeleteUser(r.Context(), sess.user, sess.actor(), r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	writeData(w, http.StatusOK, map[string]bool{"success": true})
}

// readIDs mirrors the mock: a body without an `ids` array selects nothing;
// non-string entries are skipped.
func readIDs(raw map[string]any) []string {
	list, _ := raw["ids"].([]any)
	ids := []string{}
	for _, v := range list {
		if s, ok := v.(string); ok {
			ids = append(ids, s)
		}
	}
	return ids
}

func readObject(w http.ResponseWriter, r *http.Request) map[string]any {
	var raw map[string]any
	_ = json.Unmarshal(readJSON(w, r), &raw)
	return raw
}

func (s *Server) batchDeleteUsers(w http.ResponseWriter, r *http.Request) {
	sess := s.guard(w, r, "users:write")
	if sess == nil {
		return
	}
	n, err := s.store.BatchDeleteUsers(r.Context(), sess.user, sess.actor(), readIDs(readObject(w, r)))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeData(w, http.StatusOK, map[string]int{"deletedCount": n})
}

func (s *Server) updateUsersStatus(w http.ResponseWriter, r *http.Request) {
	sess := s.guard(w, r, "users:write")
	if sess == nil {
		return
	}
	raw := readObject(w, r)
	status, _ := raw["status"].(string)
	if status != "active" && status != "inactive" {
		writeError(w, apierr.New(422, "INVALID_STATUS", "状态只允许启用或停用。"))
		return
	}
	n, err := s.store.SetUsersStatus(r.Context(), sess.user, sess.actor(), readIDs(raw), status)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeData(w, http.StatusOK, map[string]int{"updatedCount": n})
}

func (s *Server) inviteUser(w http.ResponseWriter, r *http.Request) {
	sess := s.guard(w, r, "users:write")
	if sess == nil {
		return
	}
	raw := readObject(w, r)
	email, _ := raw["email"].(string)
	email = strings.TrimSpace(email)
	if !userEmail.MatchString(email) {
		writeError(w, apierr.New(422, "INVALID_EMAIL", "请输入有效邮箱。"))
		return
	}
	role, _ := raw["role"].(string)
	if !slices.Contains(userRoles, role) {
		writeError(w, apierr.New(422, "INVALID_ROLE", "角色不在允许范围内。"))
		return
	}
	u, err := s.store.InviteUser(r.Context(), sess.user, sess.actor(), newID(), email, role)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeData(w, http.StatusCreated, u)
}

func (s *Server) batchInviteUsers(w http.ResponseWriter, r *http.Request) {
	sess := s.guard(w, r, "users:write")
	if sess == nil {
		return
	}
	n, err := s.store.BatchInviteUsers(r.Context(), sess.user, sess.actor(), readIDs(readObject(w, r)))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeData(w, http.StatusOK, map[string]int{"invitedCount": n})
}
