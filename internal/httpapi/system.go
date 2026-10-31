package httpapi

import (
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/braver-braver/go-admin-server/internal/apierr"
	"github.com/braver-braver/go-admin-server/internal/auth"
	"github.com/braver-braver/go-admin-server/internal/authz"
	"github.com/braver-braver/go-admin-server/internal/httpx"
	"github.com/braver-braver/go-admin-server/internal/store"
)

func (s *Server) systemOptions(c *httpx.Ctx) {
	sess := c.Session
	can := func(res string) bool { return sess.User.Has("system:" + res + ":read") }
	if !slices.ContainsFunc(authz.Resources, can) {
		httpx.WriteError(c.W, apierr.New(403, "FORBIDDEN", "没有查看系统配置的权限。"))
		return
	}
	snap := sess.Snap
	items := []any{}
	if can(authz.ResPermissions) {
		for _, p := range snap.Permissions {
			items = append(items, p)
		}
	}
	if can(authz.ResMenus) {
		for _, m := range snap.Menus {
			items = append(items, m)
		}
	}
	if can(authz.ResRoles) {
		for _, x := range snap.Roles {
			items = append(items, x)
		}
	}
	if can(authz.ResDepartments) {
		for _, d := range snap.Departments {
			if sess.User.CanAccess(authz.Record{DepartmentID: d.ID}, "system:departments:read") {
				items = append(items, d)
			}
		}
	}
	c.OK(map[string]any{"items": items})
}

// lenientInt mirrors `Math.trunc(Number(v) || fallback)` of the mock's
// system lists.
func lenientInt(v string, fallback int) int {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if v == "" || err != nil || math.IsNaN(f) || f == 0 {
		return fallback
	}
	return int(max(math.MinInt32, min(math.MaxInt32, math.Trunc(f))))
}

// system serves /system/{resource} and /system/{resource}/{id}, checking in
// the reference mock's order: request header, resource, session, capability,
// CSRF, then method/path agreement.
func (s *Server) system(w http.ResponseWriter, r *http.Request) {
	read := r.Method == http.MethodGet
	if !read && !s.checkWriteHeaders(w, r) {
		return
	}
	resource := r.PathValue("resource")
	if !slices.Contains(authz.Resources, resource) {
		httpx.WriteError(w, apierr.New(404, "NOT_FOUND", "未知系统资源。"))
		return
	}
	mode := "write"
	if read {
		mode = "read"
	}
	sess := s.guard(w, r, "system:"+resource+":"+mode)
	if sess == nil {
		return
	}
	id := r.PathValue("id")
	if read {
		if id != "" {
			httpx.WriteError(w, apierr.New(404, "NOT_FOUND", "请使用列表接口。"))
			return
		}
		s.listSystem(w, r, sess, resource)
		return
	}
	switch {
	case r.Method == http.MethodPost && id == "",
		(r.Method == http.MethodPut || r.Method == http.MethodDelete) && id != "":
	default:
		httpx.WriteError(w, apierr.InvalidMethod)
		return
	}
	var body []byte
	if r.Method != http.MethodDelete {
		body = httpx.ReadJSON(w, r)
		if body == nil {
			body = []byte("null")
		}
	}
	change := authz.Change{
		Resource: resource, ID: id, NewID: httpx.NewID(), Remove: r.Method == http.MethodDelete, Body: body,
		ActorID: sess.User.ID, ActorCredentialVersion: sess.CredentialVersion,
	}
	params := s.cfg.PasswordParams
	record, err := s.store.ApplySystemChange(r.Context(), change, sess.Actor(), func(pw string) (string, error) {
		return auth.HashPassword(pw, params)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	switch r.Method {
	case http.MethodPost:
		httpx.WriteData(w, http.StatusCreated, record)
	case http.MethodDelete:
		httpx.WriteData(w, http.StatusOK, map[string]bool{"success": true})
	default:
		httpx.WriteData(w, http.StatusOK, record)
	}
}

func (s *Server) listSystem(w http.ResponseWriter, r *http.Request, sess *httpx.Session, resource string) {
	q := r.URL.Query()
	page := max(1, lenientInt(q.Get("page"), 1))
	size := min(100, max(1, lenientInt(q.Get("pageSize"), 10)))
	search := strings.ToLower(q.Get("search"))
	snap, user := sess.Snap, sess.User
	var items []any
	add := func(rec any, name, key string) {
		if strings.Contains(strings.ToLower(name+" "+key), search) {
			items = append(items, rec)
		}
	}
	switch resource {
	case authz.ResAccounts:
		for _, a := range snap.Accounts {
			if user.CanAccess(authz.Record{ID: a.ID, DepartmentID: a.DepartmentID}, "system:accounts:read") {
				add(a, a.Name, a.Email)
			}
		}
	case authz.ResRoles:
		for _, x := range snap.Roles {
			add(x, x.Name, x.Code)
		}
	case authz.ResPermissions:
		for _, p := range snap.Permissions {
			add(p, p.Name, p.Code)
		}
	case authz.ResMenus:
		for _, m := range snap.Menus {
			add(m, m.Name, "")
		}
	case authz.ResDepartments:
		for _, d := range snap.Departments {
			if user.CanAccess(authz.Record{DepartmentID: d.ID}, "system:departments:read") {
				add(d, d.Name, d.Code)
			}
		}
	}
	total := len(items)
	start := min(total, (page-1)*size)
	end := min(total, start+size)
	httpx.WriteData(w, http.StatusOK, store.List[any]{
		Items: append([]any{}, items[start:end]...),
		Meta:  store.PageMeta{Page: page, PageSize: size, Total: total, TotalPageCount: max(1, (total+size-1)/size)},
	})
}
