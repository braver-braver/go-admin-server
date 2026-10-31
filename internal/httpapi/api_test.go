package httpapi

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/braver-braver/go-admin-server/internal/httpx"
	"github.com/braver-braver/go-admin-server/internal/modules/tickets"
	"github.com/braver-braver/go-admin-server/internal/modules/users"
)

func TestLoginSessionLogout(t *testing.T) {
	e := newTestEnv(t)
	c := e.client()
	login := map[string]string{"email": "admin@example.com", "password": "Demo1234!"}

	expect(t, c.do("POST", "/auth/login", login, noRequestedWith), 403, "REQUEST_HEADER_REQUIRED")
	expect(t, c.do("POST", "/auth/login", []byte("{not json")), 400, "INVALID_REQUEST")
	expect(t, c.do("POST", "/auth/login", map[string]string{"email": "nope"}), 400, "INVALID_CREDENTIALS_FORMAT")
	expect(t, c.loginWith("admin@example.com", "wrong-password"), 401, "INVALID_CREDENTIALS")
	expect(t, c.loginWith("ghost@example.com", "Demo1234!"), 401, "INVALID_CREDENTIALS")
	expect(t, c.do("GET", "/auth/session", nil), 401, "UNAUTHENTICATED")

	r := c.do("POST", "/auth/login", map[string]string{"email": "ADMIN@example.com", "password": "Demo1234!"})
	expect(t, r, 200, "")
	cookie := r.header.Get("Set-Cookie")
	for _, attr := range []string{"session=", "HttpOnly", "SameSite=Lax", "Path=/"} {
		if !strings.Contains(cookie, attr) {
			t.Errorf("cookie %q lacks %s", cookie, attr)
		}
	}
	c.csrf = r.dataMap()["csrfToken"].(string)
	user := r.dataMap()["user"].(map[string]any)
	if user["email"] != "admin@example.com" || !slices.Contains(user["routes"].([]any), any("/system/accounts")) {
		t.Fatalf("unexpected user %v", user)
	}

	s := c.do("GET", "/auth/session", nil)
	expect(t, s, 200, "")
	if s.dataMap()["csrfToken"] != c.csrf {
		t.Fatal("session must return the same CSRF token")
	}
	expect(t, c.do("POST", "/auth/logout", nil, noCSRF), 403, "INVALID_CSRF_TOKEN")
	expect(t, c.do("POST", "/auth/logout", nil, noRequestedWith), 403, "REQUEST_HEADER_REQUIRED")
	expect(t, c.do("POST", "/auth/logout", nil), 200, "")
	expect(t, c.do("GET", "/auth/session", nil), 401, "UNAUTHENTICATED")
	expect(t, c.do("POST", "/auth/logout", nil), 401, "UNAUTHENTICATED")
}

func TestLoginRotatesTheSession(t *testing.T) {
	e := newTestEnv(t)
	c := e.client().login("admin@example.com")
	stolen := e.client()
	stolen.http.Jar.SetCookies(mustURL(e.srv.URL), c.http.Jar.Cookies(mustURL(e.srv.URL)))
	c.login("viewer@example.com") // logging in again replaces the old session
	expect(t, stolen.do("GET", "/auth/session", nil), 401, "UNAUTHENTICATED")
}

func TestPermissionsAndNavigation(t *testing.T) {
	e := newTestEnv(t)
	viewer := e.client().login("viewer@example.com")
	r := viewer.do("GET", "/auth/permissions", nil)
	expect(t, r, 200, "")
	if perms := r.dataMap()["permissions"].([]any); len(perms) != 2 || !slices.Contains(perms, any("users:read")) || !slices.Contains(perms, any("permissions:read")) {
		t.Fatalf("viewer permissions %v", r.dataMap())
	}
	guest := e.client().login("guest@example.com")
	expect(t, guest.do("GET", "/auth/permissions", nil), 403, "FORBIDDEN")
	nav := guest.do("GET", "/auth/navigation", nil)
	expect(t, nav, 200, "")
	if items := nav.data().([]any); len(items) != 1 || items[0].(map[string]any)["id"] != "dashboard" {
		t.Fatalf("guest navigation %s", nav.raw)
	}
	expect(t, guest.do("GET", "/users", nil), 403, "FORBIDDEN")
	expect(t, guest.do("GET", "/system/options", nil), 403, "FORBIDDEN")
	expect(t, viewer.do("GET", "/audit-logs", nil), 403, "FORBIDDEN")
}

func TestUsersListServerSide(t *testing.T) {
	e := newTestEnv(t)
	c := e.client().login("admin@example.com")
	r := c.do("GET", "/users?page=2&pageSize=15", nil)
	expect(t, r, 200, "")
	meta := r.dataMap()["meta"].(map[string]any)
	if meta["total"] != 120.0 || meta["page"] != 2.0 || meta["pageSize"] != 15.0 || meta["totalPageCount"] != 8.0 {
		t.Fatalf("meta %v", meta)
	}
	if n := len(r.dataMap()["items"].([]any)); n != 15 {
		t.Fatalf("items %d", n)
	}
	if m := c.do("GET", "/users?pageSize=500&page=99", nil).dataMap()["meta"].(map[string]any); m["pageSize"] != 100.0 || m["page"] != 2.0 {
		t.Fatalf("clamping %v", m)
	}
	if m := c.do("GET", "/users?page=abc&pageSize=-3", nil).dataMap()["meta"].(map[string]any); m["page"] != 1.0 || m["pageSize"] != 10.0 {
		t.Fatalf("fallbacks %v", m)
	}
	filtered := c.do("GET", "/users?status=active&status=invited&role=cashier&pageSize=100", nil)
	for _, it := range filtered.dataMap()["items"].([]any) {
		u := it.(map[string]any)
		if (u["status"] != "active" && u["status"] != "invited") || u["role"] != "cashier" {
			t.Fatalf("filter leaked %v", u)
		}
	}
	search := c.do("GET", "/users?username=CHEN.FANG39", nil).dataMap()["items"].([]any)
	if len(search) != 1 {
		t.Fatalf("search found %d", len(search))
	}
	asc := c.do("GET", "/users?sortBy=email&pageSize=100", nil).dataMap()["items"].([]any)
	desc := c.do("GET", "/users?sortBy=email&sortOrder=desc&pageSize=100", nil).dataMap()["items"].([]any)
	if asc[0].(map[string]any)["email"] == desc[0].(map[string]any)["email"] {
		t.Fatal("sort order ignored")
	}
	expect(t, c.do("GET", "/users?sortBy=password;drop", nil), 200, "") // falls back to username
}

func userBody(name string) map[string]any {
	return map[string]any{"firstName": "测", "lastName": "试", "username": name, "email": name + "@example.com",
		"phoneNumber": "13800000000", "role": "manager"}
}

func TestUserWrites(t *testing.T) {
	e := newTestEnv(t)
	admin := e.client().login("admin@example.com")
	viewer := e.client().login("viewer@example.com")
	expect(t, viewer.do("POST", "/users", userBody("x1")), 403, "FORBIDDEN")
	expect(t, admin.do("POST", "/users", userBody("x1"), noCSRF), 403, "INVALID_CSRF_TOKEN")

	bad := userBody("x2")
	bad["email"] = "not-an-email"
	delete(bad, "phoneNumber")
	r := admin.do("POST", "/users", bad)
	expect(t, r, 422, "INVALID_USER_FIELDS")
	if !strings.Contains(string(r.raw), "请完整填写必填字段") {
		t.Fatalf("required fields must be reported first: %s", r.raw)
	}
	bad = userBody("x2")
	bad["role"] = "root"
	expect(t, admin.do("POST", "/users", bad), 422, "INVALID_USER_FIELDS")

	created := admin.do("POST", "/users", userBody("newbie"))
	expect(t, created, 201, "")
	u := created.dataMap()
	if u["status"] != "active" || u["departmentId"] != "root" || u["createdBy"] != "admin" {
		t.Fatalf("created %v", u)
	}
	expect(t, admin.do("POST", "/users", userBody("NEWBIE")), 422, "DUPLICATE_USER")

	upd := userBody("newbie")
	upd["firstName"] = "改"
	upd["departmentId"] = "sales"
	r = admin.do("PUT", "/users/"+u["id"].(string), upd)
	expect(t, r, 200, "")
	if r.dataMap()["firstName"] != "改" || r.dataMap()["departmentName"] != "销售部" {
		t.Fatalf("updated %s", r.raw)
	}
	expect(t, admin.do("PUT", "/users/missing", upd), 404, "USER_NOT_FOUND")
	expect(t, admin.do("DELETE", "/users/"+u["id"].(string), nil), 200, "")
	expect(t, admin.do("DELETE", "/users/"+u["id"].(string), nil), 404, "USER_NOT_FOUND")

	expect(t, admin.do("PATCH", "/users/status", map[string]any{"ids": []string{"usr-0001"}, "status": "invited"}), 422, "INVALID_STATUS")
	r = admin.do("PATCH", "/users/status", map[string]any{"ids": []any{"usr-0001", "usr-0002", 7, "missing"}, "status": "inactive"})
	expect(t, r, 200, "")
	if r.dataMap()["updatedCount"] != 2.0 {
		t.Fatalf("status %s", r.raw)
	}
	expect(t, admin.do("POST", "/users/invite", map[string]any{"email": "bad", "role": "nope"}), 422, "INVALID_EMAIL")
	expect(t, admin.do("POST", "/users/invite", map[string]any{"email": "a@b.co", "role": "nope"}), 422, "INVALID_ROLE")
	inv := admin.do("POST", "/users/invite", map[string]any{"email": "Invitee@Example.com", "role": "cashier"})
	expect(t, inv, 201, "")
	if inv.dataMap()["status"] != "invited" || inv.dataMap()["username"] != "invitee" {
		t.Fatalf("invite %s", inv.raw)
	}
	r = admin.do("POST", "/users/invite-batch", map[string]any{"ids": []string{"usr-0003", inv.dataMap()["id"].(string)}})
	if r.dataMap()["invitedCount"].(float64) > 1 {
		t.Fatalf("already invited users must be skipped: %s", r.raw)
	}
	r = admin.do("POST", "/users/batch-delete", map[string]any{"ids": []string{"usr-0004", "usr-0005"}})
	if r.dataMap()["deletedCount"] != 2.0 {
		t.Fatalf("batch delete %s", r.raw)
	}
	expect(t, admin.do("POST", "/users/batch-delete", map[string]any{}), 200, "")
}

// departmentOperator creates, through the API, a role scoped to the account's
// own department with users:read/write and an account in operations.
func departmentOperator(t *testing.T, e *tenv, admin *client, scope string) *client {
	t.Helper()
	role := admin.do("POST", "/system/roles", map[string]any{"name": "部门经办人", "code": "operator_" + scope, "enabled": true,
		"permissionIds": []string{"users:read", "users:write"}, "menuIds": []string{"users"}, "scope": scope, "departmentIds": []string{}})
	expect(t, role, 201, "")
	email := "op-" + scope + "@example.com"
	acct := admin.do("POST", "/system/accounts", map[string]any{"name": "运营经办", "email": email, "password": "Operator123!",
		"enabled": true, "departmentId": "operations", "roleIds": []string{role.dataMap()["id"].(string)}})
	expect(t, acct, 201, "")
	c := e.client()
	expect(t, c.loginWith(email, "Operator123!"), 200, "")
	return c
}

func TestDataScopeFiltersBeforePaging(t *testing.T) {
	e := newTestEnv(t)
	admin := e.client().login("admin@example.com")
	op := departmentOperator(t, e, admin, "department")
	r := op.do("GET", "/users?pageSize=100", nil)
	expect(t, r, 200, "")
	items := r.dataMap()["items"].([]any)
	for _, it := range items {
		if it.(map[string]any)["departmentId"] != "operations" {
			t.Fatalf("out-of-scope user listed: %v", it)
		}
	}
	if total := r.dataMap()["meta"].(map[string]any)["total"]; total != float64(len(items)) || len(items) != 30 {
		t.Fatalf("total %v items %d: counts must be computed after scope filtering", total, len(items))
	}
	// usr-0001 is in root, usr-0002 in operations (seeded round-robin).
	expect(t, op.do("DELETE", "/users/usr-0001", nil), 403, "DATA_SCOPE_DENIED")
	expect(t, op.do("POST", "/users/batch-delete", map[string]any{"ids": []string{"usr-0002", "usr-0001"}}), 403, "DATA_SCOPE_DENIED")
	if admin.do("GET", "/users", nil).dataMap()["meta"].(map[string]any)["total"] != 120.0 {
		t.Fatal("a rejected batch must change nothing")
	}
	moved := userBody("mover")
	moved["departmentId"] = "sales"
	expect(t, op.do("POST", "/users", moved), 403, "DATA_SCOPE_DENIED")
	created := op.do("POST", "/users", userBody("inside"))
	expect(t, created, 201, "")
	if created.dataMap()["departmentId"] != "operations" {
		t.Fatalf("default department %s", created.raw)
	}
	expect(t, op.do("PUT", "/users/"+created.dataMap()["id"].(string), moved), 403, "DATA_SCOPE_DENIED")
}

func TestSystemManagementAndRevocation(t *testing.T) {
	e := newTestEnv(t)
	admin := e.client().login("admin@example.com")
	viewer := e.client().login("viewer@example.com")

	expect(t, admin.do("GET", "/system/widgets", nil), 404, "NOT_FOUND")
	expect(t, admin.do("GET", "/system/roles/admin", nil), 404, "NOT_FOUND")
	expect(t, admin.do("PUT", "/system/roles", map[string]any{}), 400, "INVALID_METHOD")
	expect(t, viewer.do("GET", "/system/roles", nil), 403, "FORBIDDEN")

	list := admin.do("GET", "/system/permissions?search=SYSTEM:ROLES&pageSize=1", nil)
	expect(t, list, 200, "")
	if m := list.dataMap()["meta"].(map[string]any); m["total"] != 2.0 || m["totalPageCount"] != 2.0 {
		t.Fatalf("system list meta %v", m)
	}
	opts := admin.do("GET", "/system/options", nil)
	expect(t, opts, 200, "")
	for _, it := range opts.dataMap()["items"].([]any) {
		if it.(map[string]any)["resource"] == "accounts" {
			t.Fatal("options must not include accounts")
		}
	}

	expect(t, admin.do("POST", "/system/roles", map[string]any{"name": "x", "code": "x1", "enabled": true, "extra": 1,
		"permissionIds": []string{}, "menuIds": []string{}, "scope": "all", "departmentIds": []string{}}), 422, "INVALID_FIELDS")
	expect(t, admin.do("DELETE", "/system/roles/admin", nil), 409, "SYSTEM_RULE")
	expect(t, admin.do("DELETE", "/system/departments/operations", nil), 409, "SYSTEM_RULE")

	op := departmentOperator(t, e, admin, "department")
	expect(t, op.do("GET", "/auth/session", nil), 200, "")
	accounts := admin.do("GET", "/system/accounts?search=op-department", nil).dataMap()["items"].([]any)
	acct := accounts[0].(map[string]any)
	body := map[string]any{"name": acct["name"], "email": acct["email"], "enabled": true,
		"departmentId": acct["departmentId"], "roleIds": acct["roleIds"], "password": "Changed1234!"}
	expect(t, admin.do("PUT", "/system/accounts/"+acct["id"].(string), body), 200, "")
	expect(t, op.do("GET", "/auth/session", nil), 401, "UNAUTHENTICATED")
	expect(t, op.loginWith(acct["email"].(string), "Changed1234!"), 200, "")

	delete(body, "password")
	body["enabled"] = false
	expect(t, admin.do("PUT", "/system/accounts/"+acct["id"].(string), body), 200, "")
	expect(t, op.do("GET", "/auth/session", nil), 401, "UNAUTHENTICATED")
	body["enabled"] = true
	expect(t, admin.do("PUT", "/system/accounts/"+acct["id"].(string), body), 200, "")
	expect(t, op.do("GET", "/auth/session", nil), 401, "UNAUTHENTICATED") // re-enabling never revives sessions

	audit := admin.do("GET", "/audit-logs?action=system.changed&pageSize=100", nil)
	expect(t, audit, 200, "")
	for _, it := range audit.dataMap()["items"].([]any) {
		if it.(map[string]any)["action"] != "system.changed" {
			t.Fatal("audit action filter")
		}
	}
	if n := len(audit.dataMap()["items"].([]any)); n < 5 {
		t.Fatalf("expected system changes in the audit log, got %d", n)
	}
}

func TestRoleChangeTakesEffectImmediately(t *testing.T) {
	e := newTestEnv(t)
	admin := e.client().login("admin@example.com")
	viewer := e.client().login("viewer@example.com")
	expect(t, viewer.do("GET", "/users", nil), 200, "")
	role := admin.do("GET", "/system/roles?search=viewer", nil).dataMap()["items"].([]any)[0].(map[string]any)
	role["permissionIds"] = []string{"permissions:read"}
	for _, k := range []string{"id", "protected", "resource"} {
		delete(role, k)
	}
	expect(t, admin.do("PUT", "/system/roles/viewer", role), 200, "")
	expect(t, viewer.do("GET", "/users", nil), 403, "FORBIDDEN")
	if routes := viewer.do("GET", "/auth/session", nil).dataMap()["user"].(map[string]any)["routes"].([]any); slices.Contains(routes, any("/users")) {
		t.Fatal("revoked page still routed")
	}
}

func TestConcurrentSystemWritesAreSerialized(t *testing.T) {
	e := newTestEnv(t)
	admin := e.client().login("admin@example.com")
	var wg sync.WaitGroup
	statuses := make([]int, 8)
	for i := range statuses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses[i] = admin.do("POST", "/system/roles", map[string]any{"name": "并发", "code": "race", "enabled": true,
				"permissionIds": []string{}, "menuIds": []string{}, "scope": "all", "departmentIds": []string{}}).status
		}()
	}
	wg.Wait()
	created := 0
	for _, s := range statuses {
		if s == 201 {
			created++
		} else if s != 409 {
			t.Fatalf("unexpected status %d", s)
		}
	}
	if created != 1 {
		t.Fatalf("%d roles created with the same code", created)
	}
}

func pngBytes(t *testing.T) []byte {
	var buf bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{255, 0, 0, 255})
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func form(t *testing.T, field, name, contentType string, data []byte) multipartBody {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if field != "" {
		h := make(map[string][]string)
		h["Content-Disposition"] = []string{fmt.Sprintf(`form-data; name=%q; filename=%q`, field, name)}
		h["Content-Type"] = []string{contentType}
		part, _ := w.CreatePart(h)
		_, _ = part.Write(data)
	} else {
		_ = w.WriteField("other", "x")
	}
	_ = w.Close()
	return multipartBody{data: buf.Bytes(), contentType: w.FormDataContentType()}
}

func TestUploads(t *testing.T) {
	e := newTestEnv(t)
	admin := e.client().login("admin@example.com")
	viewer := e.client().login("viewer@example.com")
	img := pngBytes(t)
	expect(t, viewer.do("POST", "/uploads", form(t, "file", "a.png", "image/png", img)), 403, "FORBIDDEN")
	expect(t, admin.do("POST", "/uploads", form(t, "", "", "", nil)), 422, "FILE_REQUIRED")
	expect(t, admin.do("POST", "/uploads", form(t, "file", "x.svg", "image/svg+xml", []byte(`<svg onload="alert(1)"/>`))), 422, "UNSUPPORTED_FILE_TYPE")
	expect(t, admin.do("POST", "/uploads", form(t, "file", "fake.png", "image/png", []byte("plain text"))), 422, "UNSUPPORTED_FILE_TYPE")
	big := append(append([]byte{}, img...), make([]byte, 2<<20)...)
	expect(t, admin.do("POST", "/uploads", form(t, "file", "big.png", "image/png", big)), 422, "FILE_TOO_LARGE")
	r := admin.do("POST", "/uploads", form(t, "file", "avatar.png", "image/png", img))
	expect(t, r, 200, "")
	url := r.dataMap()["url"].(string)
	got := viewer.do("GET", strings.TrimPrefix(url, Prefix), nil)
	if got.status != 200 || !bytes.Equal(got.raw, img) || got.header.Get("Content-Type") != "image/png" {
		t.Fatalf("download %d %s", got.status, got.header)
	}
}

func TestCrossSiteWritesAreRejected(t *testing.T) {
	e := newTestEnv(t)
	c := e.client()
	r := c.do("POST", "/auth/login", map[string]string{"email": "admin@example.com", "password": "Demo1234!"},
		header("Origin", "https://evil.example"))
	expect(t, r, 403, "FORBIDDEN")
	r = c.do("POST", "/auth/login", map[string]string{"email": "admin@example.com", "password": "Demo1234!"},
		header("Sec-Fetch-Site", "cross-site"))
	expect(t, r, 403, "FORBIDDEN")
	expect(t, c.loginWith("admin@example.com", "Demo1234!"), 200, "")
}

func TestLoginRateLimit(t *testing.T) {
	e := newTestEnv(t, func(c *Config) { c.LoginRate, c.LoginBurst = time.Hour, 3 })
	c := e.client()
	for i := 0; i < 3; i++ {
		expect(t, c.loginWith("admin@example.com", "wrong"), 401, "INVALID_CREDENTIALS")
	}
	expect(t, c.loginWith("admin@example.com", "Demo1234!"), 429, "RATE_LIMITED")
}

func TestUnknownRoutes(t *testing.T) {
	e := newTestEnv(t)
	c := e.client()
	expect(t, c.do("GET", "/nope", nil), 404, "NOT_FOUND")
	expect(t, c.do("GET", "/auth/login", nil), 400, "INVALID_METHOD")
	expect(t, c.do("DELETE", "/users", nil), 400, "INVALID_METHOD")
}

// Every operation of the contract is routed, and every routed operation is in
// the contract (system resources are one generic path in the spec).
func TestRoutesMatchTheContract(t *testing.T) {
	if spec == nil {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := &Server{modules: []httpx.Module{users.New(nil, ""), tickets.New(nil)}}
	routed := map[string]bool{}
	for _, op := range s.operations() {
		if op.ID != "downloadFile" { // extension, not in the contract yet
			routed[op.Method+" "+op.Path] = true
		}
	}
	routed["GET /system/{resource}"] = true
	routed["POST /system/{resource}"] = true
	routed["PUT /system/{resource}/{id}"] = true
	routed["DELETE /system/{resource}/{id}"] = true
	inSpec := map[string]bool{}
	for path, item := range spec.Paths.Map() {
		for method := range item.Operations() {
			inSpec[method+" "+path] = true
		}
	}
	for op := range inSpec {
		if !routed[op] {
			t.Errorf("contract operation %s is not routed", op)
		}
	}
	for op := range routed {
		if !inSpec[op] {
			t.Errorf("routed operation %s is not in the contract", op)
		}
	}
}

func mustURL(raw string) *url.URL { u, _ := url.Parse(raw); return u }

// Guards the guard: a response that breaks the contract must be caught.
func TestSpecValidationCatchesDrift(t *testing.T) {
	if spec == nil {
		t.Skip("TEST_DATABASE_URL not set")
	}
	h := http.Header{"Content-Type": {"application/json"}}
	bad := []string{
		`{"data":{"user":{"id":"a","email":"a@b.co","name":"A","roles":[],"permissions":[]}}}`, // no csrfToken
		`{"data":{"items":[],"meta":{"page":1,"pageSize":10,"total":0}}}`,                      // no totalPageCount
		`{"data":{"items":[{"id":"1","createdAt":12,"actorName":"a","actorEmail":"a","action":"x","target":"t","detail":"d","ip":""}],"meta":{"page":1,"pageSize":10,"total":1,"totalPageCount":1}}}`,
	}
	paths := []string{"/auth/session", "/users", "/audit-logs"}
	for i, body := range bad {
		if err := specError("GET", paths[i], &resp{status: 200, header: h, raw: []byte(body)}); err == nil {
			t.Errorf("drift in %s not detected", paths[i])
		}
	}
}
