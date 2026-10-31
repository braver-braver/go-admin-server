package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/jackc/pgx/v5"

	"github.com/braver-braver/go-admin-server/internal/auth"
	"github.com/braver-braver/go-admin-server/internal/authz"
	"github.com/braver-braver/go-admin-server/internal/httpx"
	"github.com/braver-braver/go-admin-server/internal/modules/users"
	"github.com/braver-braver/go-admin-server/internal/store"
)

// Integration tests run against PostgreSQL. Set TEST_DATABASE_URL to a
// superuser connection (it creates and drops databases), e.g.
// postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable.

var (
	adminURL   string
	templateDB string
	dbCounter  atomic.Int64
	spec       *openapi3.T
	specRouter routers.Router
	fastParams = auth.Params{Memory: 64, Time: 1, Threads: 1}
)

func TestMain(m *testing.M) {
	adminURL = os.Getenv("TEST_DATABASE_URL")
	if adminURL == "" {
		fmt.Println("TEST_DATABASE_URL not set: skipping integration tests")
		os.Exit(m.Run())
	}
	if err := setup(); err != nil {
		fmt.Println("setup:", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = execAdmin(fmt.Sprintf(`DROP DATABASE IF EXISTS %s`, templateDB))
	os.Exit(code)
}

func execAdmin(sql string) error {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, sql)
	return err
}

func dbURL(name string) string {
	i := strings.LastIndex(adminURL, "/")
	rest := ""
	if q := strings.Index(adminURL[i:], "?"); q >= 0 {
		rest = adminURL[i+q:]
	}
	return adminURL[:i+1] + name + rest
}

// setup migrates and seeds a template database once; each test clones it.
func setup() error {
	templateDB = fmt.Sprintf("goadmin_tmpl_%d", time.Now().UnixNano())
	if err := execAdmin(`CREATE DATABASE ` + templateDB); err != nil {
		return err
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dbURL(templateDB))
	if err != nil {
		return err
	}
	defer st.Close()
	mods := []httpx.Module{users.New(st, os.TempDir())}
	if err := Install(ctx, st, slog.New(slog.NewTextHandler(io.Discard, nil)), mods); err != nil {
		return err
	}
	hash, err := auth.HashPassword("Demo1234!", fastParams)
	if err != nil {
		return err
	}
	snap := authz.Demo(Catalog(mods))
	passwords := map[string]string{}
	for _, a := range snap.Accounts {
		passwords[a.ID] = hash
	}
	if _, err := st.Bootstrap(ctx, snap, passwords); err != nil {
		return err
	}
	if err := mods[0].(httpx.DemoSeeder).SeedDemo(ctx); err != nil {
		return err
	}
	st.Close()

	loader := openapi3.NewLoader()
	if spec, err = loader.LoadFromFile("../../api/openapi.yaml"); err != nil {
		return err
	}
	spec.Servers = openapi3.Servers{{URL: "http://api.test/api/v1"}}
	specRouter, err = gorillamux.NewRouter(spec)
	return err
}

type tenv struct {
	t      *testing.T
	srv    *httptest.Server
	store  *store.Store
	server *Server
}

func newTestEnv(t *testing.T, tweak ...func(*Config)) *tenv {
	t.Helper()
	return newTestEnvWith(t, nil, tweak...)
}

// newTestEnvWith also installs extra modules into the seeded database, the
// way a module added to an existing installation is installed on restart.
func newTestEnvWith(t *testing.T, extra func(*store.Store) []httpx.Module, tweak ...func(*Config)) *tenv {
	t.Helper()
	if adminURL == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	name := fmt.Sprintf("goadmin_t%d_%d", time.Now().UnixNano()%1e9, dbCounter.Add(1))
	if err := execAdmin(fmt.Sprintf(`CREATE DATABASE %s TEMPLATE %s`, name, templateDB)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dbURL(name))
	if err != nil {
		t.Fatal(err)
	}
	mods := []httpx.Module{users.New(st, t.TempDir())}
	if extra != nil {
		mods = append(mods, extra(st)...)
	}
	if err := Install(ctx, st, slog.New(slog.NewTextHandler(io.Discard, nil)), mods); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		CookieName: "session", SessionTTL: time.Hour,
		PasswordParams: fastParams, LoginRate: time.Millisecond, LoginBurst: 1000,
	}
	for _, f := range tweak {
		f(&cfg)
	}
	server := New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)), mods...)
	srv := httptest.NewServer(server.Handler())
	t.Cleanup(func() {
		srv.Close()
		st.Close()
		_ = execAdmin(fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, name))
	})
	return &tenv{t: t, srv: srv, store: st, server: server}
}

// client is one browser: a cookie jar plus the CSRF token of its session.
type client struct {
	e    *tenv
	http *http.Client
	csrf string
}

func (e *tenv) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{e: e, http: &http.Client{Jar: jar}}
}

type resp struct {
	status int
	header http.Header
	raw    []byte
	body   map[string]any
}

func (r *resp) data() any { return r.body["data"] }

func (r *resp) code() string {
	if e, ok := r.body["error"].(map[string]any); ok {
		return e["code"].(string)
	}
	return ""
}

func (r *resp) dataMap() map[string]any { m, _ := r.data().(map[string]any); return m }

type opt func(*http.Request)

func header(k, v string) opt { return func(r *http.Request) { r.Header.Set(k, v) } }

var noRequestedWith opt = func(r *http.Request) { r.Header.Del("X-Requested-With") }
var noCSRF opt = func(r *http.Request) { r.Header.Del("X-CSRF-Token") }

func (c *client) do(method, path string, body any, opts ...opt) *resp {
	c.e.t.Helper()
	var reader io.Reader
	contentType := "application/json"
	switch b := body.(type) {
	case nil:
	case []byte:
		reader = bytes.NewReader(b)
	case multipartBody:
		reader, contentType = bytes.NewReader(b.data), b.contentType
	default:
		raw, _ := json.Marshal(b)
		reader = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, c.e.srv.URL+Prefix+path, reader)
	if reader != nil {
		req.Header.Set("Content-Type", contentType)
	}
	if method != "GET" {
		req.Header.Set("X-Requested-With", "ReactAdminStarter")
		if c.csrf != "" {
			req.Header.Set("X-CSRF-Token", c.csrf)
		}
	}
	for _, o := range opts {
		o(req)
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := &resp{status: res.StatusCode, header: res.Header, raw: raw}
	if strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(raw, &out.body); err != nil {
			c.e.t.Fatalf("%s %s: invalid JSON %q", method, path, raw)
		}
		checkEnvelope(c.e.t, method, path, out)
		validateAgainstSpec(c.e.t, method, path, out)
	}
	return out
}

// checkEnvelope enforces `{data}` on success and `{error:{code,message}}` on
// failure, plus the no-store header.
func checkEnvelope(t *testing.T, method, path string, r *resp) {
	t.Helper()
	if r.header.Get("Cache-Control") != "no-store" {
		t.Errorf("%s %s: Cache-Control %q", method, path, r.header.Get("Cache-Control"))
	}
	if r.status < 300 {
		if _, ok := r.body["data"]; !ok || len(r.body) != 1 {
			t.Errorf("%s %s: success without {data}: %s", method, path, r.raw)
		}
		return
	}
	e, ok := r.body["error"].(map[string]any)
	if !ok || len(r.body) != 1 || e["code"] == nil || e["message"] == "" {
		t.Errorf("%s %s: error without {error:{code,message}}: %s", method, path, r.raw)
	}
}

// errorCatalog mirrors src/contract/errors.ts: each code and the statuses it
// may be sent with. RATE_LIMITED and INTERNAL are not in the frontend table yet.
var errorCatalog = map[string][]int{
	"UNAUTHENTICATED": {401}, "INVALID_CREDENTIALS": {401}, "INVALID_REQUEST": {400},
	"INVALID_CREDENTIALS_FORMAT": {400}, "REQUEST_HEADER_REQUIRED": {403}, "INVALID_CSRF_TOKEN": {403},
	"FORBIDDEN": {403}, "DATA_SCOPE_DENIED": {403}, "USER_NOT_FOUND": {404}, "INVALID_USER_FIELDS": {422},
	"DUPLICATE_USER": {422}, "INVALID_STATUS": {422}, "INVALID_EMAIL": {422}, "INVALID_ROLE": {422},
	"FILE_REQUIRED": {422}, "UNSUPPORTED_FILE_TYPE": {422}, "FILE_TOO_LARGE": {422}, "INVALID_FIELDS": {422},
	"SYSTEM_RULE": {401, 403, 404, 409, 422}, "NOT_FOUND": {404}, "INVALID_METHOD": {400},
	"RATE_LIMITED": {429}, "INTERNAL": {500},
}

// validateAgainstSpec checks success bodies against api/openapi.yaml, and
// error responses against the error table. Error statuses are not checked per
// operation in the spec: the hand-written document still omits several that
// the frontend's operation registry declares.
func validateAgainstSpec(t *testing.T, method, path string, r *resp) {
	t.Helper()
	if r.status >= 400 {
		if !slices.Contains(errorCatalog[r.code()], r.status) {
			t.Errorf("%s %s: error code %q is not allowed with status %d", method, path, r.code(), r.status)
		}
		return
	}
	if err := specError(method, path, r); err != nil {
		t.Errorf("%s %s %d does not match the contract: %v\nbody: %.400s", method, path, r.status, err, r.raw)
	}
}

// specError validates a success response against the OpenAPI document.
func specError(method, path string, r *resp) error {
	req, _ := http.NewRequest(method, "http://api.test/api/v1"+path, nil)
	route, params, err := specRouter.FindRoute(req)
	if err != nil {
		return nil // not in the contract (extension endpoints)
	}
	in := &openapi3filter.RequestValidationInput{Request: req, PathParams: params, Route: route,
		Options: &openapi3filter.Options{ExcludeRequestBody: true, IncludeResponseStatus: true}}
	return openapi3filter.ValidateResponse(context.Background(), &openapi3filter.ResponseValidationInput{
		RequestValidationInput: in, Status: r.status, Header: r.header,
		Body:    io.NopCloser(bytes.NewReader(r.raw)),
		Options: &openapi3filter.Options{IncludeResponseStatus: true, MultiError: true},
	})
}

func (c *client) login(email string) *client {
	c.e.t.Helper()
	r := c.do("POST", "/auth/login", map[string]string{"email": email, "password": "Demo1234!"})
	if r.status != 200 {
		c.e.t.Fatalf("login %s: %d %s", email, r.status, r.raw)
	}
	c.csrf = r.dataMap()["csrfToken"].(string)
	return c
}

func (c *client) loginWith(email, password string) *resp {
	r := c.do("POST", "/auth/login", map[string]string{"email": email, "password": password})
	if r.status == 200 {
		c.csrf = r.dataMap()["csrfToken"].(string)
	}
	return r
}

func expect(t *testing.T, r *resp, status int, code string) {
	t.Helper()
	if r.status != status || (code != "" && r.code() != code) {
		t.Fatalf("want %d %s, got %d %s", status, code, r.status, r.raw)
	}
}

type multipartBody struct {
	data        []byte
	contentType string
}
