// Package httpx is the toolkit API modules are written with: declarative
// operations whose guards the server runs, the request context handlers get,
// and helpers for the `{data}` / `{error}` envelope and lenient query parsing.
package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"math"
	"net/http"
	"strconv"

	"github.com/braver-braver/go-admin-server/internal/apierr"
	"github.com/braver-braver/go-admin-server/internal/authz"
	"github.com/braver-braver/go-admin-server/internal/store"
)

// Module is a pluggable business module. The server merges every module's
// catalog into the configuration on start (new capabilities and pages are
// granted to the super administrator only), runs its migrations and serves
// its operations behind the standard guards.
type Module interface {
	// Name identifies the module in logs.
	Name() string
	// Catalog lists the capabilities its operations check and the frontend
	// pages it adds.
	Catalog() authz.Catalog
	// Operations are served under /api/v1.
	Operations() []Op
	// Migrations holds goose SQL files with globally unique versions (use a
	// timestamp, e.g. 20261031120000_orders.sql), or nil.
	Migrations() fs.FS
}

// DepartmentReferencer is implemented by modules whose records belong to a
// department; a department they still reference cannot be deleted.
type DepartmentReferencer interface {
	DepartmentInUse(ctx context.Context, q store.Querier, departmentID string) (bool, error)
}

// DemoSeeder is implemented by modules that add demo data for `seed-demo`.
type DemoSeeder interface {
	SeedDemo(ctx context.Context) error
}

// Op is one API operation. The server enforces, in this order: for writes
// `X-Requested-With: ReactAdminStarter` and the origin policy; unless Public,
// a valid session, then Permission (if set), then for writes the CSRF token.
// Handle runs only when every check passed.
type Op struct {
	Method string
	// Path is relative to /api/v1 and may use {param} segments.
	Path string
	// ID is the operationId in the OpenAPI contract.
	ID string
	// Permission is the capability required; empty means any signed-in account.
	Permission string
	// Public operations run without a session (only login is public).
	Public bool
	Handle func(*Ctx)
}

// Session is the authenticated caller, recomputed from the live configuration
// on every request.
type Session struct {
	User              *authz.Principal
	Snap              *authz.Snapshot
	CSRFToken         string
	CredentialVersion int
	TokenHash         []byte
	IP                string
}

// Actor identifies the caller in audit records.
func (s *Session) Actor() store.Actor {
	return store.Actor{ID: s.User.ID, Name: s.User.Name, Email: s.User.Email, DepartmentID: s.User.DepartmentID, IP: s.IP}
}

// Ctx is what a handler gets.
type Ctx struct {
	W       http.ResponseWriter
	R       *http.Request
	Session *Session // nil for public operations
	// IP is the client address (proxy headers honoured when configured).
	IP   string
	fail func(http.ResponseWriter, *http.Request, error)
}

// NewCtx is used by the server.
func NewCtx(w http.ResponseWriter, r *http.Request, s *Session, ip string, fail func(http.ResponseWriter, *http.Request, error)) *Ctx {
	return &Ctx{W: w, R: r, Session: s, IP: ip, fail: fail}
}

func (c *Ctx) Context() context.Context { return c.R.Context() }

// User is the signed-in principal.
func (c *Ctx) User() *authz.Principal { return c.Session.User }

// Data sends `{ "data": v }`.
func (c *Ctx) Data(status int, v any) { WriteData(c.W, status, v) }

// OK sends 200 `{ "data": v }`.
func (c *Ctx) OK(v any) { WriteData(c.W, http.StatusOK, v) }

// Fail sends an error; *apierr.Error and *authz.RuleError keep their status
// and code, anything else is logged and becomes 500 INTERNAL.
func (c *Ctx) Fail(err error) { c.fail(c.W, c.R, err) }

// Body returns the JSON body, or nil when it is empty or not valid JSON.
func (c *Ctx) Body() []byte { return ReadJSON(c.W, c.R) }

// Object returns the JSON body as an object, or nil.
func (c *Ctx) Object() map[string]any {
	var raw map[string]any
	_ = json.Unmarshal(c.Body(), &raw)
	return raw
}

// Page reads `page` and `pageSize` like the users and audit lists: positive
// integers or the defaults (1 and 10), with pageSize clamped to 100.
func (c *Ctx) Page() store.Page {
	q := c.R.URL.Query()
	return store.Page{Page: PositiveInt(q.Get("page"), 1), PageSize: min(100, PositiveInt(q.Get("pageSize"), 10))}
}

// Multi returns the non-empty values of a repeated query key.
func (c *Ctx) Multi(key string) []string {
	var out []string
	for _, v := range c.R.URL.Query()[key] {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// WriteData sends `{ "data": v }`.
func WriteData(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": v})
}

// WriteError sends `{ "error": { "code", "message" } }`.
func WriteError(w http.ResponseWriter, e *apierr.Error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": e.Code, "message": e.Message}})
}

const maxJSONBody = 1 << 20

// ReadJSON reads a JSON body of at most 1 MiB. It returns nil for an empty or
// invalid body; callers decide whether that is an error.
func ReadJSON(w http.ResponseWriter, r *http.Request) []byte {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxJSONBody))
	if err != nil || !json.Valid(body) {
		return nil
	}
	return body
}

// IDs reads a bulk request's `ids`: a body without an array selects nothing,
// and non-string entries are skipped (the contract's rule).
func IDs(raw map[string]any) []string {
	list, _ := raw["ids"].([]any)
	ids := []string{}
	for _, v := range list {
		if s, ok := v.(string); ok {
			ids = append(ids, s)
		}
	}
	return ids
}

// PositiveInt parses a positive integer query value, else returns fallback.
func PositiveInt(v string, fallback int) int {
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 {
		return fallback
	}
	if f >= math.MaxInt32 {
		return math.MaxInt32
	}
	return int(math.Floor(f))
}

// NewID returns a random UUID (version 4).
func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
