// Package httpapi serves the /api/v1 contract of react-admin-starter: the
// platform's own operations (sessions, navigation, system management, audit)
// plus every module's operations behind the same guards.
package httpapi

import (
	"context"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/braver-braver/go-admin-server/internal/apierr"
	"github.com/braver-braver/go-admin-server/internal/auth"
	"github.com/braver-braver/go-admin-server/internal/authz"
	"github.com/braver-braver/go-admin-server/internal/httpx"
	"github.com/braver-braver/go-admin-server/internal/store"
)

// Prefix is the API major version path (decision D5 of the frontend).
const Prefix = "/api/v1"

type Config struct {
	CookieName   string
	CookieSecure bool
	SessionTTL   time.Duration
	// AllowedOrigins lists origins allowed to send writes, e.g.
	// "https://admin.example.com". Empty: the request's own host only.
	AllowedOrigins []string
	// TrustProxyHeaders takes the client IP from X-Forwarded-For.
	TrustProxyHeaders bool
	PasswordParams    auth.Params
	// LoginRate limits login attempts per client IP and per email.
	LoginRate  time.Duration
	LoginBurst int
}

type Server struct {
	cfg     Config
	store   *store.Store
	log     *slog.Logger
	limiter *limiter
	modules []httpx.Module
	mux     *http.ServeMux
}

// Catalog merges every module's catalog with the platform's. Module pages
// come before the platform's example pages in menus.
func Catalog(modules []httpx.Module) authz.Catalog {
	var cats []authz.Catalog
	for _, m := range modules {
		cats = append(cats, m.Catalog())
	}
	return authz.Merge(append(cats, authz.CoreCatalog())...)
}

// New wires the server. It registers each module's department references with
// the store; Install must have run before serving.
func New(cfg Config, st *store.Store, log *slog.Logger, modules ...httpx.Module) *Server {
	s := &Server{cfg: cfg, store: st, log: log, limiter: newLimiter(cfg.LoginRate, cfg.LoginBurst),
		modules: modules, mux: http.NewServeMux()}
	for _, m := range modules {
		if ref, ok := m.(httpx.DepartmentReferencer); ok {
			st.AddDepartmentReference(ref.DepartmentInUse)
		}
	}
	s.routes()
	return s
}

// Install applies the platform's and every module's migrations, then adds
// newly provided capabilities and pages to the configuration.
func Install(ctx context.Context, st *store.Store, log *slog.Logger, modules []httpx.Module) error {
	var dirs []fs.FS
	for _, m := range modules {
		dirs = append(dirs, m.Migrations())
	}
	if err := st.Migrate(ctx, dirs...); err != nil {
		return err
	}
	changed, err := st.InstallCatalog(ctx, Catalog(modules))
	if changed {
		log.Info("installed new capabilities and pages for the super administrator")
	}
	return err
}

// Handler returns the root handler with logging, recovery and headers.
func (s *Server) Handler() http.Handler {
	return s.recoverer(s.logRequests(s.mux))
}

// coreOperations are the platform's own operations. System resources are
// served by s.system, which checks in the reference mock's own order.
func (s *Server) coreOperations() []httpx.Op {
	return []httpx.Op{
		{Method: "POST", Path: "/auth/login", ID: "login", Public: true, Handle: s.login},
		{Method: "GET", Path: "/auth/session", ID: "getSession", Handle: s.getSession},
		{Method: "POST", Path: "/auth/logout", ID: "logout", Handle: s.logout},
		{Method: "GET", Path: "/auth/permissions", ID: "getPermissions", Permission: "permissions:read", Handle: s.getPermissions},
		{Method: "GET", Path: "/auth/navigation", ID: "currentNavigation", Handle: s.navigation},
		{Method: "GET", Path: "/system/options", ID: "systemReferenceOptions", Handle: s.systemOptions},
		{Method: "GET", Path: "/audit-logs", ID: "listAuditLogs", Permission: "audit:read", Handle: s.listAudit},
	}
}

// operations is every operation the server serves.
func (s *Server) operations() []httpx.Op {
	ops := s.coreOperations()
	for _, m := range s.modules {
		ops = append(ops, m.Operations()...)
	}
	return ops
}

func (s *Server) routes() {
	// Dispatch by method per path, so a known path with another method gets
	// the contract's INVALID_METHOD instead of the mux's plain-text 405.
	byPath := map[string]map[string]http.HandlerFunc{}
	var order []string
	for _, op := range s.operations() {
		if byPath[op.Path] == nil {
			byPath[op.Path] = map[string]http.HandlerFunc{}
			order = append(order, op.Path)
		}
		if _, dup := byPath[op.Path][op.Method]; dup {
			panic("httpapi: duplicate operation " + op.Method + " " + op.Path)
		}
		byPath[op.Path][op.Method] = s.serve(op)
	}
	for _, p := range order {
		methods := byPath[p]
		s.mux.HandleFunc(Prefix+p, func(w http.ResponseWriter, r *http.Request) {
			if h, ok := methods[r.Method]; ok {
				h(w, r)
				return
			}
			httpx.WriteError(w, apierr.InvalidMethod)
		})
	}
	s.mux.HandleFunc(Prefix+"/system/{resource}", s.system)
	s.mux.HandleFunc(Prefix+"/system/{resource}/{id}", s.system)
	s.mux.HandleFunc(Prefix+"/", func(w http.ResponseWriter, r *http.Request) { httpx.WriteError(w, apierr.NotFound) })

	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	s.mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.store.Ping(ctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// serve wraps an operation with the contract's guards, in order: request
// header and origin for writes, then session, capability and CSRF token.
func (s *Server) serve(op httpx.Op) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var sess *httpx.Session
		if op.Public {
			if isWrite(r) && !s.checkWriteHeaders(w, r) {
				return
			}
		} else if sess = s.guard(w, r, op.Permission); sess == nil {
			return
		}
		op.Handle(httpx.NewCtx(w, r, sess, s.clientIP(r), s.fail))
	}
}

func isWrite(r *http.Request) bool { return r.Method != http.MethodGet && r.Method != http.MethodHead }

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		if strings.HasPrefix(r.URL.Path, Prefix+"/") {
			sw.Header().Set("Cache-Control", "no-store")
			sw.Header().Set("X-Content-Type-Options", "nosniff")
		}
		next.ServeHTTP(sw, r)
		s.log.Info("request", "method", r.Method, "path", r.URL.Path, "status", sw.status,
			"duration_ms", time.Since(start).Milliseconds(), "ip", s.clientIP(r))
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.Error("panic", "error", v, "stack", string(debug.Stack()))
				httpx.WriteError(w, apierr.Internal)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// fail writes an error response, logging unexpected ones.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	e := apierr.From(err)
	if e == apierr.Internal {
		s.log.Error("request failed", "method", r.Method, "path", r.URL.Path, "error", err)
	}
	httpx.WriteError(w, e)
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxyHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// originAllowed rejects cross-site browser writes. Non-browser clients send
// neither Origin nor Sec-Fetch-Site and are still subject to CSRF tokens.
func (s *Server) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return r.Header.Get("Sec-Fetch-Site") != "cross-site"
	}
	if len(s.cfg.AllowedOrigins) > 0 {
		return slices.Contains(s.cfg.AllowedOrigins, origin)
	}
	host := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
	return host == r.Host
}
