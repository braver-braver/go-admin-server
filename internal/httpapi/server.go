// Package httpapi serves the /api/v1 contract of react-admin-starter.
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/braver-braver/go-admin-server/internal/apierr"
	"github.com/braver-braver/go-admin-server/internal/auth"
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
	UploadDir         string
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
	mux     *http.ServeMux
}

func New(cfg Config, st *store.Store, log *slog.Logger) *Server {
	s := &Server{cfg: cfg, store: st, log: log, limiter: newLimiter(cfg.LoginRate, cfg.LoginBurst), mux: http.NewServeMux()}
	s.routes()
	return s
}

// Handler returns the root handler with logging, recovery and headers.
func (s *Server) Handler() http.Handler {
	return s.recoverer(s.logRequests(s.mux))
}

// route is one API operation; the table mirrors src/contract/operations.ts and
// is checked against api/openapi.yaml in tests.
type route struct {
	method, path, operationID string
	handler                   http.HandlerFunc
}

func (s *Server) routeTable() []route {
	return []route{
		{"POST", "/auth/login", "login", s.login},
		{"GET", "/auth/session", "getSession", s.getSession},
		{"POST", "/auth/logout", "logout", s.logout},
		{"GET", "/auth/permissions", "getPermissions", s.getPermissions},
		{"GET", "/auth/navigation", "currentNavigation", s.navigation},
		{"GET", "/system/options", "systemReferenceOptions", s.systemOptions},
		{"GET", "/users", "listUsers", s.listUsers},
		{"POST", "/users", "createUser", s.createUser},
		{"PUT", "/users/{id}", "updateUser", s.updateUser},
		{"DELETE", "/users/{id}", "deleteUser", s.deleteUser},
		{"POST", "/users/batch-delete", "batchDeleteUsers", s.batchDeleteUsers},
		{"PATCH", "/users/status", "updateUsersStatus", s.updateUsersStatus},
		{"POST", "/users/invite", "inviteUser", s.inviteUser},
		{"POST", "/users/invite-batch", "batchInviteUsers", s.batchInviteUsers},
		{"POST", "/uploads", "uploadFile", s.upload},
		{"GET", "/audit-logs", "listAuditLogs", s.listAudit},
	}
}

func (s *Server) routes() {
	// Dispatch by method per path, so a known path with another method gets
	// the contract's INVALID_METHOD instead of the mux's plain-text 405.
	byPath := map[string]map[string]http.HandlerFunc{}
	for _, r := range s.routeTable() {
		if byPath[r.path] == nil {
			byPath[r.path] = map[string]http.HandlerFunc{}
		}
		byPath[r.path][r.method] = r.handler
	}
	for p, methods := range byPath {
		s.mux.HandleFunc(Prefix+p, func(w http.ResponseWriter, r *http.Request) {
			if h, ok := methods[r.Method]; ok {
				h(w, r)
				return
			}
			writeError(w, apierr.InvalidMethod)
		})
	}
	// System resources dispatch by method themselves, like the reference mock.
	s.mux.HandleFunc(Prefix+"/system/{resource}", s.system)
	s.mux.HandleFunc(Prefix+"/system/{resource}/{id}", s.system)
	// Extension: download an uploaded file (not yet in the contract).
	s.mux.HandleFunc("GET "+Prefix+"/uploads/{id}", s.download)
	s.mux.HandleFunc(Prefix+"/", func(w http.ResponseWriter, r *http.Request) { writeError(w, apierr.NotFound) })

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
				writeError(w, apierr.Internal)
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
	writeError(w, e)
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

// newID returns a random UUID (version 4).
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
