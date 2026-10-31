package httpapi

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/braver-braver/go-admin-server/internal/apierr"
	"github.com/braver-braver/go-admin-server/internal/auth"
	"github.com/braver-braver/go-admin-server/internal/authz"
	"github.com/braver-braver/go-admin-server/internal/store"
)

// session is an authenticated request: the stored session plus the live
// principal recomputed from the current configuration on every request.
type session struct {
	tokenHash []byte
	stored    *store.Session
	snap      *authz.Snapshot
	user      *authz.Principal
	ip        string
}

func (s *session) actor() store.Actor {
	return store.Actor{ID: s.user.ID, Name: s.user.Name, Email: s.user.Email, DepartmentID: s.user.DepartmentID, IP: s.ip}
}

// authenticate resolves the session cookie. A session is valid only while the
// account still has a principal and its credential version is unchanged.
func (s *Server) authenticate(r *http.Request) (*session, error) {
	c, err := r.Cookie(s.cfg.CookieName)
	if err != nil || c.Value == "" {
		return nil, apierr.Unauthenticated
	}
	hash := auth.TokenHash(c.Value)
	stored, err := s.store.GetSession(r.Context(), hash)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, apierr.Unauthenticated
	}
	snap, err := s.store.Snapshot(r.Context())
	if err != nil {
		return nil, err
	}
	user, ok := snap.Principal(stored.AccountID)
	version, known := snap.CredentialVersions[stored.AccountID]
	if !ok || !known || version != stored.CredentialVersion {
		return nil, apierr.Unauthenticated
	}
	return &session{tokenHash: hash, stored: stored, snap: snap, user: user, ip: s.clientIP(r)}, nil
}

// guard runs the contract's checks in order: request header and origin for
// writes, then session, capability and CSRF token. It writes the error and
// returns nil when a check fails.
func (s *Server) guard(w http.ResponseWriter, r *http.Request, permission string) *session {
	write := r.Method != http.MethodGet && r.Method != http.MethodHead
	if write && !s.checkWriteHeaders(w, r) {
		return nil
	}
	sess, err := s.authenticate(r)
	if err != nil {
		s.fail(w, r, err)
		return nil
	}
	if permission != "" && !sess.user.Has(permission) {
		writeError(w, apierr.Forbidden)
		return nil
	}
	if write && r.Header.Get("X-CSRF-Token") != sess.stored.CSRFToken {
		writeError(w, apierr.InvalidCSRF)
		return nil
	}
	return sess
}

// checkWriteHeaders enforces `X-Requested-With: ReactAdminStarter`, before
// any authentication, and the origin policy.
func (s *Server) checkWriteHeaders(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Requested-With") != "ReactAdminStarter" {
		writeError(w, apierr.RequestHeaderRequired)
		return false
	}
	if !s.originAllowed(r) {
		writeError(w, apierr.OriginNotAllowed)
		return false
	}
	return true
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cfg.CookieName, Value: token, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
	})
}

var loginEmail = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.checkWriteHeaders(w, r) {
		return
	}
	ip := s.clientIP(r)
	body := readJSON(w, r)
	if body == nil {
		writeError(w, apierr.New(400, "INVALID_REQUEST", "请求内容必须是 JSON。"))
		return
	}
	var in struct {
		Email    *string `json:"email"`
		Password *string `json:"password"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Email == nil || in.Password == nil ||
		!loginEmail.MatchString(*in.Email) || *in.Password == "" {
		writeError(w, apierr.New(400, "INVALID_CREDENTIALS_FORMAT", "请输入有效的邮箱和密码。"))
		return
	}
	email := strings.ToLower(*in.Email)
	if !s.limiter.allow("ip:"+ip, "email:"+email) {
		writeError(w, apierr.RateLimited)
		return
	}
	snap, err := s.store.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	invalid := apierr.New(401, "INVALID_CREDENTIALS", "邮箱或密码错误。")
	account, found := snap.AccountByEmail(email)
	if !found {
		auth.VerifyDummy(*in.Password)
		writeError(w, invalid)
		return
	}
	hash, version, err := s.store.PasswordHash(r.Context(), account.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ok, err := auth.VerifyPassword(*in.Password, hash)
	user, active := snap.Principal(account.ID)
	if err != nil || !ok || !active || snap.CredentialVersions[account.ID] != version {
		writeError(w, invalid)
		return
	}
	token, csrf := auth.NewToken(), auth.NewToken()
	var replaced []byte
	if old, err := r.Cookie(s.cfg.CookieName); err == nil && old.Value != "" {
		replaced = auth.TokenHash(old.Value)
	}
	stored := store.Session{AccountID: account.ID, CredentialVersion: version, CSRFToken: csrf, ExpiresAt: time.Now().Add(s.cfg.SessionTTL)}
	if err := s.store.CreateSession(r.Context(), auth.TokenHash(token), replaced, stored, ip, r.UserAgent()); err != nil {
		s.fail(w, r, err)
		return
	}
	actor := store.Actor{ID: user.ID, Name: user.Name, Email: user.Email, DepartmentID: user.DepartmentID, IP: ip}
	if err := s.store.AppendAudit(r.Context(), actor, "auth.sign_in", user.Email, "登录管理端"); err != nil {
		s.fail(w, r, err)
		return
	}
	s.setSessionCookie(w, token, int(s.cfg.SessionTTL.Seconds()))
	writeData(w, http.StatusOK, map[string]any{"user": user, "csrfToken": csrf})
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	sess := s.guard(w, r, "")
	if sess == nil {
		return
	}
	writeData(w, http.StatusOK, map[string]any{"user": sess.user, "csrfToken": sess.stored.CSRFToken})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	sess := s.guard(w, r, "")
	if sess == nil {
		return
	}
	if err := s.store.AppendAudit(r.Context(), sess.actor(), "auth.sign_out", sess.user.Email, "退出登录"); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.DeleteSession(r.Context(), sess.tokenHash); err != nil {
		s.fail(w, r, err)
		return
	}
	s.setSessionCookie(w, "", -1)
	writeData(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) getPermissions(w http.ResponseWriter, r *http.Request) {
	sess := s.guard(w, r, "permissions:read")
	if sess == nil {
		return
	}
	writeData(w, http.StatusOK, map[string]any{"roles": sess.user.Roles, "permissions": sess.user.Permissions})
}

func (s *Server) navigation(w http.ResponseWriter, r *http.Request) {
	sess := s.guard(w, r, "")
	if sess == nil {
		return
	}
	writeData(w, http.StatusOK, sess.snap.Navigation(sess.user))
}
