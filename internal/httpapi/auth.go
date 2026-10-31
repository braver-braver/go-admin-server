package httpapi

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/braver-braver/go-admin-server/internal/apierr"
	"github.com/braver-braver/go-admin-server/internal/auth"
	"github.com/braver-braver/go-admin-server/internal/httpx"
	"github.com/braver-braver/go-admin-server/internal/store"
)

// authenticate resolves the session cookie. A session is valid only while the
// account still has a principal and its credential version is unchanged.
func (s *Server) authenticate(r *http.Request) (*httpx.Session, error) {
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
	return &httpx.Session{User: user, Snap: snap, CSRFToken: stored.CSRFToken,
		CredentialVersion: stored.CredentialVersion, TokenHash: hash, IP: s.clientIP(r)}, nil
}

// guard runs the contract's checks in order: request header and origin for
// writes, then session, capability and CSRF token. It writes the error and
// returns nil when a check fails.
func (s *Server) guard(w http.ResponseWriter, r *http.Request, permission string) *httpx.Session {
	write := isWrite(r)
	if write && !s.checkWriteHeaders(w, r) {
		return nil
	}
	sess, err := s.authenticate(r)
	if err != nil {
		s.fail(w, r, err)
		return nil
	}
	if permission != "" && !sess.User.Has(permission) {
		httpx.WriteError(w, apierr.Forbidden)
		return nil
	}
	if write && r.Header.Get("X-CSRF-Token") != sess.CSRFToken {
		httpx.WriteError(w, apierr.InvalidCSRF)
		return nil
	}
	return sess
}

// checkWriteHeaders enforces `X-Requested-With: ReactAdminStarter`, before
// any authentication, and the origin policy.
func (s *Server) checkWriteHeaders(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Requested-With") != "ReactAdminStarter" {
		httpx.WriteError(w, apierr.RequestHeaderRequired)
		return false
	}
	if !s.originAllowed(r) {
		httpx.WriteError(w, apierr.OriginNotAllowed)
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

func (s *Server) login(c *httpx.Ctx) {
	w, r := c.W, c.R
	body := c.Body()
	if body == nil {
		httpx.WriteError(w, apierr.New(400, "INVALID_REQUEST", "请求内容必须是 JSON。"))
		return
	}
	var in struct {
		Email    *string `json:"email"`
		Password *string `json:"password"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Email == nil || in.Password == nil ||
		!loginEmail.MatchString(*in.Email) || *in.Password == "" {
		httpx.WriteError(w, apierr.New(400, "INVALID_CREDENTIALS_FORMAT", "请输入有效的邮箱和密码。"))
		return
	}
	email := strings.ToLower(*in.Email)
	if !s.limiter.allow("ip:"+c.IP, "email:"+email) {
		httpx.WriteError(w, apierr.RateLimited)
		return
	}
	snap, err := s.store.Snapshot(r.Context())
	if err != nil {
		c.Fail(err)
		return
	}
	invalid := apierr.New(401, "INVALID_CREDENTIALS", "邮箱或密码错误。")
	account, found := snap.AccountByEmail(email)
	if !found {
		auth.VerifyDummy(*in.Password)
		httpx.WriteError(w, invalid)
		return
	}
	hash, version, err := s.store.PasswordHash(r.Context(), account.ID)
	if err != nil {
		c.Fail(err)
		return
	}
	ok, err := auth.VerifyPassword(*in.Password, hash)
	user, active := snap.Principal(account.ID)
	if err != nil || !ok || !active || snap.CredentialVersions[account.ID] != version {
		httpx.WriteError(w, invalid)
		return
	}
	token, csrf := auth.NewToken(), auth.NewToken()
	var replaced []byte
	if old, err := r.Cookie(s.cfg.CookieName); err == nil && old.Value != "" {
		replaced = auth.TokenHash(old.Value)
	}
	stored := store.Session{AccountID: account.ID, CredentialVersion: version, CSRFToken: csrf, ExpiresAt: time.Now().Add(s.cfg.SessionTTL)}
	if err := s.store.CreateSession(r.Context(), auth.TokenHash(token), replaced, stored, c.IP, r.UserAgent()); err != nil {
		c.Fail(err)
		return
	}
	actor := store.Actor{ID: user.ID, Name: user.Name, Email: user.Email, DepartmentID: user.DepartmentID, IP: c.IP}
	if err := s.store.AppendAudit(r.Context(), actor, "auth.sign_in", user.Email, "登录管理端"); err != nil {
		c.Fail(err)
		return
	}
	s.setSessionCookie(w, token, int(s.cfg.SessionTTL.Seconds()))
	c.OK(map[string]any{"user": user, "csrfToken": csrf})
}

func (s *Server) getSession(c *httpx.Ctx) {
	c.OK(map[string]any{"user": c.User(), "csrfToken": c.Session.CSRFToken})
}

func (s *Server) logout(c *httpx.Ctx) {
	if err := s.store.AppendAudit(c.Context(), c.Session.Actor(), "auth.sign_out", c.User().Email, "退出登录"); err != nil {
		c.Fail(err)
		return
	}
	if err := s.store.DeleteSession(c.Context(), c.Session.TokenHash); err != nil {
		c.Fail(err)
		return
	}
	s.setSessionCookie(c.W, "", -1)
	c.OK(map[string]bool{"success": true})
}

func (s *Server) getPermissions(c *httpx.Ctx) {
	c.OK(map[string]any{"roles": c.User().Roles, "permissions": c.User().Permissions})
}

func (s *Server) navigation(c *httpx.Ctx) {
	c.OK(c.Session.Snap.Navigation(c.User()))
}

func (s *Server) listAudit(c *httpx.Ctx) {
	list, err := s.store.ListAudit(c.Context(), c.User().Filter("audit:read"), c.Multi("action"), c.Page())
	if err != nil {
		c.Fail(err)
		return
	}
	c.OK(list)
}
