// Package apierr defines the API error type. Every non-2xx response is
// `{ "error": { "code", "message" } }` with the status below; codes follow the
// error table in react-admin-starter src/contract/errors.ts.
package apierr

import (
	"errors"

	"github.com/braver-braver/go-admin-server/internal/authz"
)

type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func New(status int, code, message string) *Error {
	return &Error{Status: status, Code: code, Message: message}
}

// Shared errors.
var (
	Unauthenticated       = New(401, "UNAUTHENTICATED", "请先登录。")
	Forbidden             = New(403, "FORBIDDEN", "没有执行该操作的权限。")
	RequestHeaderRequired = New(403, "REQUEST_HEADER_REQUIRED", "缺少请求来源标识。")
	InvalidCSRF           = New(403, "INVALID_CSRF_TOKEN", "请求令牌无效。")
	OriginNotAllowed      = New(403, "FORBIDDEN", "请求来源不被允许。")
	ScopeDenied           = New(403, "DATA_SCOPE_DENIED", "数据超出当前范围。")
	BatchScopeDenied      = New(403, "DATA_SCOPE_DENIED", "批量操作包含范围外数据，未执行任何更改。")
	NotFound              = New(404, "NOT_FOUND", "接口不存在。")
	InvalidMethod         = New(400, "INVALID_METHOD", "操作与资源路径不匹配。")
	// Not yet in the frontend error table: 429 for login throttling and 500.
	RateLimited = New(429, "RATE_LIMITED", "尝试次数过多，请稍后再试。")
	Internal    = New(500, "INTERNAL", "服务器内部错误，请稍后重试。")
)

// From converts any error to an API error; unknown errors become Internal.
func From(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	var r *authz.RuleError
	if errors.As(err, &r) {
		return New(r.Status, r.Code, r.Message)
	}
	return Internal
}
