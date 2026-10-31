package store

import (
	"context"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/braver-braver/go-admin-server/internal/authz"
)

// AuditLog is one audit record as the API returns it.
type AuditLog struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"createdAt"`
	ActorName  string    `json:"actorName"`
	ActorEmail string    `json:"actorEmail"`
	Action     string    `json:"action"`
	Target     string    `json:"target"`
	Detail     string    `json:"detail"`
	IP         string    `json:"ip"`
}

// AuditActions is the whitelist of audit actions (src/contract/audit.ts).
var AuditActions = []string{
	"auth.sign_in", "auth.sign_out", "user.created", "user.updated", "user.deleted",
	"user.batch_deleted", "user.status_changed", "user.invited", "user.batch_invited", "system.changed",
}

// Audit appends an audit record with q, so it commits or rolls back together
// with the change it describes.
func Audit(ctx context.Context, q Querier, a Actor, action, target, detail string) error {
	_, err := q.Exec(ctx, `INSERT INTO audit_logs (actor_id, actor_name, actor_email, department_id, action, target, detail, ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, a.ID, a.Name, a.Email, a.DepartmentID, action, target, detail, a.IP)
	return err
}

// AppendAudit records an event outside a business transaction (sign in/out).
func (s *Store) AppendAudit(ctx context.Context, a Actor, action, target, detail string) error {
	return Audit(ctx, s.pool, a, action, target, detail)
}

// Page is a requested page; the result reports the effective values.
type Page struct {
	Page     int
	PageSize int
}

// PageMeta is the `meta` of every paged list.
type PageMeta struct {
	Page           int `json:"page"`
	PageSize       int `json:"pageSize"`
	Total          int `json:"total"`
	TotalPageCount int `json:"totalPageCount"`
}

// List is the `{ items, meta }` envelope of every paged list.
type List[T any] struct {
	Items []T      `json:"items"`
	Meta  PageMeta `json:"meta"`
}

// ClampPage keeps the page within [1, totalPageCount], like the reference mock
// does for users and audit logs.
func ClampPage(p Page, total int) PageMeta {
	pages := max(1, (total+p.PageSize-1)/p.PageSize)
	return PageMeta{Page: min(max(1, p.Page), pages), PageSize: p.PageSize, Total: total, TotalPageCount: pages}
}

// ScopeSQL renders a data scope as a SQL condition over the given department
// and owner columns, appending its arguments.
func ScopeSQL(f authz.ScopeFilter, deptCol, ownerCol string, args *[]any) string {
	return ScopeSQLAny(f, deptCol, []string{ownerCol}, args)
}

// ScopeSQLAny is ScopeSQL for records with several owners, e.g. a creator and
// an assignee: "self" matches a row when any of ownerCols is the actor.
func ScopeSQLAny(f authz.ScopeFilter, deptCol string, ownerCols []string, args *[]any) string {
	if f.All {
		return "true"
	}
	*args = append(*args, f.DepartmentIDs)
	cond := "(" + deptCol + " = ANY($" + strconv.Itoa(len(*args)) + ")"
	if f.SelfID != "" && len(ownerCols) > 0 {
		*args = append(*args, f.SelfID)
		for _, col := range ownerCols {
			cond += " OR " + col + " = $" + strconv.Itoa(len(*args))
		}
	}
	return cond + ")"
}

// ListAudit lists audit logs within a data scope, newest first. The scope and
// the action filter apply before counting and paging.
func (s *Store) ListAudit(ctx context.Context, scope authz.ScopeFilter, actions []string, p Page) (List[AuditLog], error) {
	var args []any
	where := ScopeSQL(scope, "department_id", "actor_id", &args)
	if len(actions) > 0 {
		args = append(args, actions)
		where += " AND action = ANY($" + strconv.Itoa(len(args)) + ")"
	}
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE `+where, args...).Scan(&total); err != nil {
		return List[AuditLog]{}, err
	}
	meta := ClampPage(p, total)
	args = append(args, meta.PageSize, (meta.Page-1)*meta.PageSize)
	rows, err := s.pool.Query(ctx, `SELECT id, created_at, actor_name, actor_email, action, target, detail, ip
		FROM audit_logs WHERE `+where+` ORDER BY created_at DESC, id DESC
		LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return List[AuditLog]{}, err
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (AuditLog, error) {
		var l AuditLog
		var id int64
		err := r.Scan(&id, &l.CreatedAt, &l.ActorName, &l.ActorEmail, &l.Action, &l.Target, &l.Detail, &l.IP)
		l.ID = strconv.FormatInt(id, 10)
		l.CreatedAt = l.CreatedAt.UTC()
		return l, err
	})
	return List[AuditLog]{Items: items, Meta: meta}, err
}
