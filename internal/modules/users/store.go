package users

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/braver-braver/go-admin-server/internal/store"

	"github.com/braver-braver/go-admin-server/internal/apierr"
	"github.com/braver-braver/go-admin-server/internal/authz"
)

// User is a business user record as the API returns it.
type User struct {
	ID             string    `json:"id"`
	DepartmentID   string    `json:"departmentId"`
	DepartmentName string    `json:"departmentName,omitempty"`
	CreatedBy      string    `json:"createdBy"`
	FirstName      string    `json:"firstName"`
	LastName       string    `json:"lastName"`
	Username       string    `json:"username"`
	Email          string    `json:"email"`
	PhoneNumber    string    `json:"phoneNumber"`
	Status         string    `json:"status"`
	Role           string    `json:"role"`
	AvatarURL      string    `json:"avatarUrl,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

func (u *User) record() authz.Record {
	return authz.Record{DepartmentID: u.DepartmentID, CreatedBy: u.CreatedBy}
}

// UserFields are the writable fields of a user.
type UserFields struct {
	FirstName, LastName, Username, Email, PhoneNumber, Role string
	DepartmentID                                            string // empty: actor's department (create) or unchanged (update)
	AvatarURL                                               string // on update, used only when the body has avatarUrl
}

// UsersQuery is a validated list query.
type UsersQuery struct {
	store.Page
	Search    string
	Status    []string
	Role      []string
	SortBy    string // one of the whitelisted keys
	SortOrder string // "asc" or "desc"
}

// sortColumns maps the whitelisted sort keys to SQL. Text columns sort in
// Chinese collation, like the reference mock.
var sortColumns = map[string]string{
	"username":    `u.username COLLATE zh_sort`,
	"fullName":    `(u.last_name || u.first_name) COLLATE zh_sort`,
	"email":       `u.email COLLATE zh_sort`,
	"phoneNumber": `u.phone_number COLLATE zh_sort`,
	"status":      `u.status`,
	"role":        `u.role`,
	"createdAt":   `u.created_at`,
	"updatedAt":   `u.updated_at`,
}

// SortKeys lists the accepted values of sortBy.
func SortKeys() map[string]string { return sortColumns }

const userColumns = `u.id, u.department_id, coalesce(d.name, u.department_id), u.created_by, u.first_name, u.last_name,
	u.username, u.email, u.phone_number, u.status, u.role, u.avatar_url, u.created_at, u.updated_at`

func scanUser(r pgx.Row) (User, error) {
	var u User
	err := r.Scan(&u.ID, &u.DepartmentID, &u.DepartmentName, &u.CreatedBy, &u.FirstName, &u.LastName,
		&u.Username, &u.Email, &u.PhoneNumber, &u.Status, &u.Role, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt)
	u.CreatedAt, u.UpdatedAt = u.CreatedAt.UTC(), u.UpdatedAt.UTC()
	return u, err
}

// ListUsers filters by data scope and query before sorting, counting and paging.
func (r *Repo) ListUsers(ctx context.Context, scope authz.ScopeFilter, q UsersQuery) (store.List[User], error) {
	var args []any
	arg := func(v any) string { args = append(args, v); return "$" + strconv.Itoa(len(args)) }
	where := store.ScopeSQL(scope, "u.department_id", "u.created_by", &args)
	if q.Search != "" {
		p := arg("%" + escapeLike(strings.ToLower(q.Search)) + "%")
		where += fmt.Sprintf(` AND lower(u.username || ' ' || u.email || ' ' || u.last_name || u.first_name || ' ' || u.phone_number) LIKE %s`, p)
	}
	if len(q.Status) > 0 {
		where += " AND u.status = ANY(" + arg(q.Status) + ")"
	}
	if len(q.Role) > 0 {
		where += " AND u.role = ANY(" + arg(q.Role) + ")"
	}
	var total int
	if err := r.st.DB().QueryRow(ctx, `SELECT count(*) FROM users u WHERE `+where, args...).Scan(&total); err != nil {
		return store.List[User]{}, err
	}
	meta := store.ClampPage(q.Page, total)
	dir := "ASC"
	if q.SortOrder == "desc" {
		dir = "DESC"
	}
	order := sortColumns[q.SortBy] + " " + dir + ", u.id " + dir
	limit, offset := arg(meta.PageSize), arg((meta.Page-1)*meta.PageSize)
	rows, err := r.st.DB().Query(ctx, `SELECT `+userColumns+` FROM users u LEFT JOIN departments d ON d.id = u.department_id
		WHERE `+where+` ORDER BY `+order+` LIMIT `+limit+` OFFSET `+offset, args...)
	if err != nil {
		return store.List[User]{}, err
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (User, error) { return scanUser(r) })
	return store.List[User]{Items: items, Meta: meta}, err
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func getUser(ctx context.Context, q store.Querier, id string, lock bool) (*User, error) {
	sql := `SELECT ` + userColumns + ` FROM users u LEFT JOIN departments d ON d.id = u.department_id WHERE u.id = $1`
	if lock {
		sql += ` FOR UPDATE OF u`
	}
	u, err := scanUser(q.QueryRow(ctx, sql, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

var (
	errUserNotFound  = apierr.New(404, "USER_NOT_FOUND", "用户不存在。")
	errDuplicateUser = apierr.New(422, "DUPLICATE_USER", "邮箱或用户名已存在。")
	errDeptDenied    = apierr.New(403, "DATA_SCOPE_DENIED", "所属部门超出范围或不可用。")
)

func duplicateUser(ctx context.Context, q store.Querier, email, username, exceptID string) (bool, error) {
	var dup bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id <> $3 AND (lower(email) = lower($1) OR lower(username) = lower($2)))`,
		strings.TrimSpace(email), strings.TrimSpace(username), exceptID).Scan(&dup)
	return dup, err
}

// usableDepartment reports whether business records may be placed in a
// department: it must exist and be enabled.
func usableDepartment(snap *authz.Snapshot, id string) bool {
	d, ok := snap.Department(id)
	return ok && d.Enabled
}

// CreateUser creates a business user owned by the actor.
func (r *Repo) CreateUser(ctx context.Context, p *authz.Principal, snap *authz.Snapshot, actor store.Actor, id string, f UserFields) (*User, error) {
	var created *User
	err := r.st.Tx(ctx, func(tx pgx.Tx) error {
		if dup, err := duplicateUser(ctx, tx, f.Email, f.Username, ""); err != nil || dup {
			return orErr(err, errDuplicateUser)
		}
		dept := f.DepartmentID
		if dept == "" {
			dept = p.DepartmentID
		}
		rec := authz.Record{DepartmentID: dept, CreatedBy: p.ID}
		if !p.CanAccess(rec, "users:write") || !p.CanWriteDepartment(dept) || !usableDepartment(snap, dept) {
			return errDeptDenied
		}
		_, err := tx.Exec(ctx, `INSERT INTO users (id, department_id, created_by, first_name, last_name, username, email, phone_number, status, role, avatar_url)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,$10)`,
			id, dept, p.ID, f.FirstName, f.LastName, f.Username, f.Email, f.PhoneNumber, f.Role, f.AvatarURL)
		if store.IsUniqueViolation(err) {
			return errDuplicateUser
		}
		if err != nil {
			return err
		}
		if created, err = getUser(ctx, tx, id, false); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "user.created", created.Username+"（"+created.Email+"）", "创建用户并分配角色 "+created.Role)
	})
	return created, err
}

// UpdateUser checks the scope of the record before and after the change.
func (r *Repo) UpdateUser(ctx context.Context, p *authz.Principal, snap *authz.Snapshot, actor store.Actor, id string, parse func() (UserFields, bool, error)) (*User, error) {
	var updated *User
	err := r.st.Tx(ctx, func(tx pgx.Tx) error {
		existing, err := getUser(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if existing == nil {
			return errUserNotFound
		}
		if !p.CanAccess(existing.record(), "users:write") {
			return apierr.ScopeDenied
		}
		f, avatarSet, err := parse()
		if err != nil {
			return err
		}
		if !avatarSet {
			f.AvatarURL = existing.AvatarURL
		}
		if dup, err := duplicateUser(ctx, tx, f.Email, f.Username, id); err != nil || dup {
			return orErr(err, errDuplicateUser)
		}
		dept := f.DepartmentID
		if dept == "" {
			dept = existing.DepartmentID
		}
		if dept != existing.DepartmentID && !p.CanWriteDepartment(dept) {
			return apierr.New(403, "DATA_SCOPE_DENIED", "不能移到范围外的部门。")
		}
		moved := *existing
		moved.DepartmentID = dept
		if !p.CanAccess(moved.record(), "users:write") || !usableDepartment(snap, dept) {
			return errDeptDenied
		}
		_, err = tx.Exec(ctx, `UPDATE users SET department_id=$2, first_name=$3, last_name=$4, username=$5, email=$6,
			phone_number=$7, role=$8, avatar_url=$9, updated_at=now() WHERE id=$1`,
			id, dept, f.FirstName, f.LastName, f.Username, f.Email, f.PhoneNumber, f.Role, f.AvatarURL)
		if store.IsUniqueViolation(err) {
			return errDuplicateUser
		}
		if err != nil {
			return err
		}
		if updated, err = getUser(ctx, tx, id, false); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "user.updated", updated.Username+"（"+updated.Email+"）", "更新用户资料")
	})
	return updated, err
}

// DeleteUser deletes one user within the actor's write scope.
func (r *Repo) DeleteUser(ctx context.Context, p *authz.Principal, actor store.Actor, id string) error {
	return r.st.Tx(ctx, func(tx pgx.Tx) error {
		existing, err := getUser(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if existing == nil {
			return errUserNotFound
		}
		if !p.CanAccess(existing.record(), "users:write") {
			return apierr.ScopeDenied
		}
		if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, id); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "user.deleted", existing.Username+"（"+existing.Email+"）", "删除用户")
	})
}

// lockScoped locks the existing users among ids and rejects the whole batch if
// any of them is outside the actor's write scope. Unknown ids are ignored.
func lockScoped(ctx context.Context, tx pgx.Tx, p *authz.Principal, ids []string) ([]User, error) {
	rows, err := tx.Query(ctx, `SELECT `+userColumns+` FROM users u LEFT JOIN departments d ON d.id = u.department_id
		WHERE u.id = ANY($1) ORDER BY u.id FOR UPDATE OF u`, ids)
	if err != nil {
		return nil, err
	}
	users, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (User, error) { return scanUser(r) })
	if err != nil {
		return nil, err
	}
	for i := range users {
		if !p.CanAccess(users[i].record(), "users:write") {
			return nil, apierr.BatchScopeDenied
		}
	}
	return users, nil
}

func ids(users []User) []string {
	out := make([]string, len(users))
	for i, u := range users {
		out[i] = u.ID
	}
	return out
}

// BatchDeleteUsers deletes all or none.
func (r *Repo) BatchDeleteUsers(ctx context.Context, p *authz.Principal, actor store.Actor, requested []string) (int, error) {
	n := 0
	err := r.st.Tx(ctx, func(tx pgx.Tx) error {
		users, err := lockScoped(ctx, tx, p, requested)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id = ANY($1)`, ids(users)); err != nil {
			return err
		}
		n = len(users)
		detail := "未匹配到用户"
		if n > 0 {
			detail = fmt.Sprintf("批量删除 %d 个用户", n)
		}
		return store.Audit(ctx, tx, actor, "user.batch_deleted", fmt.Sprintf("%d 个用户", n), detail)
	})
	return n, err
}

// SetUsersStatus enables or disables all or none.
func (r *Repo) SetUsersStatus(ctx context.Context, p *authz.Principal, actor store.Actor, requested []string, status string) (int, error) {
	n := 0
	err := r.st.Tx(ctx, func(tx pgx.Tx) error {
		users, err := lockScoped(ctx, tx, p, requested)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET status = $2, updated_at = now() WHERE id = ANY($1)`, ids(users), status); err != nil {
			return err
		}
		n = len(users)
		label := map[string]string{"active": "启用", "inactive": "停用"}[status]
		return store.Audit(ctx, tx, actor, "user.status_changed", fmt.Sprintf("%d 个用户", n), "批量变更为"+label)
	})
	return n, err
}

// InviteUser creates an invited user in the actor's department.
func (r *Repo) InviteUser(ctx context.Context, p *authz.Principal, actor store.Actor, id, email, role string) (*User, error) {
	var invited *User
	err := r.st.Tx(ctx, func(tx pgx.Tx) error {
		username := strings.ToLower(strings.SplitN(email, "@", 2)[0])
		if dup, err := duplicateUser(ctx, tx, email, username, ""); err != nil || dup {
			return orErr(err, apierr.New(422, "DUPLICATE_USER", "该邮箱已被邀请或已存在。"))
		}
		if !p.CanAccess(authz.Record{DepartmentID: p.DepartmentID, CreatedBy: p.ID}, "users:write") {
			return apierr.New(403, "DATA_SCOPE_DENIED", "所属部门超出当前范围。")
		}
		_, err := tx.Exec(ctx, `INSERT INTO users (id, department_id, created_by, first_name, last_name, username, email, phone_number, status, role)
			VALUES ($1,$2,$3,'待','邀请',$4,$5,'—','invited',$6)`, id, p.DepartmentID, p.ID, username, email, role)
		if store.IsUniqueViolation(err) {
			return apierr.New(422, "DUPLICATE_USER", "该邮箱已被邀请或已存在。")
		}
		if err != nil {
			return err
		}
		if invited, err = getUser(ctx, tx, id, false); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "user.invited", invited.Username+"（"+invited.Email+"）", "邀请加入并分配角色 "+role)
	})
	return invited, err
}

// BatchInviteUsers marks users as invited; already-invited users are skipped.
func (r *Repo) BatchInviteUsers(ctx context.Context, p *authz.Principal, actor store.Actor, requested []string) (int, error) {
	n := 0
	err := r.st.Tx(ctx, func(tx pgx.Tx) error {
		users, err := lockScoped(ctx, tx, p, requested)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE users SET status = 'invited', updated_at = now() WHERE id = ANY($1) AND status <> 'invited'`, ids(users))
		if err != nil {
			return err
		}
		n = int(tag.RowsAffected())
		return store.Audit(ctx, tx, actor, "user.batch_invited", fmt.Sprintf("%d 个用户", n), fmt.Sprintf("批量邀请 %d 个用户", n))
	})
	return n, err
}

func orErr(err error, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}
