package tickets

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/braver-braver/go-admin-server/internal/apierr"
	"github.com/braver-braver/go-admin-server/internal/authz"
	"github.com/braver-braver/go-admin-server/internal/store"
)

// Repo holds the module's queries and transactions.
type Repo struct{ st *store.Store }

// scopeSQL filters tickets by a capability's scope: department, or for "self"
// the creator or the assignee.
func scopeSQL(p *authz.Principal, capability string, args *[]any) string {
	return store.ScopeSQLAny(p.Filter(capability), "t.department_id", []string{"t.created_by", "t.assignee_id"}, args)
}

// Query is a validated list query.
type Query struct {
	store.Page
	Search                     string
	Status, Priority, Category []string
	Assignee                   string // "", "me", "unassigned" or an account id
	SortBy, SortOrder          string
}

// sortColumns maps the whitelisted sort keys to SQL.
var sortColumns = map[string]string{
	"number":    "t.number",
	"title":     "t.title COLLATE zh_sort",
	"priority":  "array_position(ARRAY['low','medium','high','urgent'], t.priority)",
	"status":    "array_position(ARRAY['open','in_progress','resolved','closed'], t.status)",
	"createdAt": "t.created_at",
	"updatedAt": "t.updated_at",
}

// List filters by scope and query before counting, sorting and paging.
func (r *Repo) List(ctx context.Context, p *authz.Principal, q Query) (store.List[Ticket], error) {
	var args []any
	arg := func(v any) string { args = append(args, v); return "$" + strconv.Itoa(len(args)) }
	where := scopeSQL(p, CapRead, &args)
	if q.Search != "" {
		like := arg("%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(q.Search)) + "%")
		where += " AND (lower(t.number) LIKE " + like + " OR lower(t.title) LIKE " + like + ")"
	}
	for col, values := range map[string][]string{"t.status": q.Status, "t.priority": q.Priority, "t.category": q.Category} {
		if len(values) > 0 {
			where += " AND " + col + " = ANY(" + arg(values) + ")"
		}
	}
	switch q.Assignee {
	case "":
	case "unassigned":
		where += " AND t.assignee_id IS NULL"
	case "me":
		where += " AND t.assignee_id = " + arg(p.ID)
	default:
		where += " AND t.assignee_id = " + arg(q.Assignee)
	}
	var total int
	if err := r.st.DB().QueryRow(ctx, `SELECT count(*) FROM tickets t WHERE `+where, args...).Scan(&total); err != nil {
		return store.List[Ticket]{}, err
	}
	meta := store.ClampPage(q.Page, total)
	dir := "ASC"
	if q.SortOrder == "desc" {
		dir = "DESC"
	}
	order := sortColumns[q.SortBy] + " " + dir + ", t.id " + dir
	limit, offset := arg(meta.PageSize), arg((meta.Page-1)*meta.PageSize)
	rows, err := r.st.DB().Query(ctx, `SELECT `+ticketColumns+ticketFrom+` WHERE `+where+` ORDER BY `+order+
		` LIMIT `+limit+` OFFSET `+offset, args...)
	if err != nil {
		return store.List[Ticket]{}, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Ticket, error) { return scanTicket(row) })
	return store.List[Ticket]{Items: items, Meta: meta}, err
}

// Summary is the response of GET /tickets/summary.
type Summary struct {
	Open         int `json:"open"`
	InProgress   int `json:"inProgress"`
	Resolved     int `json:"resolved"`
	Closed       int `json:"closed"`
	AssignedToMe int `json:"assignedToMe"`
}

func (r *Repo) Summary(ctx context.Context, p *authz.Principal) (Summary, error) {
	var args []any
	where := scopeSQL(p, CapRead, &args)
	args = append(args, p.ID)
	var s Summary
	err := r.st.DB().QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE t.status = 'open'),
			count(*) FILTER (WHERE t.status = 'in_progress'),
			count(*) FILTER (WHERE t.status = 'resolved'),
			count(*) FILTER (WHERE t.status = 'closed'),
			count(*) FILTER (WHERE t.status IN ('open', 'in_progress') AND t.assignee_id = $`+strconv.Itoa(len(args))+`)
		FROM tickets t WHERE `+where, args...).Scan(&s.Open, &s.InProgress, &s.Resolved, &s.Closed, &s.AssignedToMe)
	return s, err
}

func getTicket(ctx context.Context, q store.Querier, id string, lock bool) (*Ticket, error) {
	sql := `SELECT ` + ticketColumns + ticketFrom + ` WHERE t.id = $1`
	if lock {
		sql += ` FOR UPDATE OF t`
	}
	t, err := scanTicket(q.QueryRow(ctx, sql, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// readable loads a ticket the principal can read; anything else is 404, so
// tickets outside the scope are not revealed.
func readable(ctx context.Context, q store.Querier, p *authz.Principal, id string, lock bool) (*Ticket, error) {
	t, err := getTicket(ctx, q, id, lock)
	if err != nil {
		return nil, err
	}
	if t == nil || !canAccess(p, t, CapRead) {
		return nil, errNotFound
	}
	return t, nil
}

// writable loads and locks a ticket the principal can write.
func writable(ctx context.Context, tx pgx.Tx, p *authz.Principal, id string) (*Ticket, error) {
	t, err := readable(ctx, tx, p, id, true)
	if err != nil {
		return nil, err
	}
	if !canAccess(p, t, CapWrite) {
		return nil, apierr.ScopeDenied
	}
	return t, nil
}

// Get returns a ticket with its timeline.
func (r *Repo) Get(ctx context.Context, p *authz.Principal, id string) (*Detail, error) {
	t, err := readable(ctx, r.st.DB(), p, id, false)
	if err != nil {
		return nil, err
	}
	rows, err := r.st.DB().Query(ctx, `SELECT id, kind, actor_id, actor_name, body, from_status, to_status, assignee_name, created_at
		FROM ticket_events WHERE ticket_id = $1 ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	events, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Event, error) {
		var e Event
		var eid int64
		err := row.Scan(&eid, &e.Kind, &e.ActorID, &e.ActorName, &e.Body, &e.FromStatus, &e.ToStatus, &e.AssigneeName, &e.CreatedAt)
		e.ID, e.CreatedAt = strconv.FormatInt(eid, 10), e.CreatedAt.UTC()
		return e, err
	})
	if err != nil {
		return nil, err
	}
	return &Detail{Ticket: *t, Events: events}, nil
}

// event appends to a ticket's timeline and returns the stored event.
func event(ctx context.Context, tx pgx.Tx, ticketID, kind string, actor store.Actor, body string, from, to, assignee *string) (Event, error) {
	e := Event{Kind: kind, ActorID: actor.ID, ActorName: actor.Name, Body: body, FromStatus: from, ToStatus: to, AssigneeName: assignee}
	var id int64
	err := tx.QueryRow(ctx, `INSERT INTO ticket_events (ticket_id, kind, actor_id, actor_name, body, from_status, to_status, assignee_name)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id, created_at`, ticketID, kind, actor.ID, actor.Name, body, from, to, assignee).
		Scan(&id, &e.CreatedAt)
	e.ID, e.CreatedAt = strconv.FormatInt(id, 10), e.CreatedAt.UTC()
	return e, err
}

func label(t *Ticket) string { return t.Number + " " + t.Title }

// assignee resolves an account that may take a ticket.
func assignee(snap *authz.Snapshot, id string, t *Ticket) (*authz.Principal, error) {
	a, ok := snap.Principal(id)
	if !ok || !a.Has(CapWrite) || !canBeAssigned(a, t) {
		return nil, errAssignee
	}
	return a, nil
}

// Create opens a ticket in the actor's department unless another one in its
// write scope is given, optionally assigned.
func (r *Repo) Create(ctx context.Context, p *authz.Principal, snap *authz.Snapshot, actor store.Actor, id string, f fields, dept, assigneeID string) (*Ticket, error) {
	if dept == "" {
		dept = p.DepartmentID
	}
	draft := &Ticket{DepartmentID: dept, CreatedBy: p.ID}
	if !canAccess(p, draft, CapWrite) || !p.CanWriteDepartment(CapWrite, dept) || !snap.ActiveDepartment(dept) {
		return nil, errDeptDenied
	}
	var who *authz.Principal
	if assigneeID != "" {
		var err error
		if who, err = assignee(snap, assigneeID, draft); err != nil {
			return nil, err
		}
	}
	var created *Ticket
	err := r.st.Tx(ctx, func(tx pgx.Tx) error {
		var seq int64
		if err := tx.QueryRow(ctx, `SELECT nextval('ticket_number_seq')`).Scan(&seq); err != nil {
			return err
		}
		var assignID, assignName *string
		if who != nil {
			assignID, assignName = &who.ID, &who.Name
		}
		if _, err := tx.Exec(ctx, `INSERT INTO tickets (id, number, title, description, category, priority, status, department_id,
				created_by, created_by_name, assignee_id, assignee_name) VALUES ($1,$2,$3,$4,$5,$6,'open',$7,$8,$9,$10,$11)`,
			id, fmt.Sprintf("TK-%06d", seq), f.Title, f.Description, f.Category, f.Priority, dept, p.ID, p.Name, assignID, assignName); err != nil {
			return err
		}
		if _, err := event(ctx, tx, id, "created", actor, "", nil, nil, nil); err != nil {
			return err
		}
		if who != nil {
			if _, err := event(ctx, tx, id, "assigned", actor, "", nil, nil, assignName); err != nil {
				return err
			}
		}
		var err error
		if created, err = getTicket(ctx, tx, id, false); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "ticket.created", label(created), "创建工单")
	})
	return created, err
}

// Update edits the content of an open ticket.
func (r *Repo) Update(ctx context.Context, p *authz.Principal, actor store.Actor, id string, parse func() (fields, error)) (*Ticket, error) {
	var updated *Ticket
	err := r.st.Tx(ctx, func(tx pgx.Tx) error {
		t, err := writable(ctx, tx, p, id)
		if err != nil {
			return err
		}
		if t.Status == "closed" {
			return errClosed
		}
		f, err := parse()
		if err != nil {
			return err
		}
		if f == (fields{t.Title, t.Description, t.Category, t.Priority}) {
			updated = t
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE tickets SET title=$2, description=$3, category=$4, priority=$5, updated_at=now() WHERE id=$1`,
			id, f.Title, f.Description, f.Category, f.Priority); err != nil {
			return err
		}
		if _, err := event(ctx, tx, id, "updated", actor, "", nil, nil, nil); err != nil {
			return err
		}
		if updated, err = getTicket(ctx, tx, id, false); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "ticket.updated", label(updated), "编辑工单内容")
	})
	return updated, err
}

// Comment adds a comment to an open ticket's timeline.
func (r *Repo) Comment(ctx context.Context, p *authz.Principal, actor store.Actor, id string, parse func() (string, error)) (*Event, error) {
	var added Event
	err := r.st.Tx(ctx, func(tx pgx.Tx) error {
		t, err := writable(ctx, tx, p, id)
		if err != nil {
			return err
		}
		if t.Status == "closed" {
			return errClosed
		}
		body, err := parse()
		if err != nil {
			return err
		}
		if added, err = event(ctx, tx, id, "comment", actor, body, nil, nil, nil); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE tickets SET updated_at = now() WHERE id = $1`, id); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "ticket.commented", label(t), "添加评论")
	})
	return &added, err
}

// Transition moves a ticket to another status.
func (r *Repo) Transition(ctx context.Context, p *authz.Principal, actor store.Actor, id, to, comment string) (*Ticket, error) {
	var moved *Ticket
	err := r.st.Tx(ctx, func(tx pgx.Tx) error {
		t, err := writable(ctx, tx, p, id)
		if err != nil {
			return err
		}
		if !canTransition(t.Status, to) {
			return errTransition
		}
		// resolved_at and closed_at describe the current state: set on
		// entering it, cleared on reopening.
		if _, err := tx.Exec(ctx, `UPDATE tickets SET status = $2, updated_at = now(),
				resolved_at = CASE WHEN $2 = 'resolved' THEN now() WHEN $2 = 'closed' THEN resolved_at ELSE NULL END,
				closed_at = CASE WHEN $2 = 'closed' THEN now() ELSE NULL END
			WHERE id = $1`, id, to); err != nil {
			return err
		}
		from := t.Status
		if _, err := event(ctx, tx, id, "status_changed", actor, comment, &from, &to, nil); err != nil {
			return err
		}
		if moved, err = getTicket(ctx, tx, id, false); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "ticket.status_changed", label(moved), statusLabels[from]+" → "+statusLabels[to])
	})
	return moved, err
}

// Assign sets (or with an empty id clears) the assignee of every ticket, or
// of none: each must be in the actor's assign scope, not closed, and
// reachable by the assignee.
func (r *Repo) Assign(ctx context.Context, p *authz.Principal, snap *authz.Snapshot, actor store.Actor, ids []string, assigneeID string) (int, error) {
	changed := 0
	err := r.st.Tx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+ticketColumns+ticketFrom+` WHERE t.id = ANY($1) ORDER BY t.id FOR UPDATE OF t`, ids)
		if err != nil {
			return err
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Ticket, error) { return scanTicket(row) })
		if err != nil {
			return err
		}
		// Scope first, so a batch never reveals more than it may.
		for i := range list {
			if !canAccess(p, &list[i], CapAssign) {
				return apierr.BatchScopeDenied
			}
		}
		var who *authz.Principal
		for i := range list {
			if list[i].Status == "closed" {
				return errClosed
			}
			if assigneeID != "" {
				if who, err = assignee(snap, assigneeID, &list[i]); err != nil {
					return err
				}
			}
		}
		var newID, newName *string
		if who != nil {
			newID, newName = &who.ID, &who.Name
		}
		for i := range list {
			t := &list[i]
			if (t.AssigneeID == nil && newID == nil) || (t.AssigneeID != nil && newID != nil && *t.AssigneeID == *newID) {
				continue
			}
			if _, err := tx.Exec(ctx, `UPDATE tickets SET assignee_id = $2, assignee_name = $3, updated_at = now() WHERE id = $1`,
				t.ID, newID, newName); err != nil {
				return err
			}
			if _, err := event(ctx, tx, t.ID, "assigned", actor, "", nil, nil, newName); err != nil {
				return err
			}
			changed++
		}
		detail := "取消指派"
		if newName != nil {
			detail = "指派给 " + *newName
		}
		return store.Audit(ctx, tx, actor, "ticket.assigned", fmt.Sprintf("%d 个工单", changed), detail)
	})
	return changed, err
}
