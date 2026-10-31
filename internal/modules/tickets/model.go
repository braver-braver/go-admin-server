package tickets

import (
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/braver-braver/go-admin-server/internal/apierr"
	"github.com/braver-braver/go-admin-server/internal/authz"
)

// Ticket is a ticket as the API returns it (src/contract/tickets.ts).
type Ticket struct {
	ID             string     `json:"id"`
	Number         string     `json:"number"`
	Title          string     `json:"title"`
	Description    string     `json:"description"`
	Category       string     `json:"category"`
	Priority       string     `json:"priority"`
	Status         string     `json:"status"`
	DepartmentID   string     `json:"departmentId"`
	DepartmentName string     `json:"departmentName"`
	CreatedBy      string     `json:"createdBy"`
	CreatedByName  string     `json:"createdByName"`
	AssigneeID     *string    `json:"assigneeId"`
	AssigneeName   *string    `json:"assigneeName"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
	ResolvedAt     *time.Time `json:"resolvedAt"`
	ClosedAt       *time.Time `json:"closedAt"`
}

// Event is one entry of a ticket's timeline.
type Event struct {
	ID           string    `json:"id"`
	Kind         string    `json:"kind"`
	ActorID      string    `json:"actorId"`
	ActorName    string    `json:"actorName"`
	Body         string    `json:"body"`
	FromStatus   *string   `json:"fromStatus"`
	ToStatus     *string   `json:"toStatus"`
	AssigneeName *string   `json:"assigneeName"`
	CreatedAt    time.Time `json:"createdAt"`
}

// Detail is a ticket with its timeline, oldest first.
type Detail struct {
	Ticket
	Events []Event `json:"events"`
}

var (
	statuses   = []string{"open", "in_progress", "resolved", "closed"}
	priorities = []string{"low", "medium", "high", "urgent"}
	categories = []string{"consultation", "fault", "request", "complaint"}

	// transitions mirrors ticketTransitions in the contract.
	transitions = map[string][]string{
		"open":        {"in_progress", "resolved", "closed"},
		"in_progress": {"open", "resolved", "closed"},
		"resolved":    {"in_progress", "closed"},
		"closed":      {"open"},
	}

	statusLabels = map[string]string{"open": "待处理", "in_progress": "处理中", "resolved": "已解决", "closed": "已关闭"}
)

func canTransition(from, to string) bool { return slices.Contains(transitions[from], to) }

// Errors of this module (registered in the frontend's error table).
var (
	errNotFound   = apierr.New(404, "TICKET_NOT_FOUND", "工单不存在或无权查看。")
	errClosed     = apierr.New(409, "TICKET_CLOSED", "工单已关闭，请先重新打开。")
	errTransition = apierr.New(409, "INVALID_TICKET_TRANSITION", "当前状态不能执行该操作，请刷新后重试。")
	errAssignee   = apierr.New(422, "INVALID_ASSIGNEE", "处理人不可用，或无权处理所选工单。")
	errDeptDenied = apierr.New(403, "DATA_SCOPE_DENIED", "所属部门超出范围或不可用。")
)

func invalid(message string) *apierr.Error { return apierr.New(422, "INVALID_TICKET_FIELDS", message) }

// canAccess reports whether a principal reaches a ticket through a
// capability. "self" covers tickets the account created or is assigned to:
// assigning a ticket to a self-scoped account is how it gets that ticket.
func canAccess(p *authz.Principal, t *Ticket, capability string) bool {
	if p.CanAccess(authz.Record{DepartmentID: t.DepartmentID, CreatedBy: t.CreatedBy}, capability) {
		return true
	}
	scope, ok := p.DataScopes[capability]
	return ok && scope.Self && t.AssigneeID != nil && *t.AssigneeID == p.ID
}

// canBeAssigned reports whether an account may be made the assignee of a
// ticket: it needs tickets:write covering the ticket's department, or a self
// scope, which the assignment itself then satisfies.
func canBeAssigned(assignee *authz.Principal, t *Ticket) bool {
	scope, ok := assignee.DataScopes[CapWrite]
	return ok && (scope.Self || canAccess(assignee, t, CapWrite))
}

// fields are the editable content of a ticket.
type fields struct {
	Title, Description, Category, Priority string
}

// parseFields mirrors the contract: missing or blank title, then
// description, then the enums; strings are trimmed.
func parseFields(raw map[string]any) (fields, error) {
	text := func(key string) string {
		v, _ := raw[key].(string)
		return strings.TrimSpace(v)
	}
	f := fields{Title: text("title"), Description: text("description")}
	f.Category, _ = raw["category"].(string)
	f.Priority, _ = raw["priority"].(string)
	switch {
	case f.Title == "":
		return f, invalid("请输入标题。")
	case utf8.RuneCountInString(f.Title) > 120:
		return f, invalid("标题最多 120 字。")
	case f.Description == "":
		return f, invalid("请描述问题。")
	case utf8.RuneCountInString(f.Description) > 5000:
		return f, invalid("描述最多 5000 字。")
	case !slices.Contains(categories, f.Category):
		return f, invalid("请选择有效的类型。")
	case !slices.Contains(priorities, f.Priority):
		return f, invalid("请选择有效的优先级。")
	}
	return f, nil
}

const ticketColumns = `t.id, t.number, t.title, t.description, t.category, t.priority, t.status, t.department_id,
	coalesce(d.name, t.department_id), t.created_by, t.created_by_name, t.assignee_id, t.assignee_name,
	t.created_at, t.updated_at, t.resolved_at, t.closed_at`

const ticketFrom = ` FROM tickets t LEFT JOIN departments d ON d.id = t.department_id`

func scanTicket(r pgx.Row) (Ticket, error) {
	var t Ticket
	err := r.Scan(&t.ID, &t.Number, &t.Title, &t.Description, &t.Category, &t.Priority, &t.Status, &t.DepartmentID,
		&t.DepartmentName, &t.CreatedBy, &t.CreatedByName, &t.AssigneeID, &t.AssigneeName,
		&t.CreatedAt, &t.UpdatedAt, &t.ResolvedAt, &t.ClosedAt)
	t.CreatedAt, t.UpdatedAt = t.CreatedAt.UTC(), t.UpdatedAt.UTC()
	for _, ts := range []**time.Time{&t.ResolvedAt, &t.ClosedAt} {
		if *ts != nil {
			u := (*ts).UTC()
			*ts = &u
		}
	}
	return t, err
}
