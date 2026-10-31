// Package tickets is a business module with a workflow: tickets (工单) that
// belong to a department, are assigned to accounts, move through a fixed
// status machine and keep a timeline of comments and changes.
//
// Data scopes: department scopes match the ticket's department; "self" matches
// tickets the account created or is assigned to, so assigning a ticket to a
// self-scoped account is how that account receives it.
package tickets

import (
	"context"
	"embed"
	"io/fs"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/braver-braver/go-admin-server/internal/apierr"
	"github.com/braver-braver/go-admin-server/internal/authz"
	"github.com/braver-braver/go-admin-server/internal/httpx"
	"github.com/braver-braver/go-admin-server/internal/store"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Capabilities of this module.
const (
	CapRead   = "tickets:read"
	CapWrite  = "tickets:write"
	CapAssign = "tickets:assign"
)

type Module struct{ repo *Repo }

func New(st *store.Store) *Module { return &Module{repo: &Repo{st: st}} }

func (m *Module) Name() string { return "tickets" }

func (m *Module) Catalog() authz.Catalog {
	return authz.Catalog{
		Capabilities: []authz.Capability{
			{Code: CapRead, Method: "GET", Path: "/api/v1/tickets", Name: "查看工单"},
			{Code: CapWrite, Method: "POST / PUT", Path: "/api/v1/tickets/*", Name: "处理工单"},
			{Code: CapAssign, Method: "POST", Path: "/api/v1/tickets/assign", Name: "指派工单"},
		},
		Routes: []authz.Route{
			{ID: "tickets", Path: "/tickets", Name: "工单管理", Permission: CapRead, Menu: authz.MenuBusiness},
		},
	}
}

func (m *Module) Operations() []httpx.Op {
	return []httpx.Op{
		{Method: "GET", Path: "/tickets", ID: "listTickets", Permission: CapRead, Handle: m.list},
		{Method: "POST", Path: "/tickets", ID: "createTicket", Permission: CapWrite, Handle: m.create},
		{Method: "GET", Path: "/tickets/summary", ID: "ticketSummary", Permission: CapRead, Handle: m.summary},
		{Method: "GET", Path: "/tickets/assignees", ID: "listTicketAssignees", Permission: CapAssign, Handle: m.assignees},
		{Method: "POST", Path: "/tickets/assign", ID: "assignTickets", Permission: CapAssign, Handle: m.assign},
		{Method: "GET", Path: "/tickets/{id}", ID: "getTicket", Permission: CapRead, Handle: m.get},
		{Method: "PUT", Path: "/tickets/{id}", ID: "updateTicket", Permission: CapWrite, Handle: m.update},
		{Method: "POST", Path: "/tickets/{id}/comments", ID: "commentTicket", Permission: CapWrite, Handle: m.comment},
		{Method: "POST", Path: "/tickets/{id}/transition", ID: "transitionTicket", Permission: CapWrite, Handle: m.transition},
	}
}

func (m *Module) Migrations() fs.FS {
	sub, _ := fs.Sub(migrations, "migrations")
	return sub
}

// DepartmentInUse blocks deleting a department that still owns tickets.
func (m *Module) DepartmentInUse(ctx context.Context, q store.Querier, departmentID string) (bool, error) {
	var used bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tickets WHERE department_id = $1)`, departmentID).Scan(&used)
	return used, err
}

var (
	_ httpx.Module               = (*Module)(nil)
	_ httpx.DepartmentReferencer = (*Module)(nil)
	_ httpx.DemoSeeder           = (*Module)(nil)
)

// ---------------------------------------------------------------- handlers

func (m *Module) list(c *httpx.Ctx) {
	q := c.R.URL.Query()
	sortBy := q.Get("sortBy")
	if _, ok := sortColumns[sortBy]; !ok {
		sortBy = "updatedAt"
	}
	order := "desc"
	if q.Get("sortOrder") == "asc" {
		order = "asc"
	}
	list, err := m.repo.List(c.Context(), c.User(), Query{
		Page: c.Page(), Search: strings.TrimSpace(q.Get("search")),
		Status: c.Multi("status"), Priority: c.Multi("priority"), Category: c.Multi("category"),
		Assignee: strings.TrimSpace(q.Get("assignee")), SortBy: sortBy, SortOrder: order,
	})
	if err != nil {
		c.Fail(err)
		return
	}
	c.OK(list)
}

func (m *Module) summary(c *httpx.Ctx) {
	s, err := m.repo.Summary(c.Context(), c.User())
	if err != nil {
		c.Fail(err)
		return
	}
	c.OK(s)
}

func (m *Module) get(c *httpx.Ctx) {
	d, err := m.repo.Get(c.Context(), c.User(), c.R.PathValue("id"))
	if err != nil {
		c.Fail(err)
		return
	}
	c.OK(d)
}

func (m *Module) create(c *httpx.Ctx) {
	raw := c.Object()
	f, err := parseFields(raw)
	if err != nil {
		c.Fail(err)
		return
	}
	dept, _ := raw["departmentId"].(string)
	assigneeID, _ := raw["assigneeId"].(string)
	if assigneeID != "" && !c.User().Has(CapAssign) {
		c.Fail(apierr.Forbidden)
		return
	}
	t, err := m.repo.Create(c.Context(), c.User(), c.Session.Snap, c.Session.Actor(), httpx.NewID(), f, strings.TrimSpace(dept), assigneeID)
	if err != nil {
		c.Fail(err)
		return
	}
	c.Data(201, t)
}

func (m *Module) update(c *httpx.Ctx) {
	raw := c.Object()
	t, err := m.repo.Update(c.Context(), c.User(), c.Session.Actor(), c.R.PathValue("id"),
		func() (fields, error) { return parseFields(raw) })
	if err != nil {
		c.Fail(err)
		return
	}
	c.OK(t)
}

func text(raw map[string]any, key string) string {
	v, _ := raw[key].(string)
	return strings.TrimSpace(v)
}

func (m *Module) comment(c *httpx.Ctx) {
	raw := c.Object()
	e, err := m.repo.Comment(c.Context(), c.User(), c.Session.Actor(), c.R.PathValue("id"), func() (string, error) {
		body := text(raw, "body")
		switch {
		case body == "":
			return "", invalid("请输入内容。")
		case utf8.RuneCountInString(body) > 2000:
			return "", invalid("内容最多 2000 字。")
		}
		return body, nil
	})
	if err != nil {
		c.Fail(err)
		return
	}
	c.Data(201, e)
}

func (m *Module) transition(c *httpx.Ctx) {
	raw := c.Object()
	to, _ := raw["to"].(string)
	comment := text(raw, "comment")
	switch {
	case !slices.Contains(statuses, to):
		c.Fail(invalid("请选择有效的状态。"))
		return
	case utf8.RuneCountInString(comment) > 2000:
		c.Fail(invalid("内容最多 2000 字。"))
		return
	case to == "resolved" && comment == "":
		c.Fail(invalid("请填写处理结果。"))
		return
	}
	t, err := m.repo.Transition(c.Context(), c.User(), c.Session.Actor(), c.R.PathValue("id"), to, comment)
	if err != nil {
		c.Fail(err)
		return
	}
	c.OK(t)
}

func (m *Module) assign(c *httpx.Ctx) {
	raw := c.Object()
	ids := httpx.IDs(raw)
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			c.Fail(invalid("不能重复选择。"))
			return
		}
		seen[id] = true
	}
	if len(ids) == 0 || len(ids) > 200 {
		c.Fail(invalid("请选择工单。"))
		return
	}
	value, present := raw["assigneeId"]
	assigneeID, isString := value.(string)
	if !present || (value != nil && (!isString || assigneeID == "")) {
		c.Fail(invalid("请选择处理人。"))
		return
	}
	n, err := m.repo.Assign(c.Context(), c.User(), c.Session.Snap, c.Session.Actor(), ids, assigneeID)
	if err != nil {
		c.Fail(err)
		return
	}
	c.OK(map[string]int{"assignedCount": n})
}

// Assignee is an account that may be assigned tickets.
type Assignee struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Email          string `json:"email"`
	DepartmentID   string `json:"departmentId"`
	DepartmentName string `json:"departmentName"`
}

// assignees lists enabled accounts holding tickets:write, limited to the
// departments of the caller's assign scope (all of them for a global scope).
func (m *Module) assignees(c *httpx.Ctx) {
	snap, p := c.Session.Snap, c.User()
	items := []Assignee{}
	for _, a := range snap.Accounts {
		who, ok := snap.Principal(a.ID)
		if !ok || !who.Has(CapWrite) {
			continue
		}
		if a.ID != p.ID && !p.CanAccess(authz.Record{DepartmentID: a.DepartmentID}, CapAssign) {
			continue
		}
		dept, _ := snap.Department(a.DepartmentID)
		items = append(items, Assignee{ID: a.ID, Name: a.Name, Email: a.Email, DepartmentID: a.DepartmentID, DepartmentName: dept.Name})
	}
	c.OK(map[string]any{"items": items})
}
