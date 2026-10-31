package httpapi

import (
	"fmt"
	"slices"
	"testing"
)

func ticketBody(title string) map[string]any {
	return map[string]any{"title": title, "description": "详细描述", "category": "fault", "priority": "high"}
}

// ticketRole creates a role over the ticket capabilities with the given scope
// and an enabled account holding it, and returns a signed-in client.
func ticketRole(t *testing.T, e *tenv, admin *client, code, scope, dept string, perms ...string) (*client, string) {
	t.Helper()
	role := admin.do("POST", "/system/roles", map[string]any{"name": code, "code": code, "enabled": true,
		"permissionIds": perms, "menuIds": []string{"tickets"}, "scope": scope, "departmentIds": []string{}})
	expect(t, role, 201, "")
	email := code + "@example.com"
	acct := admin.do("POST", "/system/accounts", map[string]any{"name": code, "email": email, "password": "Secret1234!",
		"enabled": true, "departmentId": dept, "roleIds": []string{role.dataMap()["id"].(string)}})
	expect(t, acct, 201, "")
	c := e.client()
	expect(t, c.loginWith(email, "Secret1234!"), 200, "")
	return c, acct.dataMap()["id"].(string)
}

func items(r *resp) []map[string]any {
	var out []map[string]any
	for _, it := range r.dataMap()["items"].([]any) {
		out = append(out, it.(map[string]any))
	}
	return out
}

func TestTicketListSummaryAndDetail(t *testing.T) {
	e := newTestEnv(t)
	admin := e.client().login("admin@example.com")
	expect(t, e.client().login("viewer@example.com").do("GET", "/tickets", nil), 403, "FORBIDDEN")

	r := admin.do("GET", "/tickets?pageSize=100", nil)
	expect(t, r, 200, "")
	if r.dataMap()["meta"].(map[string]any)["total"] != 36.0 {
		t.Fatalf("seeded tickets %v", r.dataMap()["meta"])
	}
	sum := admin.do("GET", "/tickets/summary", nil).dataMap()
	if sum["open"].(float64)+sum["inProgress"].(float64)+sum["resolved"].(float64)+sum["closed"].(float64) != 36 {
		t.Fatalf("summary %v", sum)
	}
	for _, it := range items(admin.do("GET", "/tickets?status=open&status=in_progress&priority=high&pageSize=100", nil)) {
		if (it["status"] != "open" && it["status"] != "in_progress") || it["priority"] != "high" {
			t.Fatalf("filter leaked %v", it)
		}
	}
	unassigned := items(admin.do("GET", "/tickets?assignee=unassigned&pageSize=100", nil))
	mine := items(admin.do("GET", "/tickets?assignee=me&pageSize=100", nil))
	if len(unassigned) == 0 || len(mine) == 0 || len(unassigned)+len(mine) != 36 {
		t.Fatalf("assignee filters %d + %d", len(unassigned), len(mine))
	}
	urgent := items(admin.do("GET", "/tickets?sortBy=priority&sortOrder=desc&pageSize=1", nil))
	if urgent[0]["priority"] != "urgent" {
		t.Fatalf("priority sort %v", urgent[0]["priority"])
	}
	if found := items(admin.do("GET", "/tickets?search=tk-000001", nil)); len(found) != 1 || found[0]["number"] != "TK-000001" {
		t.Fatalf("search by number %v", found)
	}
	expect(t, admin.do("GET", "/tickets?sortBy=drop%20table", nil), 200, "")

	d := admin.do("GET", "/tickets/tkt-0006", nil)
	expect(t, d, 200, "")
	if d.dataMap()["status"] != "closed" || len(d.dataMap()["events"].([]any)) < 4 || d.dataMap()["closedAt"] == nil {
		t.Fatalf("closed ticket detail %s", d.raw)
	}
	expect(t, admin.do("GET", "/tickets/missing", nil), 404, "TICKET_NOT_FOUND")
}

func TestTicketWorkflow(t *testing.T) {
	e := newTestEnv(t)
	admin := e.client().login("admin@example.com")

	bad := ticketBody("")
	bad["priority"] = "whenever"
	r := admin.do("POST", "/tickets", bad)
	expect(t, r, 422, "INVALID_TICKET_FIELDS")
	if r.body["error"].(map[string]any)["message"] != "请输入标题。" {
		t.Fatalf("title must be reported first: %s", r.raw)
	}
	created := admin.do("POST", "/tickets", ticketBody("  显示器闪烁  "))
	expect(t, created, 201, "")
	tk := created.dataMap()
	id := tk["id"].(string)
	if tk["title"] != "显示器闪烁" || tk["status"] != "open" || tk["number"] != "TK-000037" || tk["departmentId"] != "root" {
		t.Fatalf("created %v", tk)
	}

	expect(t, admin.do("POST", "/tickets/"+id+"/transition", map[string]any{"to": "resolved"}), 422, "INVALID_TICKET_FIELDS")
	expect(t, admin.do("POST", "/tickets/"+id+"/transition", map[string]any{"to": "in_progress"}), 200, "")
	res := admin.do("POST", "/tickets/"+id+"/transition", map[string]any{"to": "resolved", "comment": "已更换线缆"})
	expect(t, res, 200, "")
	if res.dataMap()["resolvedAt"] == nil {
		t.Fatal("resolvedAt not set")
	}
	expect(t, admin.do("POST", "/tickets/"+id+"/transition", map[string]any{"to": "open"}), 409, "INVALID_TICKET_TRANSITION")
	expect(t, admin.do("POST", "/tickets/"+id+"/transition", map[string]any{"to": "closed"}), 200, "")
	expect(t, admin.do("PUT", "/tickets/"+id, ticketBody("改标题")), 409, "TICKET_CLOSED")
	expect(t, admin.do("POST", "/tickets/"+id+"/comments", map[string]any{"body": "还在吗"}), 409, "TICKET_CLOSED")
	expect(t, admin.do("POST", "/tickets/assign", map[string]any{"ids": []string{id}, "assigneeId": "admin"}), 409, "TICKET_CLOSED")
	reopened := admin.do("POST", "/tickets/"+id+"/transition", map[string]any{"to": "open"})
	expect(t, reopened, 200, "")
	if reopened.dataMap()["resolvedAt"] != nil || reopened.dataMap()["closedAt"] != nil {
		t.Fatalf("reopening must clear timestamps: %s", reopened.raw)
	}
	expect(t, admin.do("POST", "/tickets/"+id+"/comments", map[string]any{"body": " "}), 422, "INVALID_TICKET_FIELDS")
	expect(t, admin.do("POST", "/tickets/"+id+"/comments", map[string]any{"body": "复发了"}), 201, "")
	upd := ticketBody("显示器又闪烁")
	upd["priority"] = "urgent"
	expect(t, admin.do("PUT", "/tickets/"+id, upd), 200, "")

	var kinds []string
	for _, ev := range admin.do("GET", "/tickets/"+id, nil).dataMap()["events"].([]any) {
		kinds = append(kinds, ev.(map[string]any)["kind"].(string))
	}
	want := []string{"created", "status_changed", "status_changed", "status_changed", "status_changed", "comment", "updated"}
	if !slices.Equal(kinds, want) {
		t.Fatalf("timeline %v", kinds)
	}
	audit := items(admin.do("GET", "/audit-logs?action=ticket.status_changed&action=ticket.created&pageSize=100", nil))
	if len(audit) != 5 {
		t.Fatalf("expected 1 creation and 4 transitions audited, got %d", len(audit))
	}
}

func TestTicketDepartmentScope(t *testing.T) {
	e := newTestEnv(t)
	admin := e.client().login("admin@example.com")
	agent, _ := ticketRole(t, e, admin, "ops_agent", "department", "operations", "tickets:read", "tickets:write")

	list := items(agent.do("GET", "/tickets?pageSize=100", nil))
	if len(list) != 9 {
		t.Fatalf("operations tickets %d", len(list))
	}
	for _, it := range list {
		if it["departmentId"] != "operations" {
			t.Fatalf("out of scope ticket listed %v", it)
		}
	}
	if s := agent.do("GET", "/tickets/summary", nil).dataMap(); s["open"].(float64)+s["inProgress"].(float64)+s["resolved"].(float64)+s["closed"].(float64) != 9 {
		t.Fatalf("summary must be scoped %v", s)
	}
	// tkt-0002 belongs to support: not revealed, not writable.
	expect(t, agent.do("GET", "/tickets/tkt-0002", nil), 404, "TICKET_NOT_FOUND")
	expect(t, agent.do("POST", "/tickets/tkt-0002/comments", map[string]any{"body": "x"}), 404, "TICKET_NOT_FOUND")
	expect(t, agent.do("POST", "/tickets/tkt-0001/comments", map[string]any{"body": "跟进中"}), 201, "")

	elsewhere := ticketBody("跨部门")
	elsewhere["departmentId"] = "sales"
	expect(t, agent.do("POST", "/tickets", elsewhere), 403, "DATA_SCOPE_DENIED")
	own := agent.do("POST", "/tickets", ticketBody("本部门"))
	expect(t, own, 201, "")
	if own.dataMap()["departmentId"] != "operations" {
		t.Fatalf("default department %v", own.dataMap()["departmentId"])
	}
	withAssignee := ticketBody("直接指派")
	withAssignee["assigneeId"] = "admin"
	expect(t, agent.do("POST", "/tickets", withAssignee), 403, "FORBIDDEN")
	expect(t, agent.do("POST", "/tickets/assign", map[string]any{"ids": []string{"tkt-0001"}, "assigneeId": nil}), 403, "FORBIDDEN")

	// A department holding tickets cannot be deleted.
	dept := admin.do("POST", "/system/departments", map[string]any{"name": "临时组", "code": "temp_team", "parentId": "root", "enabled": true})
	deptID := dept.dataMap()["id"].(string)
	inDept := ticketBody("临时组工单")
	inDept["departmentId"] = deptID
	expect(t, admin.do("POST", "/tickets", inDept), 201, "")
	expect(t, admin.do("DELETE", "/system/departments/"+deptID, nil), 409, "SYSTEM_RULE")
}

func TestTicketAssignment(t *testing.T) {
	e := newTestEnv(t)
	admin := e.client().login("admin@example.com")
	worker, workerID := ticketRole(t, e, admin, "field_worker", "self", "operations", "tickets:read", "tickets:write")
	dispatcher, _ := ticketRole(t, e, admin, "ops_dispatch", "department", "operations", "tickets:read", "tickets:assign")

	if n := len(items(worker.do("GET", "/tickets", nil))); n != 0 {
		t.Fatalf("self-scoped worker sees %d tickets before assignment", n)
	}
	people := items(dispatcher.do("GET", "/tickets/assignees", nil))
	names := []string{}
	for _, p := range people {
		names = append(names, p["name"].(string))
	}
	if !slices.Contains(names, "field_worker") || slices.Contains(names, "演示只读用户") {
		t.Fatalf("assignees %v", names)
	}

	// tkt-0001 is in operations (dispatcher's scope); tkt-0003 is in sales.
	expect(t, dispatcher.do("POST", "/tickets/assign", map[string]any{"ids": []string{"tkt-0001", "tkt-0003"}, "assigneeId": workerID}),
		403, "DATA_SCOPE_DENIED")
	if n := len(items(worker.do("GET", "/tickets", nil))); n != 0 {
		t.Fatal("a rejected batch must change nothing")
	}
	expect(t, dispatcher.do("POST", "/tickets/assign", map[string]any{"ids": []string{"tkt-0001"}, "assigneeId": "demo-viewer"}),
		422, "INVALID_ASSIGNEE")
	r := dispatcher.do("POST", "/tickets/assign", map[string]any{"ids": []string{"tkt-0001", "tkt-0005"}, "assigneeId": workerID})
	expect(t, r, 200, "")
	if r.dataMap()["assignedCount"] != 2.0 {
		t.Fatalf("assigned %s", r.raw)
	}

	// Assignment is what gives a self-scoped worker the ticket.
	mine := items(worker.do("GET", "/tickets?assignee=me", nil))
	// tkt-0005 is resolved, so only tkt-0001 is still waiting on the worker.
	if len(mine) != 2 || worker.do("GET", "/tickets/summary", nil).dataMap()["assignedToMe"].(float64) != 1 {
		t.Fatalf("worker tickets %v", mine)
	}
	expect(t, worker.do("POST", "/tickets/tkt-0001/transition", map[string]any{"to": "in_progress"}), 200, "")
	expect(t, dispatcher.do("POST", "/tickets/tkt-0001/comments", map[string]any{"body": "x"}), 403, "FORBIDDEN")

	expect(t, dispatcher.do("POST", "/tickets/assign", map[string]any{"ids": []string{"tkt-0001"}, "assigneeId": nil}), 200, "")
	expect(t, worker.do("GET", "/tickets/tkt-0001", nil), 404, "TICKET_NOT_FOUND")

	var assigned []string
	for _, ev := range admin.do("GET", "/tickets/tkt-0001", nil).dataMap()["events"].([]any) {
		if m := ev.(map[string]any); m["kind"] == "assigned" {
			assigned = append(assigned, fmt.Sprint(m["assigneeName"]))
		}
	}
	if !slices.Equal(assigned[len(assigned)-2:], []string{"field_worker", "<nil>"}) {
		t.Fatalf("assignment timeline %v", assigned)
	}
	expect(t, dispatcher.do("POST", "/tickets/assign", map[string]any{"ids": []string{"tkt-0001", "tkt-0001"}, "assigneeId": nil}),
		422, "INVALID_TICKET_FIELDS")
}
