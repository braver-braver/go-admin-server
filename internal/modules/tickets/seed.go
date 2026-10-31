package tickets

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/braver-braver/go-admin-server/internal/authz"
)

// SeedDemo adds deterministic demo tickets, with timelines, when there are
// none. Development only.
func (m *Module) SeedDemo(ctx context.Context) error {
	return m.repo.st.Tx(ctx, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tickets)`).Scan(&exists); err != nil || exists {
			return err
		}
		titles := []struct{ title, category string }{
			{"打印机无法连接网络", "fault"}, {"申请开通 VPN 账号", "request"}, {"报销系统登录报错", "fault"},
			{"咨询年假剩余天数", "consultation"}, {"会议室投影仪不显示", "fault"}, {"客户反馈发票抬头错误", "complaint"},
			{"新员工电脑配置", "request"}, {"邮箱容量已满", "fault"}, {"咨询差旅标准", "consultation"},
			{"门禁卡失效", "fault"}, {"申请增加共享盘权限", "request"}, {"客户投诉配送延迟", "complaint"},
		}
		departments := []string{"operations", "support", "sales", authz.RootDepartmentID}
		statusesCycle := []string{"open", "open", "in_progress", "in_progress", "resolved", "closed"}
		prioritiesCycle := []string{"medium", "low", "high", "medium", "urgent", "low", "high"}
		r := rand.New(rand.NewPCG(7, 2026))
		base := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
		for i := 0; i < 36; i++ {
			pick := titles[i%len(titles)]
			status := statusesCycle[i%len(statusesCycle)]
			created := base.Add(time.Duration(i*20+r.IntN(12)) * time.Hour)
			updated := created.Add(time.Duration(1+r.IntN(48)) * time.Hour)
			id := fmt.Sprintf("tkt-%04d", i+1)
			var assigneeID, assigneeName *string
			if status != "open" || i%4 == 0 {
				aid, aname := authz.AdminAccountID, "演示管理员"
				assigneeID, assigneeName = &aid, &aname
			}
			var resolvedAt, closedAt *time.Time
			if status == "resolved" || status == "closed" {
				resolvedAt = &updated
			}
			if status == "closed" {
				c := updated.Add(2 * time.Hour)
				closedAt, updated = &c, c
			}
			if _, err := tx.Exec(ctx, `INSERT INTO tickets (id, number, title, description, category, priority, status, department_id,
					created_by, created_by_name, assignee_id, assignee_name, created_at, updated_at, resolved_at, closed_at)
				VALUES ($1, 'TK-' || lpad(nextval('ticket_number_seq')::text, 6, '0'), $2, $3, $4, $5, $6, $7,
					$8, '演示管理员', $9, $10, $11, $12, $13, $14)`,
				id, pick.title, "问题描述："+pick.title+"，请尽快处理。", pick.category, prioritiesCycle[i%len(prioritiesCycle)],
				status, departments[i%len(departments)], authz.AdminAccountID, assigneeID, assigneeName,
				created, updated, resolvedAt, closedAt); err != nil {
				return err
			}
			events := [][]any{{"created", "", nil, nil, nil, created}}
			if assigneeName != nil {
				events = append(events, []any{"assigned", "", nil, nil, *assigneeName, created.Add(10 * time.Minute)})
			}
			if status != "open" {
				events = append(events, []any{"status_changed", "", "open", "in_progress", nil, created.Add(time.Hour)})
			}
			if i%3 == 0 {
				events = append(events, []any{"comment", "已联系提交人确认情况。", nil, nil, nil, created.Add(90 * time.Minute)})
			}
			if status == "resolved" || status == "closed" {
				events = append(events, []any{"status_changed", "已处理完成，请确认。", "in_progress", "resolved", nil, *resolvedAt})
			}
			if status == "closed" {
				events = append(events, []any{"status_changed", "", "resolved", "closed", nil, *closedAt})
			}
			for _, e := range events {
				if _, err := tx.Exec(ctx, `INSERT INTO ticket_events (ticket_id, kind, actor_id, actor_name, body, from_status, to_status, assignee_name, created_at)
					VALUES ($1, $2, $3, '演示管理员', $4, $5, $6, $7, $8)`,
					id, e[0], authz.AdminAccountID, e[1], e[2], e[3], e[4], e[5]); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
