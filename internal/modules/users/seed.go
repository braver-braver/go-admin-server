package users

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"
)

// SeedDemoUsers inserts n deterministic demo business users when the users
// table is empty, spread over the demo departments. Development only.
func (r *Repo) SeedDemoUsers(ctx context.Context, n int, createdBy string, departments []string) (int, error) {
	inserted := 0
	err := r.st.Tx(ctx, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users)`).Scan(&exists); err != nil || exists {
			return err
		}
		surnames := []struct{ zh, py string }{{"张", "zhang"}, {"王", "wang"}, {"李", "li"}, {"赵", "zhao"}, {"刘", "liu"},
			{"陈", "chen"}, {"杨", "yang"}, {"黄", "huang"}, {"吴", "wu"}, {"周", "zhou"}, {"徐", "xu"}, {"孙", "sun"}}
		given := []struct{ zh, py string }{{"伟", "wei"}, {"芳", "fang"}, {"娜", "na"}, {"敏", "min"}, {"静", "jing"},
			{"磊", "lei"}, {"洋", "yang"}, {"勇", "yong"}, {"艳", "yan"}, {"杰", "jie"}, {"涛", "tao"}, {"明", "ming"}}
		statuses := []string{"active", "active", "active", "inactive", "invited", "suspended"}
		roles := []string{"admin", "manager", "manager", "cashier", "cashier", "superadmin"}
		r := rand.New(rand.NewPCG(42, 2026))
		base := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
		rows := make([][]any, 0, n)
		for i := 0; i < n; i++ {
			sn, gn := surnames[r.IntN(len(surnames))], given[r.IntN(len(given))]
			username := fmt.Sprintf("%s.%s%d", sn.py, gn.py, i+1)
			created := base.Add(time.Duration(r.IntN(300*24)) * time.Hour)
			rows = append(rows, []any{
				fmt.Sprintf("usr-%04d", i+1), departments[i%len(departments)], createdBy, gn.zh, sn.zh, username,
				username + "@example.com", fmt.Sprintf("138%08d", r.IntN(100000000)),
				statuses[r.IntN(len(statuses))], roles[r.IntN(len(roles))], created, created.Add(time.Duration(r.IntN(30*24)) * time.Hour),
			})
		}
		count, err := tx.CopyFrom(ctx, pgx.Identifier{"users"}, []string{"id", "department_id", "created_by", "first_name", "last_name",
			"username", "email", "phone_number", "status", "role", "created_at", "updated_at"}, pgx.CopyFromRows(rows))
		inserted = int(count)
		return err
	})
	return inserted, err
}
