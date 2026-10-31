package store

import (
	"context"
	"encoding/json"
	"io/fs"
	"reflect"

	"github.com/jackc/pgx/v5"

	"github.com/braver-braver/go-admin-server/internal/authz"
)

func mustSub(f fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

// Actor identifies who performs a write, for audit records.
type Actor struct {
	ID           string
	Name         string
	Email        string
	DepartmentID string
	IP           string
}

// Snapshot returns the current system configuration. The result is shared and
// must not be modified; authz.Apply clones before changing anything.
func (s *Store) Snapshot(ctx context.Context) (*authz.Snapshot, error) {
	var revision int64
	if err := s.pool.QueryRow(ctx, `SELECT revision FROM system_state`).Scan(&revision); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.cached != nil && s.revision == revision {
		snap := s.cached
		s.mu.Unlock()
		return snap, nil
	}
	s.mu.Unlock()
	var snap *authz.Snapshot
	err := s.tx(ctx, func(tx pgx.Tx) error {
		// Read the revision and the tables from one consistent view.
		if _, err := tx.Exec(ctx, `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY`); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT revision FROM system_state`).Scan(&revision); err != nil {
			return err
		}
		var err error
		snap, err = s.load(ctx, tx)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.cached, s.revision = snap, revision
	s.mu.Unlock()
	return snap, nil
}

func (s *Store) load(ctx context.Context, q Querier) (*authz.Snapshot, error) {
	snap := &authz.Snapshot{Catalog: s.catalog, CredentialVersions: map[string]int{}}
	rows, err := q.Query(ctx, `SELECT id, name, code, parent_id, enabled, protected FROM departments ORDER BY position`)
	if err != nil {
		return nil, err
	}
	snap.Departments, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (authz.Department, error) {
		d := authz.Department{Resource: authz.ResDepartments}
		return d, r.Scan(&d.ID, &d.Name, &d.Code, &d.ParentID, &d.Enabled, &d.Protected)
	})
	if err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT id, name, code, description, protected FROM permissions ORDER BY position`)
	if err != nil {
		return nil, err
	}
	snap.Permissions, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (authz.Permission, error) {
		p := authz.Permission{Resource: authz.ResPermissions}
		return p, r.Scan(&p.ID, &p.Name, &p.Code, &p.Description, &p.Protected)
	})
	if err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT id, name, parent_id, kind, route_id, enabled, visible, sort_order, protected FROM menus ORDER BY position`)
	if err != nil {
		return nil, err
	}
	snap.Menus, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (authz.Menu, error) {
		m := authz.Menu{Resource: authz.ResMenus}
		return m, r.Scan(&m.ID, &m.Name, &m.ParentID, &m.Kind, &m.RouteID, &m.Enabled, &m.Visible, &m.Order, &m.Protected)
	})
	if err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT id, name, code, enabled, permission_ids, menu_ids, scope, department_ids, protected FROM roles ORDER BY position`)
	if err != nil {
		return nil, err
	}
	snap.Roles, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (authz.Role, error) {
		x := authz.Role{Resource: authz.ResRoles}
		return x, r.Scan(&x.ID, &x.Name, &x.Code, &x.Enabled, &x.PermissionIDs, &x.MenuIDs, &x.Scope, &x.DepartmentIDs, &x.Protected)
	})
	if err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT id, name, email, enabled, department_id, role_ids, protected, credential_version FROM accounts ORDER BY position`)
	if err != nil {
		return nil, err
	}
	snap.Accounts, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (authz.Account, error) {
		a := authz.Account{Resource: authz.ResAccounts}
		var version int
		if err := r.Scan(&a.ID, &a.Name, &a.Email, &a.Enabled, &a.DepartmentID, &a.RoleIDs, &a.Protected, &version); err != nil {
			return a, err
		}
		snap.CredentialVersions[a.ID] = version
		return a, nil
	})
	if err != nil {
		return nil, err
	}
	return snap, nil
}

// PasswordHash returns an account's password hash and credential version.
func (s *Store) PasswordHash(ctx context.Context, accountID string) (string, int, error) {
	var hash string
	var version int
	err := s.pool.QueryRow(ctx, `SELECT password_hash, credential_version FROM accounts WHERE id = $1`, accountID).Scan(&hash, &version)
	return hash, version, err
}

// HashFunc hashes a new password.
type HashFunc func(password string) (string, error)

// ApplySystemChange validates and persists one system-management write with
// its audit record. Writes are serialized by a transaction-scoped advisory
// lock and always validated against the configuration read under that lock.
func (s *Store) ApplySystemChange(ctx context.Context, c authz.Change, actor Actor, hash HashFunc) (any, error) {
	var record any
	err := s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('go-admin-server:system'))`); err != nil {
			return err
		}
		before, err := s.load(ctx, tx)
		if err != nil {
			return err
		}
		if c.Resource == authz.ResDepartments && c.Remove {
			for _, inUse := range s.departmentRefs {
				used, err := inUse(ctx, tx, c.ID)
				if err != nil {
					return err
				}
				c.DepartmentInUse = c.DepartmentInUse || used
			}
		}
		res, rerr := authz.Apply(before, c)
		if rerr != nil {
			return rerr
		}
		passwords := map[string]string{}
		if res.Password != nil {
			h, err := hash(res.Password.Password)
			if err != nil {
				return err
			}
			passwords[res.Password.AccountID] = h
		}
		if err := saveDiff(ctx, tx, before, res.After, passwords); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE system_state SET revision = revision + 1`); err != nil {
			return err
		}
		id := c.ID
		if id == "" {
			id = c.NewID
		}
		method := map[bool]string{true: "DELETE", false: "PUT"}[c.Remove]
		if c.ID == "" {
			method = "POST"
		}
		record = res.Record
		return Audit(ctx, tx, actor, "system.changed", c.Resource+"/"+id, method+" "+c.Resource)
	})
	if err != nil {
		return nil, err
	}
	s.invalidate()
	return record, nil
}

func (s *Store) invalidate() {
	s.mu.Lock()
	s.cached = nil
	s.mu.Unlock()
}

// InstallCatalog records what the code provides and adds what the stored
// configuration lacks (see authz.SyncCatalog). Run it on every start, after
// migrating; it reports whether anything was added.
func (s *Store) InstallCatalog(ctx context.Context, cat authz.Catalog) (bool, error) {
	s.mu.Lock()
	s.catalog = cat
	s.cached = nil
	s.mu.Unlock()
	changed := false
	err := s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('go-admin-server:system'))`); err != nil {
			return err
		}
		before, err := s.load(ctx, tx)
		if err != nil || len(before.Accounts) == 0 {
			return err // nothing installed yet: Bootstrap writes the catalog
		}
		var after *authz.Snapshot
		if after, changed = authz.SyncCatalog(before, cat); !changed {
			return nil
		}
		if err := saveDiff(ctx, tx, before, after, nil); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE system_state SET revision = revision + 1`)
		return err
	})
	if changed {
		s.invalidate()
	}
	return changed, err
}

// Bootstrap writes an initial configuration when there are no accounts yet.
// passwords maps account ids to password hashes. It reports whether it wrote.
func (s *Store) Bootstrap(ctx context.Context, snap *authz.Snapshot, passwords map[string]string) (bool, error) {
	wrote := false
	err := s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('go-admin-server:system'))`); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM accounts)`).Scan(&exists); err != nil || exists {
			return err
		}
		empty := &authz.Snapshot{CredentialVersions: map[string]int{}}
		if err := saveDiff(ctx, tx, empty, snap, passwords); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE system_state SET revision = revision + 1`)
		wrote = err == nil
		return err
	})
	if wrote {
		s.invalidate()
	}
	return wrote, err
}

// changes returns the records of after that are new or differ from before, and
// the ids of before that are gone.
func changes[T any](before, after []T, id func(T) string) (upserts []T, deletes []string) {
	old := map[string]T{}
	for _, r := range before {
		old[id(r)] = r
	}
	seen := map[string]bool{}
	for _, r := range after {
		seen[id(r)] = true
		if prev, ok := old[id(r)]; !ok || !reflect.DeepEqual(normalize(prev), normalize(r)) {
			upserts = append(upserts, r)
		}
	}
	for _, r := range before {
		if !seen[id(r)] {
			deletes = append(deletes, id(r))
		}
	}
	return upserts, deletes
}

// normalize makes nil and empty slices compare equal.
func normalize(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	if m, ok := out.(map[string]any); ok {
		for k, val := range m {
			if val == nil {
				m[k] = []any{}
			}
		}
	}
	return out
}

func nonNil(ids []string) []string {
	if ids == nil {
		return []string{}
	}
	return ids
}

// saveDiff writes the difference between two configurations. Deletions run
// in dependency order after upserts; references are enforced by the kernel.
func saveDiff(ctx context.Context, tx pgx.Tx, before, after *authz.Snapshot, passwords map[string]string) error {
	exec := func(sql string, args ...any) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}
	deps, depDel := changes(before.Departments, after.Departments, func(d authz.Department) string { return d.ID })
	for _, d := range deps {
		if err := exec(`INSERT INTO departments (id, name, code, parent_id, enabled, protected) VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (id) DO UPDATE SET name=$2, code=$3, parent_id=$4, enabled=$5, protected=$6`,
			d.ID, d.Name, d.Code, d.ParentID, d.Enabled, d.Protected); err != nil {
			return err
		}
	}
	perms, permDel := changes(before.Permissions, after.Permissions, func(p authz.Permission) string { return p.ID })
	for _, p := range perms {
		if err := exec(`INSERT INTO permissions (id, name, code, description, protected) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (id) DO UPDATE SET name=$2, code=$3, description=$4, protected=$5`,
			p.ID, p.Name, p.Code, p.Description, p.Protected); err != nil {
			return err
		}
	}
	menus, menuDel := changes(before.Menus, after.Menus, func(m authz.Menu) string { return m.ID })
	for _, m := range menus {
		if err := exec(`INSERT INTO menus (id, name, parent_id, kind, route_id, enabled, visible, sort_order, protected)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (id) DO UPDATE SET name=$2, parent_id=$3, kind=$4, route_id=$5, enabled=$6, visible=$7, sort_order=$8, protected=$9`,
			m.ID, m.Name, m.ParentID, m.Kind, m.RouteID, m.Enabled, m.Visible, m.Order, m.Protected); err != nil {
			return err
		}
	}
	roles, roleDel := changes(before.Roles, after.Roles, func(r authz.Role) string { return r.ID })
	for _, r := range roles {
		if err := exec(`INSERT INTO roles (id, name, code, enabled, permission_ids, menu_ids, scope, department_ids, protected)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (id) DO UPDATE SET name=$2, code=$3, enabled=$4, permission_ids=$5, menu_ids=$6, scope=$7, department_ids=$8, protected=$9`,
			r.ID, r.Name, r.Code, r.Enabled, nonNil(r.PermissionIDs), nonNil(r.MenuIDs), r.Scope, nonNil(r.DepartmentIDs), r.Protected); err != nil {
			return err
		}
	}
	accounts, accDel := changes(before.Accounts, after.Accounts, func(a authz.Account) string { return a.ID })
	for _, a := range accounts {
		if err := exec(`INSERT INTO accounts (id, name, email, enabled, department_id, role_ids, protected, password_hash, credential_version)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (id) DO UPDATE SET name=$2, email=$3, enabled=$4, department_id=$5, role_ids=$6, protected=$7`,
			a.ID, a.Name, a.Email, a.Enabled, a.DepartmentID, nonNil(a.RoleIDs), a.Protected, passwords[a.ID],
			after.CredentialVersions[a.ID]); err != nil {
			return err
		}
	}
	for id, version := range after.CredentialVersions {
		if prev, ok := before.CredentialVersions[id]; ok && prev != version {
			if err := exec(`UPDATE accounts SET credential_version = $2 WHERE id = $1`, id, version); err != nil {
				return err
			}
			// Revoked sessions would fail validation anyway; drop them now.
			if err := exec(`DELETE FROM sessions WHERE account_id = $1 AND credential_version <> $2`, id, version); err != nil {
				return err
			}
		}
	}
	for id, hash := range passwords {
		if err := exec(`UPDATE accounts SET password_hash = $2 WHERE id = $1`, id, hash); err != nil {
			return err
		}
	}
	for _, del := range []struct {
		table string
		ids   []string
	}{{"accounts", accDel}, {"roles", roleDel}, {"menus", menuDel}, {"permissions", permDel}, {"departments", depDel}} {
		if len(del.ids) > 0 {
			if err := exec(`DELETE FROM `+del.table+` WHERE id = ANY($1)`, del.ids); err != nil {
				return err
			}
		}
	}
	return nil
}
