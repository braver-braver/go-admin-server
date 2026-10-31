// Package store is the PostgreSQL storage layer.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"testing/fstest"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/braver-braver/go-admin-server/internal/authz"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store wraps the connection pool and a cache of the system configuration.
type Store struct {
	pool *pgxpool.Pool
	// departmentRefs report whether a module still has records in a
	// department, which blocks deleting it.
	departmentRefs []DepartmentRef
	// catalog is what the code provides; set by InstallCatalog.
	catalog authz.Catalog

	mu       sync.Mutex
	cached   *authz.Snapshot
	revision int64
}

func Open(ctx context.Context, url string) (*Store, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

// Ping checks the database for readiness probes.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Migrate applies all pending migrations of the core and of the given module
// migration directories. Versions must be unique across all of them; modules
// use timestamp versions. Out-of-order versions are applied, so a module added
// later with an older timestamp still installs.
func (s *Store) Migrate(ctx context.Context, modules ...fs.FS) error {
	merged := fstest.MapFS{}
	for _, src := range append([]fs.FS{mustSub(migrations, "migrations")}, modules...) {
		if src == nil {
			continue
		}
		err := fs.WalkDir(src, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".sql") {
				return err
			}
			name := filepath.Base(path)
			if _, dup := merged[name]; dup {
				return fmt.Errorf("duplicate migration %s", name)
			}
			data, err := fs.ReadFile(src, path)
			merged[name] = &fstest.MapFile{Data: data}
			return err
		})
		if err != nil {
			return err
		}
	}
	db := stdlib.OpenDBFromPool(s.pool)
	defer db.Close()
	return migrate(ctx, db, merged)
}

func migrate(ctx context.Context, db *sql.DB, files fs.FS) error {
	provider, err := goose.NewProvider(goose.DialectPostgres, db, files, goose.WithAllowOutofOrder(true))
	if err != nil {
		return err
	}
	_, err = provider.Up(ctx)
	return err
}

// Tx runs fn in a transaction; it commits when fn returns nil.
func (s *Store) Tx(ctx context.Context, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, fn)
}

func (s *Store) tx(ctx context.Context, fn func(pgx.Tx) error) error { return s.Tx(ctx, fn) }

// DB is the connection pool, for queries outside a transaction.
func (s *Store) DB() Querier { return s.pool }

// DepartmentRef reports whether a module still has records in a department.
type DepartmentRef func(ctx context.Context, q Querier, departmentID string) (bool, error)

// AddDepartmentReference registers a check that blocks deleting departments
// still in use. Call it during startup, before serving.
func (s *Store) AddDepartmentReference(ref DepartmentRef) {
	s.departmentRefs = append(s.departmentRefs, ref)
}

// Querier is satisfied by the pool and by transactions.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// IsUniqueViolation reports a unique-constraint violation.
func IsUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}
