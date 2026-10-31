// Command server runs the go-admin-server API.
//
//	server            migrate (unless MIGRATE_ON_START=false), bootstrap, serve
//	server migrate    apply database migrations and exit
//	server seed-demo  load the demo configuration and users (development only)
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/braver-braver/go-admin-server/internal/auth"
	"github.com/braver-braver/go-admin-server/internal/authz"
	"github.com/braver-braver/go-admin-server/internal/httpapi"
	"github.com/braver-braver/go-admin-server/internal/httpx"
	"github.com/braver-braver/go-admin-server/internal/store"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log, os.Args[1:]); err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v, err := strconv.ParseBool(env(key, ""))
	if err != nil {
		return fallback
	}
	return v
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	d, err := time.ParseDuration(env(key, fallback.String()))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

func run(log *slog.Logger, args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dbURL := env("DATABASE_URL", "")
	if dbURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	st, err := store.Open(ctx, dbURL)
	if err != nil {
		return err
	}
	defer st.Close()

	mods := modules(st, env("UPLOAD_DIR", "./data/uploads"))
	catalog := httpapi.Catalog(mods)
	command := "serve"
	if len(args) > 0 {
		command = args[0]
	}
	switch command {
	case "migrate":
		return httpapi.Install(ctx, st, log, mods)
	case "seed-demo":
		if err := httpapi.Install(ctx, st, log, mods); err != nil {
			return err
		}
		return seedDemo(ctx, log, st, catalog, mods)
	case "serve":
	default:
		return fmt.Errorf("unknown command %q", command)
	}

	if envBool("MIGRATE_ON_START", true) {
		if err := httpapi.Install(ctx, st, log, mods); err != nil {
			return fmt.Errorf("install: %w", err)
		}
	} else if _, err := st.InstallCatalog(ctx, catalog); err != nil {
		return err
	}
	if err := bootstrap(ctx, log, st, catalog); err != nil {
		return err
	}
	ttl, err := envDuration("SESSION_TTL", 8*time.Hour)
	if err != nil {
		return err
	}
	loginRate, err := envDuration("LOGIN_RATE", 6*time.Second)
	if err != nil {
		return err
	}
	burst, _ := strconv.Atoi(env("LOGIN_BURST", "10"))
	var origins []string
	for _, o := range strings.Split(env("ALLOWED_ORIGINS", ""), ",") {
		if o = strings.TrimSpace(o); o != "" {
			origins = append(origins, o)
		}
	}
	api := httpapi.New(httpapi.Config{
		CookieName:        env("COOKIE_NAME", "session"),
		CookieSecure:      envBool("COOKIE_SECURE", true),
		SessionTTL:        ttl,
		AllowedOrigins:    origins,
		TrustProxyHeaders: envBool("TRUST_PROXY_HEADERS", false),
		PasswordParams:    auth.DefaultParams,
		LoginRate:         loginRate,
		LoginBurst:        burst,
	}, st, log, mods...)

	go purgeSessions(ctx, log, st)

	srv := &http.Server{
		Addr:              env("LISTEN_ADDR", ":8080"),
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", srv.Addr)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	log.Info("shutting down")
	return srv.Shutdown(shutdown)
}

// bootstrap creates the protected recovery administrator on an empty database.
func bootstrap(ctx context.Context, log *slog.Logger, st *store.Store, catalog authz.Catalog) error {
	email, password := env("BOOTSTRAP_ADMIN_EMAIL", ""), env("BOOTSTRAP_ADMIN_PASSWORD", "")
	if email == "" || password == "" {
		snap, err := st.Snapshot(ctx)
		if err != nil {
			return err
		}
		if len(snap.Accounts) == 0 {
			log.Warn("no accounts: set BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD to create the administrator")
		}
		return nil
	}
	if len(password) < 12 {
		return errors.New("BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters")
	}
	hash, err := auth.HashPassword(password, auth.DefaultParams)
	if err != nil {
		return err
	}
	snap := authz.Bootstrap(catalog, env("BOOTSTRAP_ADMIN_NAME", "系统管理员"), email)
	wrote, err := st.Bootstrap(ctx, snap, map[string]string{authz.AdminAccountID: hash})
	if wrote {
		log.Info("created bootstrap administrator", "email", strings.ToLower(email))
	}
	return err
}

func seedDemo(ctx context.Context, log *slog.Logger, st *store.Store, catalog authz.Catalog, mods []httpx.Module) error {
	hash, err := auth.HashPassword("Demo1234!", auth.DefaultParams)
	if err != nil {
		return err
	}
	snap := authz.Demo(catalog)
	passwords := map[string]string{}
	for _, a := range snap.Accounts {
		passwords[a.ID] = hash
	}
	wrote, err := st.Bootstrap(ctx, snap, passwords)
	if err != nil {
		return err
	}
	if !wrote {
		return errors.New("database already has accounts; seed-demo only runs on an empty database")
	}
	for _, m := range mods {
		if seeder, ok := m.(httpx.DemoSeeder); ok {
			if err := seeder.SeedDemo(ctx); err != nil {
				return fmt.Errorf("seed %s: %w", m.Name(), err)
			}
		}
	}
	log.Info("seeded demo data", "accounts", len(snap.Accounts), "password", "Demo1234!")
	return nil
}

func purgeSessions(ctx context.Context, log *slog.Logger, st *store.Store) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := st.PurgeExpiredSessions(ctx); err != nil {
				log.Warn("purge sessions", "error", err)
			} else if n > 0 {
				log.Info("purged expired sessions", "count", n)
			}
		}
	}
}
