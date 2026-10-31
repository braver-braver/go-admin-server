package main

import (
	"github.com/braver-braver/go-admin-server/internal/httpx"
	"github.com/braver-braver/go-admin-server/internal/modules/users"
	"github.com/braver-braver/go-admin-server/internal/store"
)

// modules lists the business modules this server runs. Adding a module is one
// line here; see docs/modules.md.
func modules(st *store.Store, uploadDir string) []httpx.Module {
	return []httpx.Module{
		users.New(st, uploadDir),
	}
}
