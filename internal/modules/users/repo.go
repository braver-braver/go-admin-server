package users

import "github.com/braver-braver/go-admin-server/internal/store"

// Repo is the module's storage, built on the shared store toolkit.
type Repo struct{ st *store.Store }
