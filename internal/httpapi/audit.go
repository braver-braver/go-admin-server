package httpapi

import (
	"net/http"

	"github.com/braver-braver/go-admin-server/internal/store"
)

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	sess := s.guard(w, r, "audit:read")
	if sess == nil {
		return
	}
	q := r.URL.Query()
	var actions []string
	for _, v := range q["action"] {
		if v != "" {
			actions = append(actions, v)
		}
	}
	list, err := s.store.ListAudit(r.Context(), sess.user.Filter("audit:read"), actions, store.Page{
		Page: positiveInt(q.Get("page"), 1), PageSize: pageSizeOf(q.Get("pageSize")),
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeData(w, http.StatusOK, list)
}
