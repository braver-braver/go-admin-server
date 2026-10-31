// gateway serves the frontend build with SPA fallback and proxies /api to the
// backend, the same-origin layout the frontend docs prescribe.
package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
)

func main() {
	dist, backend, addr := os.Args[1], os.Args[2], os.Args[3]
	target, _ := url.Parse(backend)
	proxy := httputil.NewSingleHostReverseProxy(target)
	files := http.FileServer(http.Dir(dist))
	http.Handle("/api/", proxy)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(filepath.Join(dist, filepath.Clean(r.URL.Path))); err != nil || r.URL.Path == "/" {
			http.ServeFile(w, r, filepath.Join(dist, "index.html"))
			return
		}
		files.ServeHTTP(w, r)
	})
	panic(http.ListenAndServe(addr, nil))
}
