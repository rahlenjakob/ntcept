// Package ui serves the inspector, embedded in the binary so there is nothing to install.
package ui

import (
	"embed"
	"net/http"
)

//go:embed assets
var assets embed.FS

// Handler serves the inspector page at the root of the control plane.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := assets.ReadFile("assets/index.html")
		if err != nil {
			http.Error(w, "inspector missing from this build", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	})
}
