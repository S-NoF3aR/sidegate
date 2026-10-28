// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"html/template"
	"io/fs"
	"net/http"
	"slices"
	"strings"

	"sidegate/internal/session"
)

//go:embed web
var webFS embed.FS

// parseTemplates parses the page templates. Assets are always referenced
// via the portal origin, because error pages are also served on app hosts.
func parseTemplates(portalURL, sourceURL string) (*template.Template, error) {
	return template.New("").Funcs(template.FuncMap{
		"portal":  func() string { return portalURL },
		"version": func() string { return Version },
		"source":  func() string { return sourceURL },
		"isURL": func(s string) bool {
			return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "/")
		},
		"initial": func(s string) string {
			for _, r := range s {
				return strings.ToUpper(string(r))
			}
			return "?"
		},
		"mb": func(n int64) string { return fmt.Sprintf("%.1f MB", float64(n)/(1<<20)) },
		"hue": func(s string) uint32 {
			h := fnv.New32a()
			h.Write([]byte(s))
			return h.Sum32() % 12
		},
	}).ParseFS(webFS, "web/*.html")
}

func (s *Server) portalMux() http.Handler {
	static, _ := fs.Sub(webFS, "web/static")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handlePortal)
	mux.HandleFunc("GET /oauth2/start", s.handleStart)
	mux.HandleFunc("GET /oauth2/callback", s.handleCallback)
	mux.HandleFunc("GET /oauth2/logout", s.handleLogoutPage)
	mux.HandleFunc("POST /oauth2/logout", s.handleLogout)
	mux.HandleFunc("GET /oauth2/signed-out", s.handleSignedOut)
	mux.HandleFunc("GET /api/me", s.handleMe)
	mux.HandleFunc("GET /cli/login", s.handleCLILoginPage)
	mux.HandleFunc("POST /cli/login", s.handleCLILogin)
	mux.HandleFunc("POST /cli/token", s.handleCLIToken)
	mux.HandleFunc("POST /cli/logout", s.handleCLILogout)
	mux.HandleFunc("GET /cli", s.handleCLIPage)
	mux.HandleFunc("GET /cli/download/{file}", s.handleCLIDownload)
	mux.HandleFunc("GET /cli/install.sh", s.handleInstallScript)
	mux.HandleFunc("GET /cli/install.ps1", s.handleInstallScript)
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Write(s.jwt.jwks)
	})
	s.adminRoutes(mux)
	s.apiRoutes(mux)
	for _, e := range s.extensions {
		if rp, ok := e.(RouteProvider); ok {
			rp.Routes(mux)
		}
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", noListing(http.FileServerFS(static))))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.renderError(w, r, http.StatusNotFound, "Not found", "This page does not exist.")
	})
	return securityHeaders(mux)
}

// noListing serves files only; directory paths get 404 instead of a
// listing.
func noListing(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src * data: blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

type portalApp struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Icon        string `json:"icon,omitempty"`
	Category    string `json:"category,omitempty"`
	URL         string `json:"url"`
	RequireMFA  bool   `json:"requireMFA,omitempty"`
	// Type is "rdp" or "ssh" for remote apps, empty for web apps.
	Type string `json:"type,omitempty"`
}

type portalData struct {
	User   *session.Session
	Admin  bool
	Groups []string
	Apps   []portalApp
	Tree   *categoryNode
	Remote bool // the user has RDP or SSH apps
}

func (s *Server) portalData(sess *session.Session) portalData {
	d := portalData{User: sess, Admin: s.isAdmin(sess)}
	for _, a := range s.visibleApps(sess) {
		d.Apps = append(d.Apps, portalApp{a.Name, a.DisplayTitle(), a.Description, a.Icon, a.Category, a.URL, a.RequireMFA, a.Protocol()})
	}
	d.Tree = buildCategoryTree(d.Apps)
	d.Remote = slices.ContainsFunc(d.Apps, func(a portalApp) bool { return a.Type != "" })
	if len(sess.Groups) > 0 {
		d.Groups = strings.Split(s.groupList(sess.Groups), ",")
		slices.Sort(d.Groups)
	}
	return d
}

func (s *Server) handlePortal(w http.ResponseWriter, r *http.Request) {
	sess := s.authenticate(w, r)
	if sess == nil {
		http.Redirect(w, r, s.loginURL(s.public.String()+"/", false, 0), http.StatusFound)
		return
	}
	setLogUser(r, sess)
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, http.StatusOK, "portal", s.portalData(sess))
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess := s.authenticate(w, r)
	if sess == nil {
		sess = s.authenticateBearer(w, r) // Sidegate CLI
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if sess == nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"authentication required"}`))
		return
	}
	setLogUser(r, sess)
	d := s.portalData(sess)
	json.NewEncoder(w).Encode(map[string]any{
		"user": map[string]any{
			"subject":  sess.Subject,
			"username": sess.Username,
			"email":    sess.Email,
			"name":     sess.Name,
			"groups":   d.Groups,
		},
		"apps":  d.Apps,
		"admin": d.Admin,
	})
}

func (s *Server) handleSignedOut(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "message", messageData{
		Title:   "Signed out",
		Message: "You have been signed out of all applications.",
		Action:  "Sign in again",
		Link:    s.public.String() + "/",
	})
}

type messageData struct {
	Admin          bool
	Status         int
	Title, Message string
	Action, Link   string
	// PostTo, if set, renders Action as a button posting there.
	PostTo string
	User   *session.Session
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, title, msg string) {
	w.Header().Set("Cache-Control", "no-store")
	if strings.Contains(r.Header.Get("Accept"), "application/json") && !strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": title, "message": msg})
		return
	}
	sess := s.loadSession(r)
	s.render(w, status, "message", messageData{
		Status:  status,
		Title:   title,
		Message: msg,
		Action:  "Go to app overview",
		Link:    s.public.String() + "/",
		User:    sess,
		Admin:   s.isAdmin(sess),
	})
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("internal error", "error", err, "path", r.URL.Path)
	s.renderError(w, r, http.StatusInternalServerError, "Something went wrong", "An internal error occurred.")
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("render template", "template", name, "error", err)
	}
}
