// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"sidegate/internal/config"
	"sidegate/internal/session"
	"sidegate/internal/store"
)

func (s *Server) adminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin", s.admin(s.handleAdminApps))
	mux.HandleFunc("GET /admin/apps/new", s.admin(s.handleAppForm))
	mux.HandleFunc("GET /admin/apps/{name}", s.admin(s.handleAppForm))
	mux.HandleFunc("POST /admin/apps", s.admin(s.handleAppSave))
	mux.HandleFunc("POST /admin/apps/{name}", s.admin(s.handleAppSave))
	mux.HandleFunc("POST /admin/apps/{name}/delete", s.admin(s.handleAppDelete))
	mux.HandleFunc("GET /admin/groups", s.admin(s.handleGroups))
	mux.HandleFunc("POST /admin/groups", s.admin(s.handleGroupSave))
	mux.HandleFunc("POST /admin/groups/delete", s.admin(s.handleGroupDelete))
	mux.HandleFunc("GET /admin/audit", s.admin(s.handleAudit))
	mux.HandleFunc("GET /admin/users", s.admin(s.handleUsers))
	mux.HandleFunc("POST /admin/users/revoke", s.admin(s.handleUserRevoke))
	mux.HandleFunc("POST /admin/users/revoke-all", s.admin(s.handleRevokeAll))
	mux.HandleFunc("GET /admin/tokens", s.admin(s.handleTokens))
	mux.HandleFunc("POST /admin/tokens", s.admin(s.handleTokenCreate))
	mux.HandleFunc("POST /admin/tokens/delete", s.admin(s.handleTokenDelete))
}

type adminHandler func(w http.ResponseWriter, r *http.Request, sess *session.Session)

// admin restricts h to admins and checks the CSRF token of form posts.
func (s *Server) admin(h adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.authenticate(w, r)
		if sess == nil {
			s.requireLogin(w, r)
			return
		}
		setLogUser(r, sess)
		if !s.isAdmin(sess) {
			s.renderError(w, r, http.StatusForbidden, "Admin access required",
				"You are signed in as "+sess.Display()+", but you are not an administrator of this proxy.")
			return
		}
		if r.Method == http.MethodPost && !s.validCSRF(r, sess) {
			s.renderError(w, r, http.StatusForbidden, "Invalid form submission",
				"The form expired or was not sent from the admin UI. Reload the page and try again.")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		h(w, r, sess)
	}
}

// csrfToken is bound to the session, so it stays valid across refreshes
// but cannot be reused by another user.
func (s *Server) csrfToken(sess *session.Session) string {
	m := hmac.New(sha256.New, s.csrfKey)
	fmt.Fprintf(m, "%s|%d", sess.Subject, sess.Expiry)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) validCSRF(r *http.Request, sess *session.Session) bool {
	// App subdomains are same-site with the portal, so SameSite cookies
	// alone don't stop them from posting here.
	if o := r.Header.Get("Origin"); o != "" && o != s.public.String() {
		return false
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}
	return hmac.Equal([]byte(r.PostFormValue("csrf")), []byte(s.csrfToken(sess)))
}

type adminData struct {
	User    *session.Session
	Admin   bool
	CSRF    string
	Section string
	Domain  string
	Notice  string
	Errors  []string

	Apps   []adminApp
	Groups []store.Group
	Audit  []store.AuditEntry
	Form   *appForm
	Tokens []store.Token
	Users  []store.User
	// Categories lists existing category paths for autocompletion.
	Categories []string
	// NewToken is shown exactly once, right after creation.
	NewToken string
	APIURL   string

	// Extension pages: tabs, and the active page's path and content.
	ExtPages []AdminPage
	ExtPath  string
	ExtBody  template.HTML
}

type adminApp struct {
	config.App
	URL    string
	Access []string
}

type appForm struct {
	App         config.App
	New         bool
	AllUsers    bool
	Groups      []groupOption
	ExtraGroups string
	Users       string
	PublicPaths string
	// HostMode is "upstream", "original" or "custom".
	HostMode string
}

type groupOption struct {
	store.Group
	Checked bool
}

func (s *Server) adminPage(w http.ResponseWriter, status int, sess *session.Session, d adminData) {
	d.User, d.Admin, d.CSRF, d.Domain = sess, true, s.csrfToken(sess), s.domain
	d.ExtPages = s.adminPages()
	if d.Section == "form" {
		d.Categories = s.categories()
	}
	s.render(w, status, "admin", d)
}

func (s *Server) handleAdminApps(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	rt := s.routes.Load()
	d := adminData{Section: "apps", Notice: notice(r)}
	for _, a := range rt.apps {
		d.Apps = append(d.Apps, adminApp{App: a.App, URL: a.URL, Access: s.accessSummary(&a.App, rt)})
	}
	// Grouped by category, uncategorized last; rt.apps is already sorted by title.
	slices.SortStableFunc(d.Apps, func(x, y adminApp) int {
		if (x.Category == "") != (y.Category == "") {
			if x.Category == "" {
				return 1
			}
			return -1
		}
		return strings.Compare(strings.ToLower(x.Category), strings.ToLower(y.Category))
	})
	s.adminPage(w, http.StatusOK, sess, d)
}

// categories returns every category path in use, including parents.
func (s *Server) categories() []string {
	seen := map[string]bool{}
	for _, a := range s.routes.Load().apps {
		path := ""
		for seg := range strings.SplitSeq(a.Category, "/") {
			if seg == "" {
				continue
			}
			if path != "" {
				path += "/"
			}
			path += seg
			seen[path] = true
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
	return out
}

func (s *Server) accessSummary(a *config.App, rt *routes) []string {
	if a.Public {
		return []string{"Public"}
	}
	var out []string
	for _, g := range a.AllowedGroups {
		switch name, ok := rt.groupNames[g]; {
		case g == "*":
			out = append(out, "All signed-in users")
		case ok:
			out = append(out, name)
		default:
			out = append(out, g)
		}
	}
	out = append(out, a.AllowedUsers...)
	for _, p := range a.PublicPaths {
		out = append(out, "public: "+p)
	}
	return out
}

func (s *Server) handleAppForm(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	name := r.PathValue("name")
	if name == "" {
		s.adminPage(w, http.StatusOK, sess, adminData{Section: "form", Form: s.newAppForm(config.App{}, true)})
		return
	}
	a := s.routes.Load().byName[name]
	if a == nil {
		s.renderError(w, r, http.StatusNotFound, "App not found", "There is no app named "+name+".")
		return
	}
	s.adminPage(w, http.StatusOK, sess, adminData{Section: "form", Form: s.newAppForm(a.App, false)})
}

func (s *Server) newAppForm(a config.App, isNew bool) *appForm {
	f := &appForm{
		App:         a,
		New:         isNew,
		Users:       strings.Join(a.AllowedUsers, "\n"),
		PublicPaths: strings.Join(a.PublicPaths, "\n"),
		HostMode:    "upstream",
	}
	switch {
	case a.HostHeader != "":
		f.HostMode = "custom"
	case a.PassHostHeader:
		f.HostMode = "original"
	}
	known := map[string]bool{}
	for _, g := range s.routes.Load().groupList {
		known[g.ID] = true
		f.Groups = append(f.Groups, groupOption{Group: g, Checked: slices.Contains(a.AllowedGroups, g.ID)})
	}
	var extra []string
	for _, g := range a.AllowedGroups {
		switch {
		case g == "*":
			f.AllUsers = true
		case !known[g]:
			extra = append(extra, g)
		}
	}
	f.ExtraGroups = strings.Join(extra, "\n")
	return f
}

func (s *Server) handleAppSave(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	name := r.PathValue("name")
	isNew := name == ""
	if isNew {
		name = r.PostFormValue("name")
	}
	// The name is the key; when editing it comes from the URL and cannot change.
	a := s.parseAppForm(r, name)

	var err error
	if verr := a.Validate(s.domain, s.portalHost); verr != nil {
		err = verr
	} else if r.PostFormValue("hostMode") == "custom" && a.HostHeader == "" {
		err = errors.Join(errors.New("enter the custom Host header value"))
	} else if isNew {
		err = s.store.CreateApp(r.Context(), actor(sess), a)
	} else {
		err = s.store.UpdateApp(r.Context(), actor(sess), a)
	}
	if err != nil {
		s.adminPage(w, http.StatusBadRequest, sess, adminData{
			Section: "form", Form: s.newAppForm(a, isNew), Errors: s.userErrors(err),
		})
		return
	}
	s.log.Info("app saved", "app", a.Name, "by", actor(sess))
	s.syncAfterWrite(r)
	http.Redirect(w, r, "/admin?saved="+url.QueryEscape(a.Name), http.StatusSeeOther)
}

func (s *Server) parseAppForm(r *http.Request, name string) config.App {
	f := r.PostFormValue
	on := func(k string) bool { return f(k) == "on" }
	a := config.App{
		Name:               name,
		Subdomain:          f("subdomain"),
		Title:              strings.TrimSpace(f("title")),
		Description:        strings.TrimSpace(f("description")),
		Icon:               strings.TrimSpace(f("icon")),
		Category:           f("category"),
		RequireMFA:         on("requireMFA"),
		Upstream:           f("upstream"),
		Public:             on("public"),
		Hidden:             on("hidden"),
		InsecureSkipVerify: on("insecureSkipVerify"),
		AllowedUsers:       splitList(f("users")),
		PublicPaths:        splitList(f("publicPaths")),
	}
	if v := strings.TrimSpace(f("maxAuthAgeMinutes")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			n = -1 // reported by validation
		}
		a.MaxAuthAgeMinutes = n
	}
	switch f("hostMode") {
	case "original":
		a.PassHostHeader = true
	case "custom":
		a.HostHeader = f("hostHeader")
	}
	if on("allUsers") {
		a.AllowedGroups = append(a.AllowedGroups, "*")
	}
	a.AllowedGroups = append(a.AllowedGroups, r.PostForm["groups"]...)
	// Free-text groups may be given by name or by ID.
	byName := map[string]string{}
	for _, g := range s.routes.Load().groupList {
		byName[strings.ToLower(g.Name)] = g.ID
	}
	for _, g := range splitList(f("extraGroups")) {
		if id, ok := byName[strings.ToLower(g)]; ok {
			g = id
		}
		a.AllowedGroups = append(a.AllowedGroups, g)
	}
	slices.Sort(a.AllowedGroups)
	a.AllowedGroups = slices.Compact(a.AllowedGroups)
	a.Normalize()
	return a
}

func (s *Server) handleAppDelete(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	name := r.PathValue("name")
	if err := s.store.DeleteApp(r.Context(), actor(sess), name); err != nil {
		s.adminPage(w, http.StatusBadRequest, sess, adminData{Section: "apps", Errors: s.userErrors(err)})
		return
	}
	s.log.Info("app deleted", "app", name, "by", actor(sess))
	s.syncAfterWrite(r)
	http.Redirect(w, r, "/admin?deleted="+url.QueryEscape(name), http.StatusSeeOther)
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	s.adminPage(w, http.StatusOK, sess, adminData{
		Section: "groups", Groups: s.routes.Load().groupList, Notice: notice(r),
	})
}

func (s *Server) handleGroupSave(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	g := store.Group{ID: r.PostFormValue("id"), Name: r.PostFormValue("name")}
	if err := s.store.SaveGroup(r.Context(), actor(sess), g); err != nil {
		s.adminPage(w, http.StatusBadRequest, sess, adminData{
			Section: "groups", Groups: s.routes.Load().groupList, Errors: s.userErrors(err),
		})
		return
	}
	s.syncAfterWrite(r)
	http.Redirect(w, r, "/admin/groups?saved="+url.QueryEscape(strings.TrimSpace(g.Name)), http.StatusSeeOther)
}

func (s *Server) handleGroupDelete(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	id := r.PostFormValue("id")
	if err := s.store.DeleteGroup(r.Context(), actor(sess), id); err != nil {
		s.adminPage(w, http.StatusBadRequest, sess, adminData{
			Section: "groups", Groups: s.routes.Load().groupList, Errors: s.userErrors(err),
		})
		return
	}
	s.syncAfterWrite(r)
	http.Redirect(w, r, "/admin/groups?deleted="+url.QueryEscape(id), http.StatusSeeOther)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	entries, err := s.store.Audit(r.Context(), 200)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.adminPage(w, http.StatusOK, sess, adminData{Section: "audit", Audit: entries})
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	s.usersPage(w, r, sess, http.StatusOK, adminData{Notice: notice(r)})
}

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request, sess *session.Session, status int, d adminData) {
	users, err := s.store.Users(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Section, d.Users = "users", users
	s.adminPage(w, status, sess, d)
}

func (s *Server) handleUserRevoke(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	subject := r.PostFormValue("subject")
	if err := s.store.RevokeSessions(r.Context(), actor(sess), subject); err != nil {
		s.usersPage(w, r, sess, http.StatusBadRequest, adminData{Errors: s.userErrors(err)})
		return
	}
	s.log.Info("sessions revoked", "subject", subject, "by", actor(sess))
	s.syncAfterWrite(r)
	http.Redirect(w, r, "/admin/users?revoked=1", http.StatusSeeOther)
}

func (s *Server) handleRevokeAll(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	if err := s.store.RevokeAllSessions(r.Context(), actor(sess)); err != nil {
		s.usersPage(w, r, sess, http.StatusBadRequest, adminData{Errors: s.userErrors(err)})
		return
	}
	s.log.Warn("all sessions revoked", "by", actor(sess))
	s.syncAfterWrite(r)
	// This includes the admin's own session.
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (s *Server) tokensPage(w http.ResponseWriter, r *http.Request, sess *session.Session, status int, d adminData) {
	tokens, err := s.store.Tokens(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Section, d.Tokens, d.APIURL = "tokens", tokens, s.public.String()+"/api/v1"
	s.adminPage(w, status, sess, d)
}

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	s.tokensPage(w, r, sess, http.StatusOK, adminData{Notice: notice(r)})
}

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	token, id := newToken()
	t := store.Token{ID: id, Name: r.PostFormValue("name")}
	if err := s.store.CreateToken(r.Context(), actor(sess), t, s.tokenHash(token)); err != nil {
		s.tokensPage(w, r, sess, http.StatusBadRequest, adminData{Errors: s.userErrors(err)})
		return
	}
	s.log.Info("api token created", "token", t.Name, "by", actor(sess))
	// Rendered directly instead of redirecting, so the secret never ends
	// up in a URL or the browser history.
	s.tokensPage(w, r, sess, http.StatusOK, adminData{NewToken: token})
}

func (s *Server) handleTokenDelete(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	if err := s.store.DeleteToken(r.Context(), actor(sess), r.PostFormValue("id")); err != nil {
		s.tokensPage(w, r, sess, http.StatusBadRequest, adminData{Errors: s.userErrors(err)})
		return
	}
	s.log.Info("api token revoked", "id", r.PostFormValue("id"), "by", actor(sess))
	http.Redirect(w, r, "/admin/tokens?deleted=token", http.StatusSeeOther)
}

// syncAfterWrite applies a change on this replica immediately; others pick
// it up through Watch.
func (s *Server) syncAfterWrite(r *http.Request) {
	if err := s.Sync(r.Context()); err != nil {
		s.log.Error("sync after write", "error", err)
	}
}

// userErrors turns validation and conflict errors into messages for the
// form, and hides database internals.
func (s *Server) userErrors(err error) []string {
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
		msg := err.Error()
		for _, p := range []string{store.ErrConflict.Error() + ": ", store.ErrNotFound.Error() + ": "} {
			msg = strings.TrimPrefix(msg, p)
		}
		return []string{msg}
	}
	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		var out []string
		for _, e := range joined.Unwrap() {
			out = append(out, e.Error())
		}
		return out
	}
	s.log.Error("admin write failed", "error", err)
	return []string{"The change could not be saved. Check the logs for details."}
}

func actor(sess *session.Session) string {
	if sess.Username != "" {
		return sess.Username
	}
	return sess.Subject
}

// notice returns the confirmation for the redirect after a change. Anyone
// can craft these links, so only app names (a restricted character set)
// are echoed, never free text.
func notice(r *http.Request) string {
	q := r.URL.Query()
	name := func(v string) string {
		if config.ValidAppName(v) {
			return " " + v
		}
		return ""
	}
	if v := q.Get("saved"); v != "" {
		return "Saved" + name(v) + "."
	}
	if v := q.Get("deleted"); v != "" {
		return "Deleted" + name(v) + "."
	}
	if q.Get("revoked") != "" {
		return "The user was signed out everywhere."
	}
	return ""
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' })
}
