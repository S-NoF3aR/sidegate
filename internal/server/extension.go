// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"sidegate/internal/config"
	"sidegate/internal/session"
	"sidegate/internal/store"
)

// Version is set by the main package.
var Version = "dev"

// Extensions are optional modules (such as session recording) that plug
// into the server through the interfaces below instead of being wired into
// its code. The main package registers them before the server starts:
//
//	server.Register(recording.New())
//
// An extension may also implement RouteProvider and EventHandler.
type Extension interface {
	Name() string
	// Init is called once while the server starts. Returning an error
	// aborts startup.
	Init(Host) error
}

// RouteProvider adds HTTP handlers on the portal host. Use Host.Admin to
// restrict them to admins.
type RouteProvider interface {
	Routes(mux *http.ServeMux)
}

// EventHandler receives events. Handlers are called from a separate
// goroutine per extension, in order; events are dropped (and counted in
// sidegate_extension_events_dropped_total) if a handler falls behind.
type EventHandler interface {
	HandleEvent(Event)
}

// AdminPageProvider adds tabs to the admin UI. The pages themselves are
// routes added with RouteProvider, wrapped in Host.Admin and rendered with
// Host.RenderAdmin.
type AdminPageProvider interface {
	AdminPages() []AdminPage
}

type AdminPage struct {
	Title string
	Path  string // on the portal host, e.g. "/admin/recordings"
}

// RemoteObserver watches browser sessions of remote (RDP and SSH) apps, e.g.
// to record them. Sessions through the Sidegate CLI are end-to-end encrypted
// between the user's client and the host, so they can't be observed.
type RemoteObserver interface {
	// RemoteNotice returns a notice shown to users on the app's page
	// before they connect (e.g. "This session is recorded."), or "".
	RemoteNotice(app string) string
	// ObserveRemote is called when a browser session has been set up with
	// guacd, before anything is shown to the user. A nil stream means the
	// session isn't observed; an error refuses the session.
	ObserveRemote(RemoteSession) (RemoteStream, error)
}

// RemoteSession describes a browser session of a remote app.
type RemoteSession struct {
	App      string
	Title    string
	Protocol string // "rdp" or "ssh"
	User     *session.Session
	Start    time.Time
	Width    int
	Height   int
}

// RemoteStream receives the Guacamole protocol stream of one session. Its
// methods are called from one goroutine at a time.
type RemoteStream interface {
	// Output receives instructions sent from guacd to the browser, in
	// order and in wire format, before the browser gets them. Returning
	// an error ends the session.
	Output(raw string) error
	// Close is called once when the session has ended.
	Close(reason string)
}

// Event types.
const (
	EventLogin          = "login"           // a user signed in
	EventLogout         = "logout"          // a user signed out (browser or CLI)
	EventSessionRevoked = "session.revoked" // the IdP revoked a session on refresh
	EventAccessDenied   = "access.denied"   // Fields: reason (unauthenticated, forbidden, step_up)
	EventRemoteStart    = "remote.start"    // Fields: protocol, client
	EventRemoteEnd      = "remote.end"      // Fields: protocol, client, duration
	EventConfigChange   = "config.change"   // Fields: action, target; User is the actor
)

type Event struct {
	Type    string            `json:"type"`
	Time    time.Time         `json:"time"`
	User    string            `json:"user,omitempty"`
	Subject string            `json:"subject,omitempty"`
	App     string            `json:"app,omitempty"`
	Fields  map[string]string `json:"fields,omitempty"`
}

// Host is what the server offers extensions.
type Host interface {
	Logger() *slog.Logger
	Store() *store.Store
	Config() *config.Config
	// Admin wraps h so only signed-in admins can use it; form posts must
	// carry the token from CSRFToken.
	Admin(h http.HandlerFunc) http.HandlerFunc
	// User returns the signed-in user of r, or nil.
	User(r *http.Request) *session.Session
	// Actor names the user of r as the audit log does.
	Actor(r *http.Request) string
	CSRFToken(r *http.Request) string
	// RenderAdmin renders body as an admin page, with the admin tabs; path
	// selects the active tab (see AdminPageProvider).
	RenderAdmin(w http.ResponseWriter, r *http.Request, status int, path string, body template.HTML)
	// RenderTemplate executes t with data and renders the result as an
	// admin page (see RenderAdmin).
	RenderTemplate(w http.ResponseWriter, r *http.Request, status int, path string, t *template.Template, data any)
}

var (
	registryMu sync.Mutex
	registry   []Extension
)

// Register adds an extension. Call it before creating the server.
func Register(e Extension) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = append(registry, e)
}

func registered() []Extension {
	registryMu.Lock()
	defer registryMu.Unlock()
	return append([]Extension(nil), registry...)
}

func (s *Server) Logger() *slog.Logger                  { return s.log }
func (s *Server) Store() *store.Store                   { return s.store }
func (s *Server) Config() *config.Config                { return s.cfg }
func (s *Server) User(r *http.Request) *session.Session { return s.loadSession(r) }

func (s *Server) Admin(h http.HandlerFunc) http.HandlerFunc {
	return s.admin(func(w http.ResponseWriter, r *http.Request, _ *session.Session) { h(w, r) })
}

func (s *Server) Actor(r *http.Request) string {
	if sess := s.loadSession(r); sess != nil {
		return actor(sess)
	}
	return ""
}

func (s *Server) RenderAdmin(w http.ResponseWriter, r *http.Request, status int, path string, body template.HTML) {
	sess := s.loadSession(r)
	if sess == nil || !s.isAdmin(sess) {
		s.renderError(w, r, http.StatusForbidden, "Access denied", "Only administrators can open this page.")
		return
	}
	s.adminPage(w, status, sess, adminData{Section: "ext", ExtPath: path, ExtBody: body})
}

func (s *Server) RenderTemplate(w http.ResponseWriter, r *http.Request, status int, path string, t *template.Template, data any) {
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.RenderAdmin(w, r, status, path, template.HTML(b.String()))
}

// adminPages returns the admin tabs added by extensions.
func (s *Server) adminPages() []AdminPage {
	var out []AdminPage
	for _, e := range s.extensions {
		if p, ok := e.(AdminPageProvider); ok {
			out = append(out, p.AdminPages()...)
		}
	}
	return out
}

// remoteNotices returns the notices extensions show before a remote
// session starts.
func (s *Server) remoteNotices(app string) []string {
	var out []string
	for _, e := range s.extensions {
		if o, ok := e.(RemoteObserver); ok {
			if n := o.RemoteNotice(app); n != "" {
				out = append(out, n)
			}
		}
	}
	return out
}

// observeRemote starts the extensions' observers of a browser session. If
// one fails, those already started are closed.
func (s *Server) observeRemote(rs RemoteSession) ([]RemoteStream, error) {
	var out []RemoteStream
	for _, e := range s.extensions {
		o, ok := e.(RemoteObserver)
		if !ok {
			continue
		}
		st, err := o.ObserveRemote(rs)
		if err != nil {
			for _, prev := range out {
				prev.Close("observer failed")
			}
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if st != nil {
			out = append(out, st)
		}
	}
	return out, nil
}

func (s *Server) CSRFToken(r *http.Request) string {
	if sess := s.loadSession(r); sess != nil {
		return s.csrfToken(sess)
	}
	return ""
}

// initExtensions starts the registered extensions and their event queues.
func (s *Server) initExtensions() error {
	for _, e := range registered() {
		if err := e.Init(s); err != nil {
			return err
		}
		if h, ok := e.(EventHandler); ok {
			q := make(chan Event, 1024)
			s.eventQueues = append(s.eventQueues, q)
			go func() {
				for ev := range q {
					h.HandleEvent(ev)
				}
			}()
		}
		s.extensions = append(s.extensions, e)
		s.log.Info("extension loaded", "name", e.Name())
	}
	return nil
}

// emit hands an event to every EventHandler without ever blocking a
// request.
func (s *Server) emit(ev Event) {
	if len(s.eventQueues) == 0 {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	for _, q := range s.eventQueues {
		select {
		case q <- ev:
		default:
			s.metrics.eventsDropped.Inc()
		}
	}
}

// userEvent fills in the user of an event from a session.
func userEvent(typ string, sess *session.Session, app string, fields map[string]string) Event {
	ev := Event{Type: typ, App: app, Fields: fields}
	if sess != nil {
		ev.User, ev.Subject = sess.Username, sess.Subject
	}
	return ev
}
