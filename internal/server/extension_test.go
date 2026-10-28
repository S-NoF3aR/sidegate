// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"sidegate/internal/config"
	"sidegate/internal/guac"
)

type testExtension struct {
	host   Host
	mu     sync.Mutex
	events []Event
}

func (e *testExtension) Name() string      { return "test" }
func (e *testExtension) Init(h Host) error { e.host = h; return nil }
func (e *testExtension) HandleEvent(ev Event) {
	e.mu.Lock()
	e.events = append(e.events, ev)
	e.mu.Unlock()
}
func (e *testExtension) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /ext/hello", e.host.Admin(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello " + e.host.User(r).Username))
	}))
}

func (e *testExtension) has(typ, field, value string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range e.events {
		if ev.Type == typ && (field == "" || ev.Fields[field] == value) {
			return true
		}
	}
	return false
}

func withExtension(t *testing.T) *testExtension {
	ext := &testExtension{}
	Register(ext)
	t.Cleanup(func() {
		registryMu.Lock()
		registry = nil
		registryMu.Unlock()
	})
	return ext
}

func TestExtensions(t *testing.T) {
	ext := withExtension(t)
	e := newEnv(t, root)

	// Routes are served on the portal host and can be restricted to admins.
	if _, body := e.get(t, e.url("portal", "/ext/hello")); body != "hello root@example.com" {
		t.Errorf("extension route = %q", body)
	}
	// Events: login, a config change through the admin API, a denial, logout.
	token := e.createToken(t, "t")
	e.api(t, token, "PUT", "/groups/g9", `{"name":"nine"}`)
	e.get(t, e.url("whoami", "/")) // root isn't in g-devs or g-admins
	noRedirects(e)
	e.post(t, "/oauth2/logout", nil, "Origin", e.srv.public.String())

	deadline := time.Now().Add(2 * time.Second)
	for !(ext.has(EventLogin, "", "") && ext.has(EventConfigChange, "action", "group.save") &&
		ext.has(EventAccessDenied, "reason", "forbidden") && ext.has(EventLogout, "", "")) {
		if time.Now().After(deadline) {
			ext.mu.Lock()
			t.Fatalf("missing events, got %+v", ext.events)
		}
		time.Sleep(10 * time.Millisecond)
	}
	ext.mu.Lock()
	defer ext.mu.Unlock()
	for _, ev := range ext.events {
		if ev.Type == EventConfigChange && ev.Fields["action"] == "group.save" && ev.User != "token:t" {
			t.Errorf("config change actor = %q", ev.User)
		}
	}
}

func TestExtensionRouteNeedsAdmin(t *testing.T) {
	withExtension(t)
	e := newEnv(t, alice)
	if resp, body := e.get(t, e.url("portal", "/ext/hello")); resp.StatusCode != 403 || strings.Contains(body, "hello") {
		t.Errorf("non-admin: %d", resp.StatusCode)
	}
}

type testObserver struct {
	testExtension
	mu       sync.Mutex
	failOpen bool
	failOut  bool
	sessions []RemoteSession
	output   strings.Builder
	closed   chan string
}

func (o *testObserver) RemoteNotice(app string) string {
	if app == "desk" {
		return "This session is recorded."
	}
	return ""
}

func (o *testObserver) ObserveRemote(rs RemoteSession) (RemoteStream, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sessions = append(o.sessions, rs)
	if o.failOpen {
		return nil, errors.New("disk full")
	}
	return o, nil
}

func (o *testObserver) Output(raw string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.failOut {
		return errors.New("write failed")
	}
	o.output.WriteString(raw)
	return nil
}

func (o *testObserver) Close(reason string) { o.closed <- reason }

func TestRemoteObserver(t *testing.T) {
	obs := &testObserver{closed: make(chan string, 1)}
	Register(obs)
	t.Cleanup(func() {
		registryMu.Lock()
		registry = nil
		registryMu.Unlock()
	})
	e := newEnv(t, alice)
	g := newFakeGuacd(t)
	e.srv.guacd = g.ln.Addr().String()
	addRDPApp(t, e, config.App{Name: "desk", Upstream: "rdp://win1.corp:3389", AllowedGroups: []string{"*"}})
	ctx := context.Background()
	dial := func() *websocket.Conn {
		t.Helper()
		ws, _, err := websocket.Dial(ctx, e.wsURL("desk", "/.sidegate/guac?width=1024&height=768"),
			&websocket.DialOptions{HTTPClient: e.client, Subprotocols: []string{"guacamole"}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ws.CloseNow() })
		return ws
	}

	// Users see the notice before connecting.
	if _, page := e.get(t, e.url("desk", "/")); !strings.Contains(page, "This session is recorded.") || !strings.Contains(page, "Recorded</span>") {
		t.Error("remote page lacks the observer's notice")
	}

	// The observer sees what guacd sends, and is closed when the session ends.
	ws := dial()
	readMsg(t, ws) // tunnel UUID
	ws.Write(ctx, websocket.MessageText, []byte(guac.New("key", "65", "1").String()))
	if got := readMsg(t, ws); got != "4.sync,2.42;" {
		t.Fatalf("relay = %q", got)
	}
	ws.Close(websocket.StatusNormalClosure, "")
	select {
	case why := <-obs.closed:
		if why != "disconnected" {
			t.Errorf("close reason = %q", why)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("observer not closed")
	}
	obs.mu.Lock()
	if out := obs.output.String(); out != "4.sync,2.42;" {
		t.Errorf("observed output = %q", out)
	}
	if rs := obs.sessions[0]; rs.App != "desk" || rs.Protocol != "rdp" || rs.User.Subject != "alice-id" || rs.Width != 1024 {
		t.Errorf("session = %+v", rs)
	}
	obs.failOut = true
	obs.mu.Unlock()

	// If the observer fails mid-session, the session ends.
	ws = dial()
	readMsg(t, ws)
	ws.Write(ctx, websocket.MessageText, []byte(guac.New("key", "65", "1").String()))
	if got := readMsg(t, ws); !strings.Contains(got, "can't be recorded") {
		t.Errorf("after output failure = %q", got)
	}
	if why := <-obs.closed; why != "session recording failed" {
		t.Errorf("close reason = %q", why)
	}

	// If the observer can't start, neither does the session.
	obs.mu.Lock()
	obs.failOpen = true
	obs.mu.Unlock()
	ws = dial()
	if got := readMsg(t, ws); !strings.HasPrefix(got, "5.error,") || !strings.Contains(got, "can't be recorded") {
		t.Errorf("refused session = %q", got)
	}
}

func TestExtensionAdminPages(t *testing.T) {
	ext := &pageExtension{}
	Register(ext)
	t.Cleanup(func() {
		registryMu.Lock()
		registry = nil
		registryMu.Unlock()
	})
	e := newEnv(t, root)
	_, body := e.get(t, e.url("portal", "/admin/things"))
	if !strings.Contains(body, `/admin/things" aria-current="page">Things</a>`) {
		t.Errorf("tab missing or not active:\n%s", body)
	}
	if !strings.Contains(body, "<p>thing for root@example.com</p>") {
		t.Errorf("body missing")
	}
	// Other admin pages show the tab too.
	if _, body := e.get(t, e.url("portal", "/admin/groups")); !strings.Contains(body, ">Things</a>") {
		t.Error("tab missing on core admin page")
	}
}

type pageExtension struct{ testExtension }

func (p *pageExtension) AdminPages() []AdminPage {
	return []AdminPage{{Title: "Things", Path: "/admin/things"}}
}
func (p *pageExtension) Routes(mux *http.ServeMux) {
	tpl := template.Must(template.New("").Parse(`<p>thing for {{.}}</p>`))
	mux.HandleFunc("GET /admin/things", p.host.Admin(func(w http.ResponseWriter, r *http.Request) {
		p.host.RenderTemplate(w, r, http.StatusOK, "/admin/things", tpl, p.host.Actor(r))
	}))
}
