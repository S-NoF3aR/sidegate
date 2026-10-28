// SPDX-License-Identifier: AGPL-3.0-only

package recording

import (
	"bytes"
	"context"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sidegate/internal/config"
	"sidegate/internal/server"
	"sidegate/internal/session"
	"sidegate/internal/store"
)

type fakeHost struct {
	st  *store.Store
	cfg *config.Config
}

func (h *fakeHost) Logger() *slog.Logger                      { return slog.New(slog.DiscardHandler) }
func (h *fakeHost) Store() *store.Store                       { return h.st }
func (h *fakeHost) Config() *config.Config                    { return h.cfg }
func (h *fakeHost) Admin(f http.HandlerFunc) http.HandlerFunc { return f }
func (h *fakeHost) User(*http.Request) *session.Session       { return nil }
func (h *fakeHost) Actor(*http.Request) string                { return "admin@example.com" }
func (h *fakeHost) CSRFToken(*http.Request) string            { return "csrf" }
func (h *fakeHost) RenderAdmin(w http.ResponseWriter, _ *http.Request, status int, _ string, body template.HTML) {
	w.WriteHeader(status)
	io.WriteString(w, string(body))
}
func (h *fakeHost) RenderTemplate(w http.ResponseWriter, r *http.Request, status int, path string, t *template.Template, data any) {
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	h.RenderAdmin(w, r, status, path, template.HTML(b.String()))
}

func newRecorder(t *testing.T, dir string) (*recorder, *fakeHost, http.Handler) {
	t.Helper()
	st, err := store.Open(context.Background(), "sqlite:"+t.TempDir()+"/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	for _, a := range []config.App{
		{Name: "desk", Subdomain: "desk", Upstream: "rdp://win1:3389", AllowedGroups: []string{"*"}},
		{Name: "shell", Subdomain: "shell", Upstream: "ssh://bastion:22", AllowedGroups: []string{"*"}},
		{Name: "wiki", Subdomain: "wiki", Upstream: "http://wiki", AllowedGroups: []string{"*"}},
	} {
		if err := st.CreateApp(ctx, "test", a); err != nil {
			t.Fatal(err)
		}
	}
	h := &fakeHost{st: st, cfg: &config.Config{Recording: config.Recording{Dir: dir, RetentionDays: 30}}}
	r := &recorder{}
	if err := r.Init(h); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	r.Routes(mux)
	return r, h, mux
}

func TestRecording(t *testing.T) {
	dir := t.TempDir()
	r, h, mux := newRecorder(t, dir)
	ctx := context.Background()
	alice := &session.Session{Subject: "alice-id", Username: "alice", Email: "alice@example.com", Name: "Alice"}
	rs := server.RemoteSession{App: "desk", Title: "Desk", Protocol: "rdp", User: alice, Start: time.Now(), Width: 1280, Height: 720}

	// Nothing is recorded until an admin enables it for the app.
	if st, err := r.ObserveRemote(rs); st != nil || err != nil {
		t.Fatalf("unconfigured app: %v %v", st, err)
	}
	if r.RemoteNotice("desk") != "" {
		t.Error("notice for an app that isn't recorded")
	}

	// The settings form keeps only remote apps.
	form := url.Values{"csrf": {"csrf"}, "app": {"desk", "wiki", "nope"}}
	req := httptest.NewRequest("POST", "/admin/recordings/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save settings: %d %s", rec.Code, rec.Body)
	}
	if v, _ := h.st.Setting(ctx, "recording"); v != `{"apps":["desk"]}` {
		t.Errorf("stored settings = %s", v)
	}
	if !strings.Contains(r.RemoteNotice("desk"), "recorded") || r.RemoteNotice("shell") != "" {
		t.Error("notices don't follow the settings")
	}

	// A recorded session writes the stream and its metadata.
	st, err := r.ObserveRemote(rs)
	if err != nil || st == nil {
		t.Fatalf("observe: %v %v", st, err)
	}
	stream := "4.size,1.0,4.1280,3.720;4.sync,4.1000;4.sync,4.3000;"
	st.Output(stream[:22])
	st.Output(stream[22:])
	st.Close("you signed out")
	list, err := r.list()
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v %v", list, err)
	}
	m := list[0]
	if m.App != "desk" || m.User != "alice" || m.Bytes != int64(len(stream)) || m.Reason != "you signed out" || m.End.IsZero() || m.Width != 1280 {
		t.Errorf("metadata = %+v", m)
	}
	info, err := os.Stat(r.path(m.ID) + ".guac")
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("recording file: %v %v", info, err)
	}

	// The list page shows it; playing it is audited.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/recordings", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "/admin/recordings/"+m.ID) || !strings.Contains(rec.Body.String(), `value="desk" checked`) {
		t.Errorf("list page: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/recordings/"+m.ID, nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `data-src="/admin/recordings/`+m.ID+`/data"`) {
		t.Errorf("player page: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/recordings/"+m.ID+"/data", nil))
	if rec.Code != 200 || rec.Body.String() != stream {
		t.Errorf("data: %d %q", rec.Code, rec.Body)
	}
	audit, _ := h.st.Audit(ctx, 10)
	if audit[0].Action != "recording.view" || audit[0].Actor != "admin@example.com" || !strings.Contains(audit[0].Target, "Alice on desk") {
		t.Errorf("audit = %+v", audit[0])
	}
	for _, bad := range []string{"../../etc/passwd", "20260101-zzzzzzzzzzzzzzzz", "20260101-0000000000000000"} {
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/recordings/"+url.PathEscape(bad)+"/data", nil))
		if rec.Code != 404 {
			t.Errorf("data %q: %d", bad, rec.Code)
		}
	}
	if r.path("../x") != "" {
		t.Error("path accepts traversal")
	}
}

func TestRecordingFailsClosed(t *testing.T) {
	// Enabled for an app on a replica without a recording directory: the
	// session must not start unrecorded.
	r, h, _ := newRecorder(t, "")
	h.st.SaveSetting(context.Background(), "admin", "recording", `{"apps":["desk"]}`)
	if st, err := r.ObserveRemote(server.RemoteSession{App: "desk", Start: time.Now()}); err == nil || st != nil {
		t.Errorf("observe without dir: %v %v", st, err)
	}
	// An unwritable directory is reported at startup.
	if os.Geteuid() != 0 {
		ro := t.TempDir()
		os.Chmod(ro, 0o500)
		h.cfg.Recording.Dir = ro
		if err := (&recorder{}).Init(h); err == nil {
			t.Error("unwritable directory accepted")
		}
	}
}

func TestRecordingRetention(t *testing.T) {
	dir := t.TempDir()
	r, _, _ := newRecorder(t, dir)
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	for _, day := range []string{"20260926", "20260927", "20261027", "notadate"} {
		os.MkdirAll(filepath.Join(dir, day), 0o700)
	}
	r.cleanup(now) // retention is 30 days
	for day, want := range map[string]bool{"20260926": false, "20260927": true, "20261027": true, "notadate": true} {
		if _, err := os.Stat(filepath.Join(dir, day)); (err == nil) != want {
			t.Errorf("%s kept = %v, want %v", day, err == nil, want)
		}
	}
}
