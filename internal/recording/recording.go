// SPDX-License-Identifier: AGPL-3.0-only

// Package recording records browser sessions of RDP and SSH apps and plays
// them back in the admin UI.
package recording

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"sidegate/internal/config"
	"sidegate/internal/server"
)

// Session recording records browser sessions of RDP and SSH apps. The proxy
// sees the Guacamole protocol stream guacd sends to the browser, which is
// exactly what guacd itself would write as a recording, so recordings are
// written by the proxy and need no shared storage with guacd. They are
// played back in the admin UI with guacamole-common-js.
//
// Layout: <dir>/<yyyymmdd>/<id>.guac (the stream) and <id>.json (metadata).
//
// Sessions through the Sidegate CLI are end-to-end encrypted between the
// user's client and the host and can't be recorded; they stay allowed and
// are logged by the core.

const (
	recordingSetting   = "recording"
	settingsCacheTTL   = 5 * time.Second
	recordingListLimit = 1000
	adminPath          = "/admin/recordings"
)

var (
	recordingID = regexp.MustCompile(`^([0-9]{8})-[0-9a-f]{16}$`)

	//go:embed templates/*.html
	recordingFS  embed.FS
	recordingTpl = template.Must(template.New("").Funcs(template.FuncMap{
		"duration": formatDuration,
		"size":     formatSize,
	}).ParseFS(recordingFS, "templates/*.html"))
)

// recordingSettings are changed in the admin UI and stored in the database.
type recordingSettings struct {
	Apps []string `json:"apps"`
}

type recorder struct {
	host server.Host
	cfg  config.Recording

	mu       sync.Mutex
	apps     map[string]bool
	loadedAt time.Time
}

type recordingMeta struct {
	ID       string    `json:"id"`
	App      string    `json:"app"`
	Title    string    `json:"title"`
	Protocol string    `json:"protocol"`
	Subject  string    `json:"subject"`
	User     string    `json:"user"`
	Name     string    `json:"name,omitempty"`
	Email    string    `json:"email,omitempty"`
	Start    time.Time `json:"start"`
	End      time.Time `json:"end,omitzero"`
	Reason   string    `json:"reason,omitempty"`
	Bytes    int64     `json:"bytes"`
	Width    int       `json:"width"`
	Height   int       `json:"height"`
}

func (m recordingMeta) Duration() time.Duration {
	if m.End.IsZero() {
		return 0
	}
	return m.End.Sub(m.Start)
}

func (m recordingMeta) Who() string {
	for _, v := range []string{m.Name, m.Email, m.User} {
		if v != "" {
			return v
		}
	}
	return m.Subject
}

// New returns the session recording module; register it with
// server.Register before the server starts.
func New() server.Extension { return &recorder{} }

func (r *recorder) Name() string { return "recording" }

func (r *recorder) Init(h server.Host) error {
	r.host = h
	cfg := h.Config().Recording
	r.cfg = cfg
	if cfg.Dir == "" {
		h.Logger().Info("session recording is not configured (recording.dir)")
		return nil
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return fmt.Errorf("recording directory: %w", err)
	}
	probe, err := os.CreateTemp(cfg.Dir, ".probe-*")
	if err != nil {
		return fmt.Errorf("recording directory is not writable: %w", err)
	}
	probe.Close()
	os.Remove(probe.Name())
	h.Logger().Info("session recording enabled", "dir", cfg.Dir, "retentionDays", cfg.RetentionDays)
	go r.cleanupLoop()
	return nil
}

// recordedApps returns the apps whose browser sessions are recorded.
func (r *recorder) recordedApps(ctx context.Context) (map[string]bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.apps != nil && time.Since(r.loadedAt) < settingsCacheTTL {
		return r.apps, nil
	}
	settings, err := r.settings(ctx)
	if err != nil {
		if r.apps != nil {
			return r.apps, nil // database hiccup: keep the last known settings
		}
		return nil, err
	}
	apps := map[string]bool{}
	for _, a := range settings.Apps {
		apps[a] = true
	}
	r.apps, r.loadedAt = apps, time.Now()
	return apps, nil
}

func (r *recorder) settings(ctx context.Context) (recordingSettings, error) {
	var s recordingSettings
	raw, err := r.host.Store().Setting(ctx, recordingSetting)
	if err != nil || raw == "" {
		return s, err
	}
	return s, json.Unmarshal([]byte(raw), &s)
}

func (r *recorder) RemoteNotice(app string) string {
	apps, err := r.recordedApps(context.Background())
	if err != nil || !apps[app] {
		return ""
	}
	return "Browser sessions of this app are recorded: everything shown on screen is stored and can be reviewed by administrators."
}

func (r *recorder) ObserveRemote(rs server.RemoteSession) (server.RemoteStream, error) {
	apps, err := r.recordedApps(context.Background())
	if err != nil {
		return nil, fmt.Errorf("load recording settings: %w", err) // fail closed
	}
	if !apps[rs.App] {
		return nil, nil
	}
	if r.cfg.Dir == "" {
		return nil, errors.New("recording is enabled for the app, but no recording directory is configured")
	}
	b := make([]byte, 8)
	rand.Read(b)
	day := rs.Start.UTC().Format("20060102")
	meta := recordingMeta{
		ID: day + "-" + hex.EncodeToString(b), App: rs.App, Title: rs.Title, Protocol: rs.Protocol,
		Start: rs.Start.UTC(), Width: rs.Width, Height: rs.Height,
	}
	if u := rs.User; u != nil {
		meta.Subject, meta.User, meta.Name, meta.Email = u.Subject, u.Username, u.Name, u.Email
	}
	dir := filepath.Join(r.cfg.Dir, day)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, meta.ID+".guac"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	st := &recordingStream{r: r, f: f, meta: meta}
	if err := st.writeMeta(); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}
	r.host.Logger().Info("session recording started", "recording", meta.ID, "app", meta.App, "user", meta.User)
	return st, nil
}

type recordingStream struct {
	r    *recorder
	f    *os.File
	meta recordingMeta
}

func (s *recordingStream) Output(raw string) error {
	n, err := s.f.WriteString(raw)
	s.meta.Bytes += int64(n)
	return err
}

func (s *recordingStream) Close(reason string) {
	if err := s.f.Close(); err != nil {
		s.r.host.Logger().Error("close recording", "recording", s.meta.ID, "error", err)
	}
	s.meta.End, s.meta.Reason = time.Now().UTC(), reason
	if err := s.writeMeta(); err != nil {
		s.r.host.Logger().Error("write recording metadata", "recording", s.meta.ID, "error", err)
	}
	s.r.host.Logger().Info("session recording ended", "recording", s.meta.ID, "app", s.meta.App,
		"user", s.meta.User, "bytes", s.meta.Bytes, "duration", s.meta.Duration().Round(time.Second))
}

// writeMeta replaces the metadata file atomically, so readers on other
// replicas never see a partial file.
func (s *recordingStream) writeMeta() error {
	data, _ := json.MarshalIndent(s.meta, "", "  ")
	path := strings.TrimSuffix(s.f.Name(), ".guac") + ".json"
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// cleanupLoop deletes recordings older than the retention period. Every
// replica runs it; deleting concurrently is harmless.
func (r *recorder) cleanupLoop() {
	for {
		r.cleanup(time.Now())
		time.Sleep(time.Hour)
	}
}

func (r *recorder) cleanup(now time.Time) {
	entries, err := os.ReadDir(r.cfg.Dir)
	if err != nil {
		r.host.Logger().Error("recording cleanup", "error", err)
		return
	}
	cutoff := now.UTC().AddDate(0, 0, -r.cfg.RetentionDays)
	for _, e := range entries {
		day, err := time.Parse("20060102", e.Name())
		if !e.IsDir() || err != nil || !day.AddDate(0, 0, 1).Before(cutoff) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(r.cfg.Dir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			r.host.Logger().Error("recording cleanup", "day", e.Name(), "error", err)
			continue
		}
		r.host.Logger().Info("deleted recordings past retention", "day", e.Name())
	}
}

// list returns the newest recordings first.
func (r *recorder) list() ([]recordingMeta, error) {
	days, err := os.ReadDir(r.cfg.Dir)
	if err != nil {
		return nil, err
	}
	slices.Reverse(days) // ReadDir sorts by name, i.e. by date
	var out []recordingMeta
	for _, d := range days {
		if !d.IsDir() || len(out) >= recordingListLimit {
			continue
		}
		files, _ := filepath.Glob(filepath.Join(r.cfg.Dir, d.Name(), "*.json"))
		var day []recordingMeta
		for _, f := range files {
			if m, err := readMeta(f); err == nil {
				day = append(day, m)
			}
		}
		sort.Slice(day, func(i, j int) bool { return day[i].Start.After(day[j].Start) })
		out = append(out, day...)
	}
	if len(out) > recordingListLimit {
		out = out[:recordingListLimit]
	}
	return out, nil
}

func readMeta(path string) (recordingMeta, error) {
	var m recordingMeta
	data, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(data, &m)
}

// path returns the base path (without extension) of recording id, or ""
// if id isn't a valid recording ID.
func (r *recorder) path(id string) string {
	m := recordingID.FindStringSubmatch(id)
	if m == nil || r.cfg.Dir == "" {
		return ""
	}
	return filepath.Join(r.cfg.Dir, m[1], id)
}

// Admin UI.

func (r *recorder) AdminPages() []server.AdminPage {
	return []server.AdminPage{{Title: "Recordings", Path: adminPath}}
}

func (r *recorder) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+adminPath, r.host.Admin(r.handleList))
	mux.HandleFunc("POST "+adminPath+"/settings", r.host.Admin(r.handleSettings))
	mux.HandleFunc("GET "+adminPath+"/{id}", r.host.Admin(r.handlePlayer))
	mux.HandleFunc("GET "+adminPath+"/{id}/data", r.host.Admin(r.handleData))
}

type remoteApp struct {
	Name     string
	Title    string
	Protocol string
	Recorded bool
}

type listData struct {
	CSRF       string
	Configured bool
	Dir        string
	Retention  int
	Apps       []remoteApp
	Recordings []recordingMeta
	Total      int64
	Notice     string
	Error      string
}

func (r *recorder) handleList(w http.ResponseWriter, req *http.Request) {
	r.renderList(w, req, http.StatusOK, req.URL.Query().Get("saved") != "", "")
}

func (r *recorder) renderList(w http.ResponseWriter, req *http.Request, status int, saved bool, errMsg string) {
	d := listData{
		CSRF: r.host.CSRFToken(req), Configured: r.cfg.Dir != "", Dir: r.cfg.Dir, Retention: r.cfg.RetentionDays, Error: errMsg,
	}
	if saved {
		d.Notice = "Recording settings saved."
	}
	apps, _, _, err := r.host.Store().Load(req.Context())
	if err != nil {
		http.Error(w, "loading apps failed", http.StatusInternalServerError)
		return
	}
	settings, err := r.settings(req.Context())
	if err != nil {
		http.Error(w, "loading recording settings failed", http.StatusInternalServerError)
		return
	}
	for _, a := range apps {
		if p := a.Protocol(); p != "" {
			d.Apps = append(d.Apps, remoteApp{Name: a.Name, Title: a.DisplayTitle(), Protocol: p, Recorded: slices.Contains(settings.Apps, a.Name)})
		}
	}
	if d.Configured {
		if d.Recordings, err = r.list(); err != nil {
			d.Error = "Reading the recording directory failed: " + err.Error()
		}
		for _, m := range d.Recordings {
			d.Total += m.Bytes
		}
	}
	r.host.RenderTemplate(w, req, status, adminPath, recordingTpl.Lookup("list.html"), d)
}

func (r *recorder) handleSettings(w http.ResponseWriter, req *http.Request) {
	if r.cfg.Dir == "" {
		r.renderList(w, req, http.StatusBadRequest, false, "Configure a recording directory first.")
		return
	}
	apps, _, _, err := r.host.Store().Load(req.Context())
	if err != nil {
		http.Error(w, "loading apps failed", http.StatusInternalServerError)
		return
	}
	selected := req.PostForm["app"]
	settings := recordingSettings{Apps: []string{}}
	for _, a := range apps {
		if a.Protocol() != "" && slices.Contains(selected, a.Name) {
			settings.Apps = append(settings.Apps, a.Name)
		}
	}
	data, _ := json.Marshal(settings)
	if err := r.host.Store().SaveSetting(req.Context(), r.host.Actor(req), recordingSetting, string(data)); err != nil {
		r.renderList(w, req, http.StatusInternalServerError, false, "Saving failed: "+err.Error())
		return
	}
	r.mu.Lock()
	r.apps = nil // apply on this replica right away
	r.mu.Unlock()
	http.Redirect(w, req, adminPath+"?saved=1", http.StatusSeeOther)
}

func (r *recorder) handlePlayer(w http.ResponseWriter, req *http.Request) {
	base := r.path(req.PathValue("id"))
	m, err := readMeta(base + ".json")
	if base == "" || err != nil {
		r.host.RenderAdmin(w, req, http.StatusNotFound, adminPath, "<p class=\"alert\">This recording doesn't exist (any more).</p>")
		return
	}
	r.host.RenderTemplate(w, req, http.StatusOK, adminPath, recordingTpl.Lookup("player.html"), m)
}

// handleData serves the recording itself. Every access is audited.
func (r *recorder) handleData(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	base := r.path(id)
	if base == "" {
		http.NotFound(w, req)
		return
	}
	f, err := os.Open(base + ".guac")
	if err != nil {
		http.NotFound(w, req)
		return
	}
	defer f.Close()
	target := id
	if m, err := readMeta(base + ".json"); err == nil {
		target = fmt.Sprintf("%s (%s on %s)", id, m.Who(), m.App)
	}
	if err := r.host.Store().LogAccess(req.Context(), r.host.Actor(req), "recording.view", target); err != nil {
		r.host.Logger().Error("audit recording access", "recording", id, "error", err)
		http.Error(w, "recording access can't be audited right now", http.StatusServiceUnavailable)
		return
	}
	info, _ := f.Stat()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, req, "", info.ModTime(), f)
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h, m, s := int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%d:%02d", m, s)
}

func formatSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
