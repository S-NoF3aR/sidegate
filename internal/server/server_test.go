// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"sidegate/internal/config"
	"sidegate/internal/store"
)

// mockIdP is a minimal OIDC provider that signs in a fixed user immediately
// and supports rotating refresh tokens.
type mockIdP struct {
	*httptest.Server
	key *rsa.PrivateKey

	mu            sync.Mutex
	claims        map[string]any
	nonces        map[string]string // code -> nonce
	refreshTokens map[string]bool   // currently valid refresh tokens
	disabled      bool              // user disabled: refreshes fail with invalid_grant
	down          bool              // token endpoint returns 503
	lastAuthorize url.Values        // query of the last authorization request
}

func (m *mockIdP) set(f func(m *mockIdP)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f(m)
}

func newMockIdP(t *testing.T, claims map[string]any) *mockIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Copied, so tests that change the IdP's claims don't leak into others.
	m := &mockIdP{key: key, claims: maps.Clone(claims), nonces: map[string]string{}, refreshTokens: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                m.URL,
			"authorization_endpoint":                m.URL + "/authorize",
			"token_endpoint":                        m.URL + "/token",
			"jwks_uri":                              m.URL + "/keys",
			"end_session_endpoint":                  m.URL + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			http.Error(w, "pkce required", http.StatusBadRequest)
			return
		}
		code := randomString()
		m.mu.Lock()
		m.nonces[code] = q.Get("nonce")
		m.lastAuthorize = q
		m.mu.Unlock()
		u, _ := url.Parse(q.Get("redirect_uri"))
		u.RawQuery = url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		m.mu.Lock()
		defer m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		invalidGrant := func(desc string) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": desc})
		}
		claims := map[string]any{
			"iss": m.URL, "aud": "client",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			nonce, ok := m.nonces[r.Form.Get("code")]
			delete(m.nonces, r.Form.Get("code"))
			if !ok || r.Form.Get("code_verifier") == "" {
				invalidGrant("unknown code")
				return
			}
			claims["nonce"] = nonce
		case "refresh_token":
			if m.down {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			rt := r.Form.Get("refresh_token")
			if m.disabled || !m.refreshTokens[rt] {
				invalidGrant("AADSTS50057: The user account is disabled.")
				return
			}
			delete(m.refreshTokens, rt) // rotate
		}
		for k, v := range m.claims {
			claims[k] = v
		}
		// Real refresh tokens (Entra ID's especially) are large; this one
		// forces the session to be split over several cookies.
		rt := "rt-" + randomString() + strings.Repeat("x", 6000)
		m.refreshTokens[rt] = true
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
			"refresh_token": rt,
			"id_token":      m.sign(t, claims),
		})
	})
	m.Server = httptest.NewServer(mux)
	t.Cleanup(m.Close)
	return m
}

func (m *mockIdP) sign(t *testing.T, claims map[string]any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: m.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := obj.CompactSerialize()
	return s
}

// newTestServer opens the configured database, seeds it from cfg and
// starts a server on it.
func newTestServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	st, err := store.Open(context.Background(), cfg.Database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.SeedFromConfig(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	srv, err := New(context.Background(), cfg, st, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

type env struct {
	idp      *mockIdP
	proxy    *httptest.Server
	srv      *Server
	upstream *httptest.Server
	client   *http.Client
}

// newEnv starts the proxy for domain test.local. The client resolves every
// *.test.local host to the proxy and keeps cookies like a browser.
func newEnv(t *testing.T, claims map[string]any) *env {
	t.Helper()
	idp := newMockIdP(t, claims)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			// An upstream that builds absolute URLs from its own Host.
			http.SetCookie(w, &http.Cookie{Name: "app", Value: "1", Domain: strings.Split(r.Host, ":")[0], Path: "/"})
			http.Redirect(w, r, "http://"+r.Host+"/target?x=1", http.StatusFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"host": r.Host, "path": r.URL.Path, "headers": r.Header})
	}))
	t.Cleanup(upstream.Close)

	// Reserve the listener first so publicURL can carry its port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	cfg, err := config.Parse([]byte(`
publicURL: http://portal.test.local:` + strconv.Itoa(port) + `
domain: test.local
session: {secret: "0123456789abcdef0123456789abcdef"}
oidc:
  issuer: "` + idp.URL + `"
  clientID: client
  clientSecret: secret
  mfa: {amr: [mfa], acr: [c1], authParams: {acr_values: mfa-please}}
database: {url: "sqlite:` + t.TempDir() + `/sidegate.db"}
admin: {groups: [g-root]}
groups: {admins: g-admins, devs: g-devs}
apps:
  - {name: whoami, title: Who Am I, upstream: "` + upstream.URL + `", allowedGroups: [devs]}
  - {name: admin, upstream: "` + upstream.URL + `", allowedGroups: [admins]}
  - {name: byuser, upstream: "` + upstream.URL + `", allowedUsers: [Alice@Example.com]}
  - {name: everyone, upstream: "` + upstream.URL + `", allowedGroups: ["*"], hidden: true}
  - {name: open, upstream: "` + upstream.URL + `", public: true}
  - {name: mixed, upstream: "` + upstream.URL + `", allowedGroups: [admins], publicPaths: [/health, /static/*]}
  - {name: rehost, upstream: "` + upstream.URL + `", allowedGroups: ["*"], hostHeader: "internal.example.com:8443"}
  - {name: passhost, upstream: "` + upstream.URL + `", allowedGroups: ["*"], passHostHeader: true}
  - {name: secure, upstream: "` + upstream.URL + `", allowedGroups: ["*"], requireMFA: true}
  - {name: fresh, upstream: "` + upstream.URL + `", allowedGroups: ["*"], maxAuthAgeMinutes: 1}
`))
	if err != nil {
		t.Fatal(err)
	}
	srv := newTestServer(t, cfg)
	proxy := httptest.NewUnstartedServer(srv.Handler())
	proxy.Listener.Close()
	proxy.Listener = ln
	proxy.Start()
	t.Cleanup(proxy.Close)

	jar, _ := cookiejar.New(nil)
	dialer := &net.Dialer{}
	client := &http.Client{
		Jar: jar,
		Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if host, p, _ := net.SplitHostPort(addr); strings.HasSuffix(host, ".test.local") {
				addr = net.JoinHostPort("127.0.0.1", p)
			}
			return dialer.DialContext(ctx, network, addr)
		}},
	}
	return &env{idp: idp, proxy: proxy, srv: srv, upstream: upstream, client: client}
}

func (e *env) url(host, path string) string {
	_, port, _ := net.SplitHostPort(e.proxy.Listener.Addr().String())
	return "http://" + host + ".test.local:" + port + path
}

func (e *env) get(t *testing.T, u string, hdr ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", u, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Add(hdr[i], hdr[i+1])
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

type echo struct {
	Host    string              `json:"host"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
}

var alice = map[string]any{
	"sub":                "alice-id",
	"email":              "alice@example.com",
	"name":               "Alice",
	"preferred_username": "alice@example.com",
	"groups":             []string{"g-devs", "g-unrelated"},
}

func TestLoginAndProxy(t *testing.T) {
	e := newEnv(t, alice)

	resp, body := e.get(t, e.url("whoami", "/some/path?x=1"))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var got echo
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("not proxied: %s", body)
	}
	if got.Path != "/some/path" {
		t.Errorf("path = %q, want /some/path (redirect must preserve the original URL)", got.Path)
	}

	// Signed in: identity headers are set, spoofed ones dropped.
	_, body = e.get(t, e.url("whoami", "/"),
		"X-Forwarded-Email", "mallory@example.com",
		"X_Forwarded_User", "mallory",
		"Cookie", "app=keep")
	got = echo{}
	json.Unmarshal([]byte(body), &got)
	h := http.Header(got.Headers)
	if v := h.Values("X-Forwarded-Email"); len(v) != 1 || v[0] != "alice@example.com" {
		t.Errorf("X-Forwarded-Email = %v", v)
	}
	if v := h.Get("X-Forwarded-User"); v != "alice@example.com" {
		t.Errorf("X-Forwarded-User = %q", v)
	}
	if _, ok := got.Headers["X_forwarded_user"]; ok {
		t.Error("underscore spoofing header reached upstream")
	}
	if v := h.Get("X-Forwarded-Groups"); v != "devs" {
		t.Errorf("X-Forwarded-Groups = %q, want only referenced groups by name", v)
	}
	if c := h.Get("Cookie"); strings.Contains(c, "_sidegate") || !strings.Contains(c, "app=keep") {
		t.Errorf("Cookie to upstream = %q", c)
	}

	// Signed in now: no redirect for another app the user may access.
	if resp, _ := e.get(t, e.url("byuser", "/")); resp.StatusCode != 200 {
		t.Errorf("allowedUsers app: status %d", resp.StatusCode)
	}
	if resp, _ := e.get(t, e.url("everyone", "/")); resp.StatusCode != 200 {
		t.Errorf("wildcard app: status %d", resp.StatusCode)
	}
	if resp, body := e.get(t, e.url("admin", "/")); resp.StatusCode != 403 || !strings.Contains(body, "Access denied") {
		t.Errorf("admin app: status %d", resp.StatusCode)
	}

	// Portal lists accessible, non-hidden apps only.
	_, body = e.get(t, e.url("portal", "/"))
	for _, want := range []string{"Who Am I", "byuser", "open"} {
		if !strings.Contains(body, want) {
			t.Errorf("portal missing %q", want)
		}
	}
	for _, unwanted := range []string{">admin<", "everyone"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("portal must not list %q", unwanted)
		}
	}

	// Logout clears the session for all subdomains.
	e.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, _ = e.post(t, "/oauth2/logout", nil, "Origin", e.srv.public.String())
	if resp.StatusCode != 302 {
		t.Fatalf("logout status %d", resp.StatusCode)
	}
	resp, _ = e.get(t, e.url("whoami", "/"))
	if resp.StatusCode != 302 || !strings.Contains(resp.Header.Get("Location"), "/oauth2/start") {
		t.Errorf("after logout: status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestUnauthenticated(t *testing.T) {
	e := newEnv(t, alice)
	e.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	if resp, _ := e.get(t, e.url("whoami", "/api"), "Sec-Fetch-Mode", "cors"); resp.StatusCode != 401 {
		t.Errorf("fetch without session: status %d, want 401", resp.StatusCode)
	}
	if resp, _ := e.get(t, e.url("nope", "/")); resp.StatusCode != 404 {
		t.Errorf("unknown app: status %d, want 404", resp.StatusCode)
	}
	resp, body := e.get(t, e.url("open", "/"), "X-Forwarded-User", "mallory")
	if resp.StatusCode != 200 || strings.Contains(body, "mallory") {
		t.Errorf("public app: status %d body %s", resp.StatusCode, body)
	}
	resp, _ = e.get(t, e.url("portal", "/oauth2/callback?state=abcdefghijkl&code=x"))
	if resp.StatusCode != 400 {
		t.Errorf("callback without state cookie: status %d, want 400", resp.StatusCode)
	}
}

func TestSafeRedirect(t *testing.T) {
	e := newEnv(t, alice)
	s := e.srv
	fallback := s.public.String() + "/"
	cases := map[string]string{
		"http://grafana.test.local/x":     "http://grafana.test.local/x",
		"http://evil.com/":                fallback,
		"http://test.local.evil.com/":     fallback,
		"https://grafana.test.local/":     fallback, // scheme mismatch
		"//grafana.test.local/":           fallback,
		"http://user@grafana.test.local/": fallback,
		"javascript:alert(1)":             fallback,
		"":                                fallback,
	}
	for in, want := range cases {
		if got := s.safeRedirect(in); got != want {
			t.Errorf("safeRedirect(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDatabaseChangesApplyWithoutRestart(t *testing.T) {
	e := newEnv(t, alice)
	if resp, _ := e.get(t, e.url("whoami", "/")); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}

	// Simulate another replica writing to the shared database.
	ctx := context.Background()
	if err := e.srv.store.DeleteApp(ctx, "test", "whoami"); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.store.CreateApp(ctx, "test", config.App{
		Name: "renamed", Subdomain: "renamed", Upstream: e.upstream.URL, AllowedGroups: []string{"*"},
	}); err != nil {
		t.Fatal(err)
	}
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go e.srv.Watch(watchCtx, 10*time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for e.srv.routes.Load().byName["renamed"] == nil {
		if time.Now().After(deadline) {
			t.Fatal("change in the database was not picked up")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if resp, _ := e.get(t, e.url("whoami", "/")); resp.StatusCode != 404 {
		t.Errorf("removed app: status %d, want 404", resp.StatusCode)
	}
	if resp, _ := e.get(t, e.url("renamed", "/")); resp.StatusCode != 200 {
		t.Errorf("new app with existing session: status %d", resp.StatusCode)
	}
}

func TestPublicPaths(t *testing.T) {
	e := newEnv(t, alice)
	e.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cases := map[string]int{
		"/health":               200,
		"/static/app.css":       200,
		"/static/":              200,
		"/static/a/b.js?v=1":    200,
		"/":                     401,
		"/health/":              401, // exact match only
		"/healthz":              401,
		"/static":               401,
		"/static/../secret":     401,
		"/static/./x":           401,
		"/static//x":            401,
		"/static/..;/secret":    401,
		"/static/;/x":           401,
		"/static/%2e%2e/secret": 401,
		"/static/..%2fsecret":   401,
		"/static/%252e%252e/x":  401,
		"/static/..%5csecret":   401,
		"/static/a%2Fb":         401,
	}
	for path, want := range cases {
		req, _ := http.NewRequest("GET", e.url("mixed", path), nil)
		req.Header.Set("Sec-Fetch-Mode", "cors") // get 401 instead of a login redirect
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s: status %d, want %d", path, resp.StatusCode, want)
		}
	}

	// Signed in without access: protected paths are denied, public ones still
	// work and carry the identity.
	e.client.CheckRedirect = nil
	if resp, _ := e.get(t, e.url("whoami", "/")); resp.StatusCode != 200 {
		t.Fatalf("login: status %d", resp.StatusCode)
	}
	if resp, _ := e.get(t, e.url("mixed", "/")); resp.StatusCode != 403 {
		t.Errorf("protected path for non-member: status %d, want 403", resp.StatusCode)
	}
	_, body := e.get(t, e.url("mixed", "/health"))
	if !strings.Contains(body, "alice@example.com") {
		t.Error("public path did not receive the identity of a signed-in user")
	}
}

func TestHostHeader(t *testing.T) {
	e := newEnv(t, alice)
	host := func(app string) string {
		_, body := e.get(t, e.url(app, "/"))
		var got echo
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatalf("%s: not proxied: %s", app, body)
		}
		return got.Host
	}
	if h := host("rehost"); h != "internal.example.com:8443" {
		t.Errorf("custom host header: %q", h)
	}
	if h := host("passhost"); !strings.HasPrefix(h, "passhost.test.local") {
		t.Errorf("original host header: %q", h)
	}
	if h := host("whoami"); !strings.HasPrefix(h, "127.0.0.1:") {
		t.Errorf("default host header: %q, want the upstream's", h)
	}
}
