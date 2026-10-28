// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"sidegate/internal/config"
	"sidegate/internal/store"
)

func noRedirects(e *env) {
	e.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
}

func TestRevokeSessions(t *testing.T) {
	e := newEnv(t, alice)
	ctx := context.Background()
	if resp, _ := e.get(t, e.url("whoami", "/")); resp.StatusCode != 200 {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	users, _ := e.srv.store.Users(ctx)
	if len(users) != 1 || users[0].Subject != "alice-id" || users[0].Email != "alice@example.com" || users[0].Logins != 1 {
		t.Errorf("recorded users = %+v", users)
	}

	// Per user.
	if err := e.srv.store.RevokeSessions(ctx, "test", "alice-id"); err != nil {
		t.Fatal(err)
	}
	e.srv.Sync(ctx)
	noRedirects(e)
	if resp, _ := e.get(t, e.url("whoami", "/")); resp.StatusCode != 302 {
		t.Errorf("revoked session: status %d, want redirect to login", resp.StatusCode)
	}
	// Signing in again works.
	e.client.CheckRedirect = nil
	if resp, _ := e.get(t, e.url("whoami", "/")); resp.StatusCode != 200 {
		t.Errorf("sign in after revocation: %d", resp.StatusCode)
	}

	// Everyone.
	if err := e.srv.store.RevokeAllSessions(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	e.srv.Sync(ctx)
	resp, _ := e.get(t, e.url("portal", "/api/me"))
	if resp.StatusCode != 401 {
		t.Errorf("after revoke-all: /api/me status %d, want 401", resp.StatusCode)
	}
}

func TestAdminUsersPage(t *testing.T) {
	e := newEnv(t, root)
	_, page := e.get(t, e.url("portal", "/admin/users"))
	if !strings.Contains(page, "root-id") {
		t.Fatal("signed-in user not listed")
	}
	token := e.createToken(t, "offboarding")
	if status, body := e.api(t, token, "GET", "/users", ""); status != 200 || !strings.Contains(body, `"subject":"root-id"`) {
		t.Errorf("api users: %d %s", status, body)
	}
	if status, _ := e.api(t, token, "POST", "/sessions/revoke", `{"subject":"someone-else"}`); status != 204 {
		t.Errorf("api revoke: %d", status)
	}
	// Revoking yourself through the UI ends your own session.
	csrf := e.csrf(t)
	noRedirects(e)
	if resp, _ := e.post(t, "/admin/users/revoke", url.Values{"csrf": {csrf}, "subject": {"root-id"}, "label": {"root"}}); resp.StatusCode != 303 {
		t.Fatalf("revoke: status %d", resp.StatusCode)
	}
	if resp, _ := e.get(t, e.url("portal", "/admin/users")); resp.StatusCode != 302 {
		t.Errorf("own session after self-revoke: status %d, want redirect", resp.StatusCode)
	}
}

func TestMetrics(t *testing.T) {
	e := newEnv(t, alice)
	e.get(t, e.url("whoami", "/"))
	e.get(t, e.url("admin", "/"))
	rec := httptest.NewRecorder()
	e.srv.MetricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`sidegate_requests_total{app="whoami",code="200",method="GET"} 1`,
		`sidegate_access_denied_total{app="admin",reason="forbidden"} 1`,
		`sidegate_access_denied_total{app="whoami",reason="unauthenticated"} 1`,
		`sidegate_logins_total{result="success"} 1`,
		`sidegate_apps 10`,
		`sidegate_request_duration_seconds_bucket{app="_portal"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}

func TestJWTAssertion(t *testing.T) {
	e := newEnv(t, alice)
	_, body := e.get(t, e.url("whoami", "/"), "X-Sidegate-Jwt-Assertion", "forged")
	var got echo
	json.Unmarshal([]byte(body), &got)
	raw := http.Header(got.Headers).Values(jwtHeader)
	if len(raw) != 1 || raw[0] == "forged" {
		t.Fatalf("assertion header = %v", raw)
	}

	_, jwks := e.get(t, e.url("portal", "/.well-known/jwks.json"))
	var set jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(jwks), &set); err != nil || len(set.Keys) != 1 {
		t.Fatalf("jwks: %v %s", err, jwks)
	}
	tok, err := jose.ParseSigned(raw[0], []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := tok.Verify(set.Keys[0])
	if err != nil {
		t.Fatalf("signature does not verify against the published key: %v", err)
	}
	var claims map[string]any
	json.Unmarshal(payload, &claims)
	if claims["sub"] != "alice-id" || claims["email"] != "alice@example.com" ||
		!strings.HasPrefix(claims["aud"].(string), "http://whoami.test.local:") || strings.HasSuffix(claims["aud"].(string), "/") ||
		claims["iss"] != e.srv.public.String() {
		t.Errorf("claims = %v", claims)
	}
	if g, _ := claims["groups"].([]any); len(g) != 1 || g[0] != "devs" {
		t.Errorf("groups claim = %v", claims["groups"])
	}

	// Every replica derives the same key from the shared secret.
	a, _ := newJWTSigner("0123456789abcdef0123456789abcdef")
	b, _ := newJWTSigner("0123456789abcdef0123456789abcdef")
	c, _ := newJWTSigner("another-secret-another-secret-xx")
	if string(a.jwks) != string(b.jwks) || string(a.jwks) == string(c.jwks) {
		t.Error("signing key derivation is not deterministic per secret")
	}
}

func TestRewriteInternalRedirects(t *testing.T) {
	e := newEnv(t, alice)
	e.get(t, e.url("whoami", "/")) // sign in
	noRedirects(e)
	for app, wantCookieDomain := range map[string]bool{"rehost": false, "whoami": false} {
		resp, _ := e.get(t, e.url(app, "/redirect"))
		loc := resp.Header.Get("Location")
		if !strings.HasPrefix(loc, "http://"+app+".test.local:") || !strings.HasSuffix(loc, "/target?x=1") {
			t.Errorf("%s: Location = %q, want the public host", app, loc)
		}
		if c := resp.Header.Get("Set-Cookie"); strings.Contains(strings.ToLower(c), "domain=") != wantCookieDomain {
			t.Errorf("%s: Set-Cookie = %q, internal Domain should be dropped", app, c)
		}
	}

	// Unit cases: unrelated hosts and relative URLs stay untouched.
	internal := map[string]bool{"internal.example.com": true}
	for in, want := range map[string]string{
		"https://internal.example.com/a": "https://app.example.com/a",
		"https://other.example.com/a":    "https://other.example.com/a",
		"/relative":                      "/relative",
	} {
		resp := &http.Response{Header: http.Header{"Location": {in}}, Request: &http.Request{Header: http.Header{"X-Forwarded-Host": {"app.example.com"}}}}
		rewriteInternalHost(resp, internal, "https")
		if got := resp.Header.Get("Location"); got != want {
			t.Errorf("rewrite %q = %q, want %q", in, got, want)
		}
	}
	resp := &http.Response{
		Header:  http.Header{"Set-Cookie": {"a=1; Domain=.internal.example.com; Path=/; HttpOnly", "b=2; Domain=example.org"}},
		Request: &http.Request{Header: http.Header{"X-Forwarded-Host": {"app.example.com"}}},
	}
	rewriteInternalHost(resp, internal, "https")
	if got := resp.Header.Values("Set-Cookie"); got[0] != "a=1; Path=/; HttpOnly" || got[1] != "b=2; Domain=example.org" {
		t.Errorf("cookies = %q", got)
	}
}

func TestStepUpMFA(t *testing.T) {
	e := newEnv(t, alice)
	e.get(t, e.url("whoami", "/")) // sign in without MFA

	// The IdP doesn't confirm MFA: an error page, not a redirect loop.
	resp, body := e.get(t, e.url("secure", "/"))
	if resp.StatusCode != 403 || !strings.Contains(body, "Multi-factor authentication required") {
		t.Fatalf("step-up without MFA: %d", resp.StatusCode)
	}
	e.idp.mu.Lock()
	q := e.idp.lastAuthorize
	e.idp.mu.Unlock()
	if q.Get("acr_values") != "mfa-please" {
		t.Errorf("step-up request lacks the configured auth params: %v", q)
	}

	// API calls get a 401 instead of a redirect.
	req, _ := http.NewRequest("GET", e.url("secure", "/api"), nil)
	req.Header.Set("Sec-Fetch-Mode", "cors")
	r2, _ := e.client.Do(req)
	b, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if r2.StatusCode != 401 || !strings.Contains(string(b), "step-up") {
		t.Errorf("fetch needing step-up: %d %s", r2.StatusCode, b)
	}

	// With MFA (here via Entra's acrs claim) the step-up succeeds.
	e.idp.set(func(m *mockIdP) { m.claims["acrs"] = []string{"c1"} })
	if resp, _ := e.get(t, e.url("secure", "/")); resp.StatusCode != 200 {
		t.Errorf("after MFA step-up: %d", resp.StatusCode)
	}
	_, me := e.get(t, e.url("secure", "/"))
	if !strings.Contains(me, "X-Sidegate-Jwt-Assertion") {
		t.Error("no assertion after step-up")
	}
}

func TestMaxAuthAge(t *testing.T) {
	e := newEnv(t, alice)
	old := time.Now().Add(-time.Hour).Unix()
	e.idp.set(func(m *mockIdP) { m.claims["auth_time"] = old })
	e.get(t, e.url("whoami", "/")) // signed in an hour ago, per the IdP

	// The IdP keeps reporting the old authentication: error, no loop.
	resp, body := e.get(t, e.url("fresh", "/"))
	if resp.StatusCode != 403 || !strings.Contains(body, "Fresh sign-in required") {
		t.Fatalf("stale re-auth: %d", resp.StatusCode)
	}
	e.idp.mu.Lock()
	q := e.idp.lastAuthorize
	e.idp.mu.Unlock()
	if q.Get("max_age") != "60" || q.Get("prompt") != "login" {
		t.Errorf("re-auth request = %v", q)
	}

	e.idp.set(func(m *mockIdP) { m.claims["auth_time"] = time.Now().Unix() })
	if resp, _ := e.get(t, e.url("fresh", "/")); resp.StatusCode != 200 {
		t.Errorf("after fresh sign-in: %d", resp.StatusCode)
	}
}

// Without auth_time the IdP may have reused an old sign-in, so the sign-in
// age is unknown and age-restricted apps stay closed.
func TestMissingAuthTime(t *testing.T) {
	e := newEnv(t, alice) // no auth_time
	if resp, _ := e.get(t, e.url("whoami", "/")); resp.StatusCode != 200 {
		t.Fatalf("app without age limit: %d", resp.StatusCode)
	}
	resp, body := e.get(t, e.url("fresh", "/"))
	if resp.StatusCode != 403 || !strings.Contains(body, "didn&#39;t confirm when you signed in") {
		t.Errorf("age-restricted app: %d %s", resp.StatusCode, body)
	}
	// Nor is an auth_time in the future believed.
	e.idp.set(func(m *mockIdP) { m.claims["auth_time"] = time.Now().Add(time.Hour).Unix() })
	if resp, _ := e.get(t, e.url("fresh", "/")); resp.StatusCode != 403 {
		t.Errorf("future auth_time: %d", resp.StatusCode)
	}
}

func TestAuditRetention(t *testing.T) {
	e := newEnv(t, root)
	ctx := context.Background()
	e.srv.store.SaveGroup(ctx, "test", store.Group{ID: "g9", Name: "nine"})
	count := func() int {
		audit, _ := e.srv.store.Audit(ctx, 100)
		return len(audit)
	}
	before := count()
	if before == 0 {
		t.Fatal("no audit entries")
	}
	// Retention 0 keeps everything.
	zero := 0
	e.srv.cfg.Audit.RetentionDays = &zero
	e.srv.pruneAudit(ctx, time.Now().AddDate(10, 0, 0))
	if count() != before {
		t.Error("retention 0 pruned entries")
	}
	// The default (365 days): recent entries stay, old ones go.
	days := 365
	e.srv.cfg.Audit.RetentionDays = &days
	e.srv.pruneAudit(ctx, time.Now())
	if count() != before {
		t.Error("recent entries pruned")
	}
	e.srv.pruneAudit(ctx, time.Now().AddDate(0, 0, 366))
	if count() != 0 {
		t.Errorf("entries past retention kept: %d", count())
	}
}

func TestUpstreamCannotSetProxyCookies(t *testing.T) {
	e := newEnv(t, alice)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Add("Set-Cookie", "_sidegate=attacker; Domain=test.local; Path=/")
		h.Add("Set-Cookie", "_sidegate_1=x; Path=/")
		h.Add("Set-Cookie", "_sidegate_oauth_abcdefgh=x; Path=/")
		h.Add("Set-Cookie", "app_session=fine; Path=/")
		h.Set("Strict-Transport-Security", "max-age=0")
	}))
	defer upstream.Close()
	addRDPApp(t, e, config.App{Name: "evil", Upstream: upstream.URL, Public: true})

	resp, _ := e.get(t, e.url("evil", "/"))
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) != 1 || !strings.HasPrefix(cookies[0], "app_session=") {
		t.Errorf("Set-Cookie from upstream = %q, want only app_session", cookies)
	}

	// With https, the proxy's HSTS policy applies and the app can't weaken it.
	e.srv.secure = true
	resp, _ = e.get(t, e.url("evil", "/"))
	if got := resp.Header.Values("Strict-Transport-Security"); len(got) != 1 || got[0] != "max-age=31536000; includeSubDomains" {
		t.Errorf("HSTS on app = %q", got)
	}
	resp, _ = e.get(t, e.url("portal", "/healthz"))
	if resp.Header.Get("Strict-Transport-Security") == "" {
		t.Error("no HSTS on the portal")
	}
}

func TestUnverifiedEmailGrantsNothing(t *testing.T) {
	claims := maps.Clone(alice)
	claims["email_verified"] = false
	claims["preferred_username"] = "alice"
	claims["groups"] = []string{}
	e := newEnv(t, claims)
	// byuser allows Alice@Example.com; an unverified email must not match.
	if resp, _ := e.get(t, e.url("byuser", "/")); resp.StatusCode != http.StatusForbidden {
		t.Errorf("unverified email: %d, want 403", resp.StatusCode)
	}
	// sub: entries match the subject.
	addRDPApp(t, e, config.App{Name: "bysub", Upstream: "http://127.0.0.1:1", AllowedUsers: []string{"sub:alice-id"}})
	addRDPApp(t, e, config.App{Name: "bysubcase", Upstream: "http://127.0.0.1:1", AllowedUsers: []string{"sub:ALICE-ID"}})
	if resp, _ := e.get(t, e.url("bysub", "/")); resp.StatusCode == http.StatusForbidden {
		t.Error("sub: entry didn't match")
	}
	if resp, _ := e.get(t, e.url("bysubcase", "/")); resp.StatusCode != http.StatusForbidden {
		t.Error("sub: entries must match case-sensitively")
	}
}

func TestLogoutNeedsPostFromOwnSite(t *testing.T) {
	e := newEnv(t, alice)
	e.get(t, e.url("whoami", "/")) // signs in
	noRedirects(e)
	signedIn := func() bool {
		resp, _ := e.get(t, e.url("whoami", "/"))
		return resp.StatusCode == 200
	}
	if !signedIn() {
		t.Fatal("not signed in")
	}
	// A link or image to /oauth2/logout only shows a confirmation.
	if resp, body := e.get(t, e.url("portal", "/oauth2/logout")); resp.StatusCode != 200 || !strings.Contains(body, `<form method="post"`) || !signedIn() {
		t.Errorf("GET logout: %d, signed in: %v", resp.StatusCode, signedIn())
	}
	// Other sites can't post it.
	if resp, _ := e.post(t, "/oauth2/logout", nil, "Origin", "https://evil.example"); resp.StatusCode != 403 || !signedIn() {
		t.Errorf("cross-site logout: %d", resp.StatusCode)
	}
	// App hosts (whose pages show a Sign out button) and the portal can.
	if resp, _ := e.post(t, "/oauth2/logout", nil, "Origin", strings.TrimSuffix(e.url("whoami", ""), "/")); resp.StatusCode != 302 || signedIn() {
		t.Errorf("logout from an app host: %d", resp.StatusCode)
	}
}

func TestNoReflectedText(t *testing.T) {
	e := newEnv(t, root)
	_, body := e.get(t, e.url("portal", "/oauth2/callback?error=access_denied&error_description=Call+support+at+555-0100"))
	if strings.Contains(body, "555-0100") || !strings.Contains(body, "(access_denied)") {
		t.Errorf("callback error page echoes the description")
	}
	_, body = e.get(t, e.url("portal", "/oauth2/callback?error=Call+support+now"))
	if strings.Contains(body, "Call support") {
		t.Errorf("callback error page echoes a free-text error")
	}
	_, body = e.get(t, e.url("portal", "/admin?saved=Your+account+is+locked"))
	if strings.Contains(body, "account is locked") {
		t.Errorf("admin notice echoes free text")
	}
	_, body = e.get(t, e.url("portal", "/admin?saved=grafana"))
	if !strings.Contains(body, "Saved grafana.") {
		t.Errorf("admin notice lost the app name")
	}
}

func TestStaticHasNoListing(t *testing.T) {
	e := newEnv(t, alice)
	if resp, _ := e.get(t, e.url("portal", "/static/")); resp.StatusCode != 404 {
		t.Errorf("/static/: %d, want 404", resp.StatusCode)
	}
	if resp, _ := e.get(t, e.url("portal", "/static/vendor/")); resp.StatusCode != 404 {
		t.Errorf("/static/vendor/: %d, want 404", resp.StatusCode)
	}
	if resp, _ := e.get(t, e.url("portal", "/static/style.css")); resp.StatusCode != 200 {
		t.Errorf("/static/style.css: %d", resp.StatusCode)
	}
}

func TestCLILoginNeedsChallenge(t *testing.T) {
	e := newEnv(t, alice)
	q := url.Values{"port": {"15555"}, "state": {"0123456789abcdefXYZ"}}
	if resp, _ := e.get(t, e.url("portal", "/cli/login?"+q.Encode())); resp.StatusCode != 400 {
		t.Errorf("CLI sign-in without PKCE challenge: %d, want 400", resp.StatusCode)
	}
}
