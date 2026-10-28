// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sidegate/internal/session"
)

func TestRefreshRevalidatesSession(t *testing.T) {

	e := newEnv(t, alice)
	e.srv.refreshes.ttl = 0   // no reuse of results between sequential requests
	e.srv.refreshInterval = 0 // revalidate on every request

	resp, body := e.get(t, e.url("whoami", "/"))
	if resp.StatusCode != 200 {
		t.Fatalf("login: status %d", resp.StatusCode)
	}
	if strings.Contains(body, "_sidegate") {
		t.Error("session cookie chunks reached the upstream")
	}
	u, _ := url.Parse(e.url("whoami", "/"))
	names := map[string]bool{}
	for _, c := range e.client.Jar.Cookies(u) {
		names[c.Name] = true
	}
	if !names["_sidegate"] || !names["_sidegate_1"] {
		t.Errorf("expected a chunked session cookie, got %v", names)
	}

	// Group change at the IdP applies on the next refresh.
	e.idp.set(func(m *mockIdP) { m.claims["groups"] = []string{"g-admins"} })
	if resp, _ := e.get(t, e.url("admin", "/")); resp.StatusCode != 200 {
		t.Errorf("after adding admin group: status %d, want 200", resp.StatusCode)
	}
	if resp, _ := e.get(t, e.url("whoami", "/")); resp.StatusCode != 403 {
		t.Errorf("after removing devs group: status %d, want 403", resp.StatusCode)
	}

	// An unreachable IdP must not sign everybody out.
	e.idp.set(func(m *mockIdP) { m.down = true })
	if resp, _ := e.get(t, e.url("admin", "/")); resp.StatusCode != 200 {
		t.Errorf("IdP down: status %d, want 200", resp.StatusCode)
	}
	e.idp.set(func(m *mockIdP) { m.down = false })

	// Disabling the user ends the session.
	e.idp.set(func(m *mockIdP) { m.disabled = true })
	e.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, _ = e.get(t, e.url("admin", "/"))
	if resp.StatusCode != 302 || !strings.Contains(resp.Header.Get("Location"), "/oauth2/start") {
		t.Errorf("disabled user: status %d location %q, want redirect to login", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, c := range e.client.Jar.Cookies(u) {
		if strings.HasPrefix(c.Name, "_sidegate") {
			t.Errorf("cookie %s not cleared after revocation", c.Name)
		}
	}
	if resp, _ := e.get(t, e.url("portal", "/api/me")); resp.StatusCode != 401 {
		t.Errorf("api after revocation: status %d, want 401", resp.StatusCode)
	}
}

func TestRefreshGroupDeduplicates(t *testing.T) {
	var g refreshGroup
	var calls atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess, err := g.do("k", func() (*session.Session, error) {
				calls.Add(1)
				time.Sleep(50 * time.Millisecond)
				return &session.Session{Subject: "s"}, nil
			})
			if err != nil || sess.Subject != "s" {
				t.Errorf("got %v, %v", sess, err)
			}
		}()
	}
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Errorf("refresh ran %d times, want 1", n)
	}
}
