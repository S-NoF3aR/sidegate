// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var root = map[string]any{
	"sub":                "root-id",
	"email":              "root@example.com",
	"preferred_username": "root@example.com",
	"groups":             []string{"g-root"},
}

var csrfField = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (e *env) csrf(t *testing.T) string {
	t.Helper()
	_, body := e.get(t, e.url("portal", "/admin/apps/new"))
	m := csrfField.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf token on admin page")
	}
	return m[1]
}

func (e *env) post(t *testing.T, path string, form url.Values, hdr ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", e.url("portal", path), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	resp.Body.Close()
	return resp, b.String()
}

func TestAdminRequiresAdminGroup(t *testing.T) {
	e := newEnv(t, alice)
	if resp, body := e.get(t, e.url("portal", "/admin")); resp.StatusCode != 403 || !strings.Contains(body, "Admin access required") {
		t.Errorf("non-admin: status %d", resp.StatusCode)
	}
	if _, body := e.get(t, e.url("portal", "/")); strings.Contains(body, "/admin") {
		t.Error("portal shows the admin link to a non-admin")
	}
}

func TestAdminManagesApps(t *testing.T) {
	e := newEnv(t, root)
	resp, body := e.get(t, e.url("portal", "/admin"))
	if resp.StatusCode != 200 || !strings.Contains(body, "whoami.test.local") {
		t.Fatalf("admin page: status %d", resp.StatusCode)
	}
	token := e.csrf(t)

	form := url.Values{
		"csrf": {token}, "name": {"newapp"}, "title": {"New App"},
		"upstream": {e.upstream.URL}, "allUsers": {"on"},
	}

	// CSRF protections.
	noToken := url.Values{}
	for k, v := range form {
		if k != "csrf" {
			noToken[k] = v
		}
	}
	if resp, _ := e.post(t, "/admin/apps", noToken); resp.StatusCode != 403 {
		t.Errorf("without csrf token: status %d, want 403", resp.StatusCode)
	}
	if resp, _ := e.post(t, "/admin/apps", form, "Origin", "http://evil.test.local"); resp.StatusCode != 403 {
		t.Errorf("cross-origin post: status %d, want 403", resp.StatusCode)
	}

	// Validation errors are shown on the form.
	bad := url.Values{"csrf": {token}, "name": {"bad"}, "upstream": {"not a url"}}
	if resp, body := e.post(t, "/admin/apps", bad); resp.StatusCode != 400 || !strings.Contains(body, "upstream must be an absolute") {
		t.Errorf("invalid app: status %d", resp.StatusCode)
	}
	dup := url.Values{"csrf": {token}, "name": {"dup"}, "subdomain": {"whoami"}, "upstream": {e.upstream.URL}, "public": {"on"}}
	if resp, body := e.post(t, "/admin/apps", dup); resp.StatusCode != 400 || !strings.Contains(body, "already used by app") {
		t.Errorf("duplicate subdomain: status %d", resp.StatusCode)
	}

	// Create, then use the app right away.
	resp, body = e.post(t, "/admin/apps", form)
	if resp.StatusCode != 200 || !strings.Contains(body, "Saved newapp") {
		t.Fatalf("create: status %d", resp.StatusCode)
	}
	if resp, _ := e.get(t, e.url("newapp", "/")); resp.StatusCode != 200 {
		t.Errorf("new app: status %d", resp.StatusCode)
	}

	// Name a group, restrict the app to it, and the admin loses access.
	if resp, _ := e.post(t, "/admin/groups", url.Values{"csrf": {token}, "name": {"ops"}, "id": {"g-ops"}}); resp.StatusCode != 200 {
		t.Fatalf("save group: status %d", resp.StatusCode)
	}
	_, body = e.get(t, e.url("portal", "/admin/apps/newapp"))
	if !strings.Contains(body, `value="g-ops"`) {
		t.Error("named group not offered on the app form")
	}
	update := url.Values{"csrf": {token}, "upstream": {e.upstream.URL}, "extraGroups": {"ops"}}
	if resp, _ := e.post(t, "/admin/apps/newapp", update); resp.StatusCode != 200 {
		t.Fatalf("update: status %d", resp.StatusCode)
	}
	if got := e.srv.routes.Load().byName["newapp"].AllowedGroups; len(got) != 1 || got[0] != "g-ops" {
		t.Errorf("group name not resolved to ID: %v", got)
	}
	if resp, _ := e.get(t, e.url("newapp", "/")); resp.StatusCode != 403 {
		t.Errorf("after restricting: status %d, want 403", resp.StatusCode)
	}

	// Delete.
	if resp, body := e.post(t, "/admin/apps/newapp/delete", url.Values{"csrf": {token}}); resp.StatusCode != 200 || !strings.Contains(body, "Deleted newapp") {
		t.Errorf("delete: status %d", resp.StatusCode)
	}
	if resp, _ := e.get(t, e.url("newapp", "/")); resp.StatusCode != 404 {
		t.Errorf("deleted app: status %d, want 404", resp.StatusCode)
	}

	_, body = e.get(t, e.url("portal", "/admin/audit"))
	for _, want := range []string{"app.create", "app.update", "app.delete", "group.save", "root@example.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("audit log missing %q", want)
		}
	}
}
