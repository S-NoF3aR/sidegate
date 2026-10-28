// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var tokenValue = regexp.MustCompile(`value="(sgt_[A-Za-z0-9_-]+)"`)

// createToken signs in as an admin and creates an API token in the UI.
func (e *env) createToken(t *testing.T, name string) string {
	t.Helper()
	resp, body := e.post(t, "/admin/tokens", url.Values{"csrf": {e.csrf(t)}, "name": {name}})
	m := tokenValue.FindStringSubmatch(body)
	if resp.StatusCode != 200 || m == nil {
		t.Fatalf("create token: status %d", resp.StatusCode)
	}
	return m[1]
}

func (e *env) api(t *testing.T, token, method, path, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, e.url("portal", "/api/v1"+path), strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	// A plain client: the API must not depend on cookies.
	client := &http.Client{Transport: e.client.Transport}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAPI(t *testing.T) {
	e := newEnv(t, root)
	token := e.createToken(t, "terraform")

	// Authentication.
	for _, tok := range []string{"", "sgt_wrong", "not-a-token"} {
		if status, _ := e.api(t, tok, "GET", "/apps", ""); status != 401 {
			t.Errorf("token %q: status %d, want 401", tok, status)
		}
	}
	status, body := e.api(t, token, "GET", "/apps", "")
	if status != 200 || !strings.Contains(body, `"name":"whoami"`) {
		t.Fatalf("list apps: %d %s", status, body)
	}

	// Create.
	status, body = e.api(t, token, "POST", "/apps", `{"name":"api-app","upstream":"`+e.upstream.URL+`",
		"allowedGroups":["g-b","g-a","g-a"],"publicPaths":["/health"],"hostHeader":"internal.example.com"}`)
	if status != 201 {
		t.Fatalf("create: %d %s", status, body)
	}
	var got apiApp
	json.Unmarshal([]byte(body), &got)
	if got.Subdomain != "api-app" || strings.Join(got.AllowedGroups, ",") != "g-a,g-b" || got.AllowedUsers == nil ||
		!strings.HasPrefix(got.URL, "http://api-app.test.local") {
		t.Errorf("created app = %+v", got)
	}
	if e.srv.routes.Load().byName["api-app"] == nil {
		t.Error("created app not routed")
	}

	// Errors.
	if status, body := e.api(t, token, "POST", "/apps", `{"name":"api-app","upstream":"http://x","public":true}`); status != 409 {
		t.Errorf("duplicate: %d %s", status, body)
	}
	status, body = e.api(t, token, "POST", "/apps", `{"name":"bad","upstream":"nope","publicPaths":["/a/../b"]}`)
	if status != 400 || !strings.Contains(body, `"details"`) || !strings.Contains(body, "upstream") || !strings.Contains(body, "public path") {
		t.Errorf("invalid: %d %s", status, body)
	}
	if status, _ := e.api(t, token, "POST", "/apps", `{"name":"x","bogus":1}`); status != 400 {
		t.Errorf("unknown field: %d", status)
	}
	if status, _ := e.api(t, token, "GET", "/apps/missing", ""); status != 404 {
		t.Errorf("get missing: %d", status)
	}
	if status, _ := e.api(t, token, "PUT", "/apps/missing", `{"upstream":"http://x","public":true}`); status != 404 {
		t.Errorf("update missing: %d", status)
	}
	if status, _ := e.api(t, token, "PUT", "/apps/api-app", `{"name":"other","upstream":"http://x","public":true}`); status != 400 {
		t.Errorf("rename: %d", status)
	}

	// Update replaces the whole app.
	status, body = e.api(t, token, "PUT", "/apps/api-app", `{"upstream":"`+e.upstream.URL+`","public":true,"title":"API"}`)
	json.Unmarshal([]byte(body), &got)
	if status != 200 || !got.Public || got.Title != "API" || len(got.AllowedGroups) != 0 || got.HostHeader != "" {
		t.Errorf("update: %d %+v", status, got)
	}
	if status, _ := e.api(t, token, "GET", "/apps/api-app", ""); status != 200 {
		t.Errorf("get: %d", status)
	}

	// Groups, including IDs with slashes.
	if status, body := e.api(t, token, "PUT", "/groups/"+url.PathEscape("/kc/admins"), `{"name":"kc-admins"}`); status != 200 {
		t.Errorf("put group: %d %s", status, body)
	}
	status, body = e.api(t, token, "GET", "/groups/"+url.PathEscape("/kc/admins"), "")
	if status != 200 || !strings.Contains(body, `"name":"kc-admins"`) {
		t.Errorf("get group: %d %s", status, body)
	}
	if status, _ := e.api(t, token, "PUT", "/groups/g2", `{"name":"kc-admins"}`); status != 409 {
		t.Errorf("duplicate group name: %d", status)
	}
	if status, _ := e.api(t, token, "DELETE", "/groups/"+url.PathEscape("/kc/admins"), ""); status != 204 {
		t.Errorf("delete group: %d", status)
	}

	// Delete.
	if status, _ := e.api(t, token, "DELETE", "/apps/api-app", ""); status != 204 {
		t.Errorf("delete: %d", status)
	}
	if status, _ := e.api(t, token, "DELETE", "/apps/api-app", ""); status != 404 {
		t.Errorf("delete twice: %d", status)
	}

	_, audit := e.get(t, e.url("portal", "/admin/audit"))
	if !strings.Contains(audit, "token:terraform") {
		t.Error("audit log does not name the token")
	}

	// Revoked tokens stop working immediately.
	_, page := e.get(t, e.url("portal", "/admin/tokens"))
	id := regexp.MustCompile(`name="id" value="([0-9a-f]+)"`).FindStringSubmatch(page)
	if id == nil {
		t.Fatal("token not listed")
	}
	if strings.Contains(page, token) {
		t.Error("token secret shown again on the tokens page")
	}
	e.post(t, "/admin/tokens/delete", url.Values{"csrf": {e.csrf(t)}, "id": {id[1]}})
	if status, _ := e.api(t, token, "GET", "/apps", ""); status != 401 {
		t.Errorf("revoked token: status %d, want 401", status)
	}
}

func TestAPITokensRequireAdmin(t *testing.T) {
	e := newEnv(t, alice)
	if resp, _ := e.get(t, e.url("portal", "/admin/tokens")); resp.StatusCode != 403 {
		t.Errorf("non-admin token page: status %d", resp.StatusCode)
	}
	// A session cookie alone must not authorize the API.
	e.get(t, e.url("whoami", "/"))
	if resp, _ := e.get(t, e.url("portal", "/api/v1/apps")); resp.StatusCode != 401 {
		t.Errorf("api with session cookie only: status %d, want 401", resp.StatusCode)
	}
}
