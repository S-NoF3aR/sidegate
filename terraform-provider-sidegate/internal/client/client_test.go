// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClient(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.EscapedPath(), r.Header.Get("Authorization")
		switch {
		case strings.HasSuffix(r.URL.Path, "/missing"):
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"app \"missing\" not found"}`))
		case r.Method == "POST":
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"validation failed","details":["a","b"]}`))
		default:
			w.Write([]byte(`{"id":"/kc/admins","name":"admins"}`))
		}
	}))
	defer srv.Close()
	c := New(srv.URL+"/", "sgt_t", "test")
	ctx := context.Background()

	g, err := c.GetGroup(ctx, "/kc/admins")
	if err != nil || g.Name != "admins" {
		t.Fatalf("get group: %v %+v", err, g)
	}
	if gotPath != "/api/v1/groups/%2Fkc%2Fadmins" || gotAuth != "Bearer sgt_t" {
		t.Errorf("request: path %q auth %q", gotPath, gotAuth)
	}

	if _, err := c.GetApp(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("404 should be ErrNotFound: %v", err)
	}
	_, err = c.CreateApp(ctx, App{Name: "x"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 400 || len(apiErr.Details) != 2 || errors.Is(err, ErrNotFound) {
		t.Errorf("validation error: %v", err)
	}
	if !strings.Contains(err.Error(), "  - a") {
		t.Errorf("details missing from message: %q", err.Error())
	}
}
