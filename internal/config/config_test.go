// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"strings"
	"testing"
)

const base = `
publicURL: https://apps.example.com
domain: example.com
session: {secret: "${TEST_SECRET}"}
oidc: {issuer: https://idp.example.com, clientID: c}
database: {url: "sqlite:/tmp/test.db"}
`

func TestParseExpandsEnvAndDefaults(t *testing.T) {
	t.Setenv("TEST_SECRET", strings.Repeat("s", 32))
	cfg, err := Parse([]byte(base + `
apps:
  - {name: Grafana, upstream: "http://grafana:3000", allowedGroups: ["*"]}
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Session.Secret != strings.Repeat("s", 32) {
		t.Error("secret not expanded from environment")
	}
	if cfg.Apps[0].Subdomain != "grafana" || cfg.Listen != ":8080" || cfg.OIDC.GroupsClaim != "groups" {
		t.Errorf("defaults not applied: %+v", cfg)
	}
}

func TestValidate(t *testing.T) {
	t.Setenv("TEST_SECRET", strings.Repeat("s", 32))
	cases := map[string]string{
		"no access rule":   `apps: [{name: a, upstream: "http://a"}]`,
		"bad upstream":     `apps: [{name: a, upstream: "a:80", public: true}]`,
		"duplicate":        `apps: [{name: a, upstream: "http://a", public: true}, {name: b, subdomain: a, upstream: "http://b", public: true}]`,
		"portal collision": `apps: [{name: apps, upstream: "http://a", public: true}]`,
		"bad label":        `apps: [{name: "a.b", upstream: "http://a", public: true}]`,
		"unknown field":    `bogus: true`,
	}
	for name, extra := range cases {
		if _, err := Parse([]byte(base + extra)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	t.Setenv("TEST_SECRET", "short")
	if _, err := Parse([]byte(base)); err == nil {
		t.Error("short secret: expected error")
	}
}

func TestPublicPathAndHostValidation(t *testing.T) {
	valid := []string{"/health", "/static/*", "/api/public/", "/a-b_c.txt", "/v1*"}
	invalid := []string{"health", "/*", "*", "/a*b", "/static/../x", "/./x", "//x", "/a;b", "/a%2f", "/a\\b", "/a b", "/a?x"}
	for _, p := range valid {
		if !ValidPublicPath(p) {
			t.Errorf("%q should be valid", p)
		}
	}
	for _, p := range invalid {
		if ValidPublicPath(p) {
			t.Errorf("%q should be invalid", p)
		}
	}

	app := func(mod func(a *App)) error {
		a := App{Name: "a", Subdomain: "a", Upstream: "http://a", Public: true}
		mod(&a)
		return a.Validate("example.com", "apps.example.com")
	}
	if err := app(func(a *App) { a.HostHeader = "internal.example.com:8443" }); err != nil {
		t.Errorf("valid host header: %v", err)
	}
	for _, h := range []string{"bad host", "http://x", "x/y", "-x.com"} {
		if app(func(a *App) { a.HostHeader = h }) == nil {
			t.Errorf("host header %q should be invalid", h)
		}
	}
	if app(func(a *App) { a.HostHeader = "x.com"; a.PassHostHeader = true }) == nil {
		t.Error("custom and original host header together should be invalid")
	}
}

func TestNormalizeCategory(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "",
		"  Monitoring ":          "Monitoring",
		" Monitoring /  Logs / ": "Monitoring/Logs",
		"a//b":                   "a/b",
		"Dev   Tools/CI":         "Dev Tools/CI",
	} {
		if got := NormalizeCategory(in); got != want {
			t.Errorf("NormalizeCategory(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRecordingConfig(t *testing.T) {
	t.Setenv("TEST_SECRET", strings.Repeat("s", 32))
	minimalConfig := base
	cfg, err := Parse([]byte(minimalConfig))
	if err != nil || cfg.Recording.Dir != "" || cfg.Recording.RetentionDays != 90 {
		t.Fatalf("defaults = %+v %v", cfg.Recording, err)
	}
	cfg, err = Parse([]byte(minimalConfig + "recording:\n  dir: /rec\n  retentionDays: 7\n"))
	if err != nil || cfg.Recording.Dir != "/rec" || cfg.Recording.RetentionDays != 7 {
		t.Errorf("yaml = %+v %v", cfg.Recording, err)
	}
	if _, err := Parse([]byte(minimalConfig + "recording:\n  retentionDays: -1\n")); err == nil {
		t.Error("negative retention accepted")
	}
	if _, err := Parse([]byte(minimalConfig + "recording:\n  dri: /x\n")); err == nil {
		t.Error("unknown recording key accepted")
	}
	t.Setenv("SIDEGATE_RECORDING_DIR", "/env")
	t.Setenv("SIDEGATE_RECORDING_RETENTION_DAYS", "3")
	if cfg, err := Parse([]byte(minimalConfig)); err != nil || cfg.Recording.Dir != "/env" || cfg.Recording.RetentionDays != 3 {
		t.Errorf("env = %+v %v", cfg.Recording, err)
	}
}

func TestAuditConfig(t *testing.T) {
	t.Setenv("TEST_SECRET", strings.Repeat("s", 32))
	for in, want := range map[string]int{"": 365, "audit: {retentionDays: 0}\n": 0, "audit: {retentionDays: 30}\n": 30} {
		cfg, err := Parse([]byte(base + in))
		if err != nil || *cfg.Audit.RetentionDays != want {
			t.Errorf("%q: %v %v, want %d", in, cfg, err, want)
		}
	}
	if _, err := Parse([]byte(base + "audit: {retentionDays: -1}\n")); err == nil {
		t.Error("negative retention accepted")
	}
	t.Setenv("SIDEGATE_AUDIT_RETENTION_DAYS", "0")
	if cfg, err := Parse([]byte(base + "audit: {retentionDays: 30}\n")); err != nil || *cfg.Audit.RetentionDays != 0 {
		t.Errorf("env: %v", err)
	}
}
