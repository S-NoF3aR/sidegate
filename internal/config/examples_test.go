// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestExamples keeps the shipped example configs valid.
func TestExamples(t *testing.T) {
	t.Setenv("SIDEGATE_SESSION_SECRET", "0123456789abcdef0123456789abcdef")
	t.Setenv("SIDEGATE_DATABASE_URL", "postgres://u:p@db/sidegate")

	compose, err := os.ReadFile("../../deploy/compose/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(compose); err != nil {
		t.Errorf("compose config: %v", err)
	}

	raw, err := os.ReadFile("../../deploy/kubernetes/configmap.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cm struct {
		Data map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal(raw, &cm); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]byte(cm.Data["config.yaml"])); err != nil {
		t.Errorf("kubernetes configmap: %v", err)
	}
}

func TestEnvOnly(t *testing.T) {
	for k, v := range map[string]string{
		"SIDEGATE_PUBLIC_URL":       "https://apps.example.com",
		"SIDEGATE_DOMAIN":           "apps.example.com",
		"SIDEGATE_DATABASE_URL":     "sqlite:/data/sidegate.db",
		"SIDEGATE_SESSION_SECRET":   "0123456789abcdef0123456789abcdef",
		"SIDEGATE_OIDC_ISSUER":      "https://idp.example.com",
		"SIDEGATE_OIDC_CLIENT_ID":   "client",
		"SIDEGATE_OIDC_SCOPES":      "openid,profile email offline_access",
		"SIDEGATE_ADMIN_GROUPS":     "g1, g2",
		"SIDEGATE_SESSION_LIFETIME": "8h",
	} {
		t.Setenv(k, v)
	}
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.OIDC.Scopes) != 4 || len(cfg.Admin.Groups) != 2 || cfg.Session.Lifetime.Hours() != 8 {
		t.Errorf("env not applied: %+v", cfg)
	}
}
