// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"sidegate/internal/config"
)

// openStores returns an SQLite store and, if SIDEGATE_TEST_POSTGRES_URL is
// set, a PostgreSQL store (whose tables are reset first).
func openStores(t *testing.T) map[string]*Store {
	t.Helper()
	ctx := context.Background()
	out := map[string]*Store{}
	sq, err := Open(ctx, "sqlite:"+t.TempDir()+"/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sq.Close() })
	out["sqlite"] = sq

	if url := os.Getenv("SIDEGATE_TEST_POSTGRES_URL"); url != "" {
		pg, err := Open(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range []string{`DELETE FROM app_access`, `DELETE FROM apps`, `DELETE FROM group_aliases`, `DELETE FROM audit_log`, `DELETE FROM settings`} {
			if _, err := pg.db.Exec(stmt); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(func() { pg.Close() })
		out["postgres"] = pg
	}
	return out
}

func TestStore(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) { testStore(t, s) })
	}
}

func testStore(t *testing.T, s *Store) {
	ctx := context.Background()
	rev0, _, err := s.Revisions(ctx)
	if err != nil {
		t.Fatal(err)
	}

	grafana := config.App{
		Name: "grafana", Subdomain: "grafana", Title: "Grafana", Upstream: "http://grafana:3000",
		AllowedGroups: []string{"g1", "*", "g1"}, AllowedUsers: []string{"bob@example.com"}, Hidden: true,
		PublicPaths: []string{"/static/*", "/health"}, HostHeader: "grafana.internal", Category: "Monitoring/Dashboards",
	}
	if err := s.CreateApp(ctx, "alice", grafana); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateApp(ctx, "alice", grafana); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate name: err = %v, want ErrConflict", err)
	}
	other := config.App{Name: "other", Subdomain: "grafana", Upstream: "http://x", Public: true}
	if err := s.CreateApp(ctx, "alice", other); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate subdomain: err = %v, want ErrConflict", err)
	}
	if err := s.SaveGroup(ctx, "alice", Group{ID: "g1", Name: "devs"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveGroup(ctx, "alice", Group{ID: "g2", Name: "devs"}); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate group name: err = %v, want ErrConflict", err)
	}
	if err := s.SaveGroup(ctx, "alice", Group{ID: "g1", Name: "developers"}); err != nil {
		t.Errorf("rename group: %v", err)
	}

	apps, groups, rev, err := s.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rev <= rev0 {
		t.Errorf("revision not bumped: %d -> %d", rev0, rev)
	}
	if len(apps) != 1 || !apps[0].Hidden || len(apps[0].AllowedGroups) != 2 || apps[0].AllowedUsers[0] != "bob@example.com" ||
		len(apps[0].PublicPaths) != 2 || apps[0].HostHeader != "grafana.internal" || apps[0].Category != "Monitoring/Dashboards" {
		t.Errorf("loaded apps = %+v", apps)
	}
	if len(groups) != 1 || groups[0].Name != "developers" {
		t.Errorf("loaded groups = %+v", groups)
	}

	grafana.AllowedGroups = []string{"g2"}
	grafana.Hidden = false
	grafana.PublicPaths = []string{"/health"}
	grafana.HostHeader = ""
	if err := s.UpdateApp(ctx, "alice", grafana); err != nil {
		t.Fatal(err)
	}
	apps, _, _, _ = s.Load(ctx)
	if apps[0].Hidden || len(apps[0].AllowedGroups) != 1 || apps[0].AllowedGroups[0] != "g2" ||
		len(apps[0].PublicPaths) != 1 || apps[0].HostHeader != "" {
		t.Errorf("after update: %+v", apps[0])
	}
	if err := s.UpdateApp(ctx, "alice", config.App{Name: "missing", Subdomain: "missing", Upstream: "http://x"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("update missing: err = %v", err)
	}

	if seeded, err := s.Seed(ctx, []config.App{other}, nil); err != nil || seeded {
		t.Errorf("seed into non-empty database: seeded=%v err=%v", seeded, err)
	}

	if err := s.DeleteApp(ctx, "alice", "grafana"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteApp(ctx, "alice", "grafana"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete twice: err = %v", err)
	}
	if err := s.DeleteGroup(ctx, "alice", "g1"); err != nil {
		t.Fatal(err)
	}

	// Ending a session bumps only the sessions revision.
	rev1, srev1, _ := s.Revisions(ctx)
	if err := s.EndSession(ctx, "sid-1", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	s.EndSession(ctx, "sid-old", time.Now().Add(-time.Hour).Unix())
	rev2, srev2, _ := s.Revisions(ctx)
	revs, err := s.Revocations(ctx)
	if err != nil || rev2 != rev1 || srev2 <= srev1 || !revs.Ended["sid-1"] || revs.Ended["sid-old"] {
		t.Errorf("end session: rev %d->%d, sessions %d->%d, ended %v, err %v", rev1, rev2, srev1, srev2, revs.Ended, err)
	}

	audit, err := s.Audit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(audit) < 6 || audit[0].Action != "group.delete" || audit[0].Actor != "alice" {
		t.Errorf("audit = %+v", audit)
	}
}

func TestReopenKeepsData(t *testing.T) {
	ctx := context.Background()
	url := "sqlite:" + t.TempDir() + "/test.db"
	s, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateApp(ctx, "a", config.App{Name: "x", Subdomain: "x", Upstream: "http://x", Public: true}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(ctx, url) // migrations must be idempotent
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	apps, _, _, err := s.Load(ctx)
	if err != nil || len(apps) != 1 {
		t.Errorf("after reopen: %v %v", apps, err)
	}
}

// TestUpgradeFromV1 opens a database created by the first schema version.
func TestUpgradeFromV1(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/old.db"
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	stmts := append([]string{`CREATE TABLE meta (key TEXT PRIMARY KEY, value BIGINT NOT NULL)`}, migrations[0]...)
	stmts = append(stmts,
		`INSERT INTO meta (key, value) VALUES ('schema_version', 1)`,
		`INSERT INTO apps (name, subdomain, upstream, public, updated_at, updated_by) VALUES ('old', 'old', 'http://old', TRUE, 0, 'x')`,
	)
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	s, err := Open(ctx, "sqlite:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	apps, _, _, err := s.Load(ctx)
	if err != nil || len(apps) != 1 || apps[0].Name != "old" || apps[0].HostHeader != "" {
		t.Fatalf("after upgrade: %+v %v", apps, err)
	}
	apps[0].PublicPaths = []string{"/health"}
	if err := s.UpdateApp(ctx, "x", apps[0]); err != nil {
		t.Errorf("update after upgrade: %v", err)
	}
}

func TestSettings(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			var audited []AuditEntry
			s.OnAudit = func(e AuditEntry) { audited = append(audited, e) }
			defer func() { s.OnAudit = nil }()
			if v, err := s.Setting(ctx, "x"); err != nil || v != "" {
				t.Fatalf("missing setting = %q %v", v, err)
			}
			rev0, _, _ := s.Revisions(ctx)
			for _, v := range []string{`{"a":1}`, `{"a":2}`} {
				if err := s.SaveSetting(ctx, "alice", "x", v); err != nil {
					t.Fatal(err)
				}
			}
			if v, err := s.Setting(ctx, "x"); err != nil || v != `{"a":2}` {
				t.Errorf("setting = %q %v", v, err)
			}
			if rev, _, _ := s.Revisions(ctx); rev <= rev0 {
				t.Errorf("revision not bumped: %d → %d", rev0, rev)
			}
			if err := s.LogAccess(ctx, "bob", "thing.view", "t1"); err != nil {
				t.Fatal(err)
			}
			audit, _ := s.Audit(ctx, 10)
			if len(audit) < 3 || audit[0].Action != "thing.view" || audit[0].Actor != "bob" || audit[1].Action != "setting.save" || audit[1].Detail != `{"a":2}` {
				t.Errorf("audit = %+v", audit)
			}
			if len(audited) != 3 || audited[2].Action != "thing.view" {
				t.Errorf("OnAudit = %+v", audited)
			}
		})
	}
}

func TestPruneAudit(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			old := time.Now().AddDate(0, 0, -400)
			if _, err := s.db.Exec(s.q(`INSERT INTO audit_log (at, actor, action, target, detail) VALUES (?, 'x', 'old.thing', 't', '')`), old.UnixMilli()); err != nil {
				t.Fatal(err)
			}
			if err := s.LogAccess(ctx, "x", "new.thing", "t"); err != nil {
				t.Fatal(err)
			}
			n, err := s.PruneAudit(ctx, time.Now().AddDate(0, 0, -365))
			if err != nil || n != 1 {
				t.Fatalf("pruned %d %v", n, err)
			}
			audit, _ := s.Audit(ctx, 100)
			for _, e := range audit {
				if e.Action == "old.thing" {
					t.Error("old entry kept")
				}
			}
			if len(audit) == 0 || audit[0].Action != "new.thing" {
				t.Errorf("recent entry lost: %+v", audit)
			}
		})
	}
}
