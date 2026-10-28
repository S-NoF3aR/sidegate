// SPDX-License-Identifier: AGPL-3.0-only

// Package store persists apps, access rules and group names in PostgreSQL
// or SQLite.
//
// Every write bumps a revision counter, which proxy replicas poll to pick
// up changes made through any other replica.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx"
	_ "modernc.org/sqlite"             // registers "sqlite"

	"sidegate/internal/config"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

// Group gives an IdP group ID a readable name.
type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Token is an API token. Only a keyed hash of the secret is stored.
type Token struct {
	ID         string
	Name       string
	CreatedBy  string
	CreatedAt  time.Time
	LastUsedAt time.Time // zero if never used
}

type AuditEntry struct {
	At     time.Time
	Actor  string
	Action string
	Target string
	Detail string
}

type Store struct {
	db       *sql.DB
	postgres bool

	// OnAudit, if set, is called with each audit entry once its
	// transaction has committed.
	OnAudit func(AuditEntry)
	pending sync.Map // *sql.Tx → []AuditEntry, until commit
}

// Open connects to url (postgres://… or sqlite:/path/file.db) and applies
// pending schema migrations.
func Open(ctx context.Context, url string) (*Store, error) {
	s := &Store{}
	var err error
	switch {
	case strings.HasPrefix(url, "postgres://"), strings.HasPrefix(url, "postgresql://"):
		s.postgres = true
		s.db, err = sql.Open("pgx", url)
	case strings.HasPrefix(url, "sqlite:"):
		path := strings.TrimPrefix(strings.TrimPrefix(url, "sqlite:"), "//")
		s.db, err = sql.Open("sqlite", "file:"+path+
			"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
		// SQLite allows a single writer; serializing avoids "database is
		// locked" errors under concurrent admin writes.
		s.db.SetMaxOpenConns(1)
	default:
		return nil, errors.New("database URL must start with postgres://, postgresql:// or sqlite:")
	}
	if err != nil {
		return nil, err
	}
	if err := s.db.PingContext(ctx); err != nil {
		s.db.Close()
		return nil, err
	}
	if err := s.migrate(ctx); err != nil {
		s.db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// The SQL below is shared by both databases and written with "?"
// placeholders, which q rewrites to $n for PostgreSQL.
var migrations = [][]string{
	{
		`CREATE TABLE apps (
			name                 TEXT PRIMARY KEY,
			subdomain            TEXT NOT NULL UNIQUE,
			title                TEXT NOT NULL DEFAULT '',
			description          TEXT NOT NULL DEFAULT '',
			icon                 TEXT NOT NULL DEFAULT '',
			upstream             TEXT NOT NULL,
			public               BOOLEAN NOT NULL DEFAULT FALSE,
			hidden               BOOLEAN NOT NULL DEFAULT FALSE,
			pass_host_header     BOOLEAN NOT NULL DEFAULT FALSE,
			insecure_skip_verify BOOLEAN NOT NULL DEFAULT FALSE,
			updated_at           BIGINT NOT NULL,
			updated_by           TEXT NOT NULL
		)`,
		`CREATE TABLE app_access (
			app   TEXT NOT NULL REFERENCES apps (name) ON DELETE CASCADE,
			kind  TEXT NOT NULL CHECK (kind IN ('group', 'user')),
			value TEXT NOT NULL,
			PRIMARY KEY (app, kind, value)
		)`,
		`CREATE TABLE group_aliases (
			id   TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE
		)`,
		`CREATE TABLE audit_log (
			at     BIGINT NOT NULL,
			actor  TEXT NOT NULL,
			action TEXT NOT NULL,
			target TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX audit_log_at ON audit_log (at)`,
		`INSERT INTO meta (key, value) VALUES ('revision', 1)`,
	},
	{
		`ALTER TABLE apps ADD COLUMN host_header TEXT NOT NULL DEFAULT ''`,
		`CREATE TABLE app_public_paths (
			app  TEXT NOT NULL REFERENCES apps (name) ON DELETE CASCADE,
			path TEXT NOT NULL,
			PRIMARY KEY (app, path)
		)`,
	},
	{
		`CREATE TABLE api_tokens (
			id           TEXT PRIMARY KEY,
			name         TEXT NOT NULL,
			hash         TEXT NOT NULL UNIQUE,
			created_at   BIGINT NOT NULL,
			created_by   TEXT NOT NULL,
			last_used_at BIGINT NOT NULL DEFAULT 0
		)`,
	},
	{
		`ALTER TABLE apps ADD COLUMN category TEXT NOT NULL DEFAULT ''`,
	},
	{
		`ALTER TABLE apps ADD COLUMN require_mfa BOOLEAN NOT NULL DEFAULT FALSE`,
		`ALTER TABLE apps ADD COLUMN max_auth_age BIGINT NOT NULL DEFAULT 0`,
		// Users who signed in, and the per-user session revocation time
		// (Unix milliseconds; sessions issued before it are invalid).
		`CREATE TABLE users (
			subject        TEXT PRIMARY KEY,
			username       TEXT NOT NULL DEFAULT '',
			email          TEXT NOT NULL DEFAULT '',
			name           TEXT NOT NULL DEFAULT '',
			last_login     BIGINT NOT NULL DEFAULT 0,
			logins         BIGINT NOT NULL DEFAULT 0,
			revoked_before BIGINT NOT NULL DEFAULT 0
		)`,
		`INSERT INTO meta (key, value) VALUES ('sessions_revoked_before', 0)`,
	},
	{
		// Sessions ended by logout, kept until they would have expired.
		`CREATE TABLE ended_sessions (
			id      TEXT PRIMARY KEY,
			expires BIGINT NOT NULL
		)`,
		// Bumped by logouts; separate from "revision" so a logout doesn't
		// make every replica reload all apps.
		`INSERT INTO meta (key, value) VALUES ('sessions_revision', 1)`,
	},
	{
		// Key/value settings, e.g. of extensions.
		`CREATE TABLE settings (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
	},
	{
		// The newest refreshed state of each session (sealed by the
		// server), so clients holding an older copy continue from it on
		// any replica instead of redeeming a rotated refresh token.
		`CREATE TABLE session_states (
			id      TEXT PRIMARY KEY,
			gen     BIGINT NOT NULL,
			data    TEXT NOT NULL,
			expires BIGINT NOT NULL
		)`,
	},
}

func (s *Store) migrate(ctx context.Context) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if s.postgres {
			// Replicas starting together must not migrate concurrently.
			if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7280633)`); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BIGINT NOT NULL)`); err != nil {
			return err
		}
		var version int
		err := tx.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'schema_version'`).Scan(&version)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		for v := version; v < len(migrations); v++ {
			for _, stmt := range migrations[v] {
				if _, err := tx.ExecContext(ctx, stmt); err != nil {
					return fmt.Errorf("migration %d: %w", v+1, err)
				}
			}
		}
		_, err = tx.ExecContext(ctx, s.q(`INSERT INTO meta (key, value) VALUES ('schema_version', ?)
			ON CONFLICT (key) DO UPDATE SET value = excluded.value`), len(migrations))
		return err
	})
}

// Revisions returns two counters: rev changes with every configuration
// write, sessionsRev whenever a session is ended by logout.
func (s *Store) Revisions(ctx context.Context) (rev, sessionsRev int64, err error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM meta WHERE key IN ('revision', 'sessions_revision')`)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var v int64
		if err := rows.Scan(&k, &v); err != nil {
			return 0, 0, err
		}
		if k == "revision" {
			rev = v
		} else {
			sessionsRev = v
		}
	}
	return rev, sessionsRev, rows.Err()
}

// Load returns all apps (sorted by name), all groups (sorted by name) and
// the revision they belong to.
func (s *Store) Load(ctx context.Context) (apps []config.App, groups []Group, rev int64, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'revision'`).Scan(&rev); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT name, subdomain, title, description, icon, category, upstream,
			public, hidden, pass_host_header, host_header, insecure_skip_verify, require_mfa, max_auth_age
			FROM apps ORDER BY name`)
		if err != nil {
			return err
		}
		byName := map[string]int{}
		for rows.Next() {
			var a config.App
			if err := rows.Scan(&a.Name, &a.Subdomain, &a.Title, &a.Description, &a.Icon, &a.Category, &a.Upstream,
				&a.Public, &a.Hidden, &a.PassHostHeader, &a.HostHeader, &a.InsecureSkipVerify,
				&a.RequireMFA, &a.MaxAuthAgeMinutes); err != nil {
				rows.Close()
				return err
			}
			byName[a.Name] = len(apps)
			apps = append(apps, a)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		rows, err = tx.QueryContext(ctx, `SELECT app, kind, value FROM app_access ORDER BY app, kind, value`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var app, kind, value string
			if err := rows.Scan(&app, &kind, &value); err != nil {
				rows.Close()
				return err
			}
			i, ok := byName[app]
			if !ok {
				continue
			}
			if kind == "group" {
				apps[i].AllowedGroups = append(apps[i].AllowedGroups, value)
			} else {
				apps[i].AllowedUsers = append(apps[i].AllowedUsers, value)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		rows, err = tx.QueryContext(ctx, `SELECT app, path FROM app_public_paths ORDER BY app, path`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var app, path string
			if err := rows.Scan(&app, &path); err != nil {
				rows.Close()
				return err
			}
			if i, ok := byName[app]; ok {
				apps[i].PublicPaths = append(apps[i].PublicPaths, path)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		groups, err = loadGroups(ctx, tx)
		return err
	})
	return apps, groups, rev, err
}

func loadGroups(ctx context.Context, tx *sql.Tx) ([]Group, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, name FROM group_aliases ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// CreateApp adds a new app. The app must already be validated.
func (s *Store) CreateApp(ctx context.Context, actor string, a config.App) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM apps WHERE name = ?`), a.Name).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%w: an app named %q already exists", ErrConflict, a.Name)
		}
		if err := s.checkSubdomain(ctx, tx, a); err != nil {
			return err
		}
		if err := s.insertApp(ctx, tx, actor, a); err != nil {
			return err
		}
		return s.written(ctx, tx, actor, "app.create", a.Name, a)
	})
}

// UpdateApp replaces an existing app, identified by its name.
func (s *Store) UpdateApp(ctx context.Context, actor string, a config.App) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if err := s.checkSubdomain(ctx, tx, a); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, s.q(`UPDATE apps SET subdomain = ?, title = ?, description = ?, icon = ?,
			category = ?, upstream = ?, public = ?, hidden = ?, pass_host_header = ?, host_header = ?, insecure_skip_verify = ?,
			require_mfa = ?, max_auth_age = ?, updated_at = ?, updated_by = ? WHERE name = ?`),
			a.Subdomain, a.Title, a.Description, a.Icon, a.Category, a.Upstream, a.Public, a.Hidden,
			a.PassHostHeader, a.HostHeader, a.InsecureSkipVerify, a.RequireMFA, a.MaxAuthAgeMinutes,
			time.Now().Unix(), actor, a.Name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%w: app %q", ErrNotFound, a.Name)
		}
		if err := s.deleteAccess(ctx, tx, a.Name); err != nil {
			return err
		}
		if err := s.insertAccess(ctx, tx, a); err != nil {
			return err
		}
		return s.written(ctx, tx, actor, "app.update", a.Name, a)
	})
}

func (s *Store) DeleteApp(ctx context.Context, actor, name string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if err := s.deleteAccess(ctx, tx, name); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, s.q(`DELETE FROM apps WHERE name = ?`), name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%w: app %q", ErrNotFound, name)
		}
		return s.written(ctx, tx, actor, "app.delete", name, nil)
	})
}

func (s *Store) checkSubdomain(ctx context.Context, tx *sql.Tx, a config.App) error {
	var other string
	err := tx.QueryRowContext(ctx, s.q(`SELECT name FROM apps WHERE subdomain = ? AND name <> ?`), a.Subdomain, a.Name).Scan(&other)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return err
	}
	return fmt.Errorf("%w: subdomain %q is already used by app %q", ErrConflict, a.Subdomain, other)
}

func (s *Store) insertApp(ctx context.Context, tx *sql.Tx, actor string, a config.App) error {
	if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO apps (name, subdomain, title, description, icon, category, upstream,
		public, hidden, pass_host_header, host_header, insecure_skip_verify, require_mfa, max_auth_age, updated_at, updated_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		a.Name, a.Subdomain, a.Title, a.Description, a.Icon, a.Category, a.Upstream,
		a.Public, a.Hidden, a.PassHostHeader, a.HostHeader, a.InsecureSkipVerify, a.RequireMFA, a.MaxAuthAgeMinutes,
		time.Now().Unix(), actor); err != nil {
		return err
	}
	return s.insertAccess(ctx, tx, a)
}

func (s *Store) deleteAccess(ctx context.Context, tx *sql.Tx, app string) error {
	for _, table := range []string{"app_access", "app_public_paths"} {
		if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM `+table+` WHERE app = ?`), app); err != nil {
			return err
		}
	}
	return nil
}

// insertAccess stores the access rules and public paths of a.
func (s *Store) insertAccess(ctx context.Context, tx *sql.Tx, a config.App) error {
	for _, p := range uniq(a.PublicPaths) {
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO app_public_paths (app, path) VALUES (?, ?)`), a.Name, p); err != nil {
			return err
		}
	}
	insert := func(kind string, values []string) error {
		for _, v := range uniq(values) {
			if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO app_access (app, kind, value) VALUES (?, ?, ?)`), a.Name, kind, v); err != nil {
				return err
			}
		}
		return nil
	}
	if err := insert("group", a.AllowedGroups); err != nil {
		return err
	}
	return insert("user", a.AllowedUsers)
}

// SaveGroup creates or renames the group with the given ID.
func (s *Store) SaveGroup(ctx context.Context, actor string, g Group) error {
	g.ID, g.Name = strings.TrimSpace(g.ID), strings.TrimSpace(g.Name)
	if g.ID == "" || g.Name == "" || g.ID == "*" || g.Name == "*" {
		return fmt.Errorf("%w: a group needs a name and an ID", ErrConflict)
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var other string
		err := tx.QueryRowContext(ctx, s.q(`SELECT id FROM group_aliases WHERE name = ? AND id <> ?`), g.Name, g.ID).Scan(&other)
		if err == nil {
			return fmt.Errorf("%w: the name %q is already used for group %s", ErrConflict, g.Name, other)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO group_aliases (id, name) VALUES (?, ?)
			ON CONFLICT (id) DO UPDATE SET name = excluded.name`), g.ID, g.Name); err != nil {
			return err
		}
		return s.written(ctx, tx, actor, "group.save", g.Name, g)
	})
}

// DeleteGroup removes a group name. Apps referencing the ID keep it.
func (s *Store) DeleteGroup(ctx context.Context, actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, s.q(`DELETE FROM group_aliases WHERE id = ?`), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%w: group %q", ErrNotFound, id)
		}
		return s.written(ctx, tx, actor, "group.delete", id, nil)
	})
}

// SeedFromConfig imports the apps and groups of a config file into an empty
// database, resolving group names to IDs.
func (s *Store) SeedFromConfig(ctx context.Context, cfg *config.Config) (bool, error) {
	if len(cfg.Apps) == 0 && len(cfg.Groups) == 0 {
		return false, nil
	}
	var groups []Group
	for name, id := range cfg.Groups {
		groups = append(groups, Group{ID: id, Name: name})
	}
	apps := make([]config.App, len(cfg.Apps))
	for i, a := range cfg.Apps {
		a.AllowedGroups = slices.Clone(a.AllowedGroups)
		for j, g := range a.AllowedGroups {
			a.AllowedGroups[j] = cfg.ResolveGroup(g)
		}
		apps[i] = a
	}
	return s.Seed(ctx, apps, groups)
}

// Seed imports apps and groups if the database has no apps yet. Group
// references in apps must already be resolved to IDs.
func (s *Store) Seed(ctx context.Context, apps []config.App, groups []Group) (bool, error) {
	seeded := false
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM apps`).Scan(&n); err != nil || n > 0 {
			return err
		}
		for _, g := range groups {
			if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO group_aliases (id, name) VALUES (?, ?)
				ON CONFLICT (id) DO UPDATE SET name = excluded.name`), g.ID, g.Name); err != nil {
				return err
			}
		}
		for _, a := range apps {
			if err := s.insertApp(ctx, tx, "seed", a); err != nil {
				return err
			}
		}
		seeded = true
		return s.written(ctx, tx, "seed", "seed", strconv.Itoa(len(apps))+" apps", nil)
	})
	return seeded, err
}

// User is someone who signed in through the proxy.
type User struct {
	Subject       string    `json:"subject"`
	Username      string    `json:"username"`
	Email         string    `json:"email"`
	Name          string    `json:"name"`
	LastLogin     time.Time `json:"lastLogin"`
	Logins        int64     `json:"logins"`
	RevokedBefore time.Time `json:"sessionsRevokedBefore"` // zero if never revoked
}

// RecordLogin creates or updates the user on sign-in. It doesn't bump the
// revision, as nothing the proxy routes on changes.
func (s *Store) RecordLogin(ctx context.Context, u User) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO users (subject, username, email, name, last_login, logins)
		VALUES (?, ?, ?, ?, ?, 1)
		ON CONFLICT (subject) DO UPDATE SET username = excluded.username, email = excluded.email,
			name = excluded.name, last_login = excluded.last_login, logins = users.logins + 1`),
		u.Subject, u.Username, u.Email, u.Name, time.Now().Unix())
	return err
}

func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT subject, username, email, name, last_login, logins, revoked_before
		FROM users ORDER BY last_login DESC, subject`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var last, revoked int64
		if err := rows.Scan(&u.Subject, &u.Username, &u.Email, &u.Name, &last, &u.Logins, &revoked); err != nil {
			return nil, err
		}
		u.LastLogin = time.Unix(last, 0)
		if revoked > 0 {
			u.RevokedBefore = time.UnixMilli(revoked)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// RevokeSessions invalidates every session the user obtained before now.
// It works for subjects that never signed in through this database, too.
func (s *Store) RevokeSessions(ctx context.Context, actor, subject string) error {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return fmt.Errorf("%w: a subject is required", ErrConflict)
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO users (subject, revoked_before) VALUES (?, ?)
			ON CONFLICT (subject) DO UPDATE SET revoked_before = excluded.revoked_before`),
			subject, time.Now().UnixMilli()); err != nil {
			return err
		}
		return s.written(ctx, tx, actor, "sessions.revoke", subject, nil)
	})
}

// RevokeAllSessions invalidates every session issued before now.
func (s *Store) RevokeAllSessions(ctx context.Context, actor string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, s.q(`UPDATE meta SET value = ? WHERE key = 'sessions_revoked_before'`),
			time.Now().UnixMilli()); err != nil {
			return err
		}
		return s.written(ctx, tx, actor, "sessions.revoke_all", "*", nil)
	})
}

// Revocations lists what invalidates sessions.
type Revocations struct {
	// All and Users[subject] invalidate sessions issued before them (Unix ms).
	All   int64
	Users map[string]int64
	// Ended holds IDs of sessions ended by logout.
	Ended map[string]bool
}

func (s *Store) Revocations(ctx context.Context) (Revocations, error) {
	r := Revocations{Users: map[string]int64{}, Ended: map[string]bool{}}
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'sessions_revoked_before'`).Scan(&r.All); err != nil {
		return r, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT subject, revoked_before FROM users WHERE revoked_before > 0`)
	if err != nil {
		return r, err
	}
	for rows.Next() {
		var sub string
		var at int64
		if err := rows.Scan(&sub, &at); err != nil {
			rows.Close()
			return r, err
		}
		r.Users[sub] = at
	}
	rows.Close()
	rows, err = s.db.QueryContext(ctx, s.q(`SELECT id FROM ended_sessions WHERE expires > ?`), time.Now().Unix())
	if err != nil {
		return r, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return r, err
		}
		r.Ended[id] = true
	}
	return r, rows.Err()
}

// EndSession invalidates one session (on logout) until it would have
// expired anyway. Entries past their expiry are pruned on the way.
func (s *Store) EndSession(ctx context.Context, id string, expires int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM ended_sessions WHERE expires <= ?`), time.Now().Unix()); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO ended_sessions (id, expires) VALUES (?, ?)
			ON CONFLICT (id) DO NOTHING`), id, expires); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE meta SET value = value + 1 WHERE key = 'sessions_revision'`)
		return err
	})
}

// SessionState returns the stored state of session id if it is newer than
// generation gen.
func (s *Store) SessionState(ctx context.Context, id string, gen int64) (data string, ok bool, err error) {
	err = s.db.QueryRowContext(ctx, s.q(`SELECT data FROM session_states WHERE id = ? AND gen > ? AND expires > ?`),
		id, gen, time.Now().Unix()).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return data, err == nil, err
}

// SaveSessionState stores data as generation gen of session id, unless a
// newer generation is stored already.
func (s *Store) SaveSessionState(ctx context.Context, id string, gen int64, data string, expires int64) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO session_states (id, gen, data, expires) VALUES (?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET gen = excluded.gen, data = excluded.data, expires = excluded.expires
		WHERE session_states.gen < excluded.gen`), id, gen, data, expires)
	return err
}

// PruneSessionStates deletes the states of expired sessions.
func (s *Store) PruneSessionStates(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM session_states WHERE expires <= ?`), now.Unix())
	return err
}

// Setting returns the value stored under key, or "" if there is none.
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT value FROM settings WHERE key = ?`), key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SaveSetting stores value under key and records the change in the audit
// log.
func (s *Store) SaveSetting(ctx context.Context, actor, key, value string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO settings (key, value) VALUES (?, ?)
			ON CONFLICT (key) DO UPDATE SET value = excluded.value`), key, value); err != nil {
			return err
		}
		return s.written(ctx, tx, actor, "setting.save", key, json.RawMessage(value))
	})
}

// PruneAudit deletes audit log entries older than before and returns how
// many were deleted.
func (s *Store) PruneAudit(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM audit_log WHERE at < ?`), before.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// LogAccess records an action that changes nothing, such as viewing
// sensitive data, in the audit log.
func (s *Store) LogAccess(ctx context.Context, actor, action, target string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		now := time.Now()
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO audit_log (at, actor, action, target, detail) VALUES (?, ?, ?, ?, '')`),
			now.UnixMilli(), actor, action, target); err != nil {
			return err
		}
		if s.OnAudit != nil {
			s.pending.Store(tx, []AuditEntry{{At: now, Actor: actor, Action: action, Target: target}})
		}
		return nil
	})
}

// CreateToken stores a new API token under its hash.
func (s *Store) CreateToken(ctx context.Context, actor string, t Token, hash string) error {
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("%w: a token needs a name", ErrConflict)
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO api_tokens (id, name, hash, created_at, created_by) VALUES (?, ?, ?, ?, ?)`),
			t.ID, strings.TrimSpace(t.Name), hash, time.Now().Unix(), actor); err != nil {
			return err
		}
		return s.written(ctx, tx, actor, "token.create", t.Name, map[string]string{"id": t.ID})
	})
}

func (s *Store) Tokens(ctx context.Context) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_by, created_at, last_used_at FROM api_tokens ORDER BY created_at DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TokenByHash returns the token with the given hash, or ErrNotFound.
func (s *Store) TokenByHash(ctx context.Context, hash string) (Token, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT id, name, created_by, created_at, last_used_at FROM api_tokens WHERE hash = ?`), hash)
	t, err := scanToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, err
}

func scanToken(row interface{ Scan(...any) error }) (Token, error) {
	var t Token
	var created, used int64
	if err := row.Scan(&t.ID, &t.Name, &t.CreatedBy, &created, &used); err != nil {
		return t, err
	}
	t.CreatedAt = time.Unix(created, 0)
	if used > 0 {
		t.LastUsedAt = time.Unix(used, 0)
	}
	return t, nil
}

// TouchToken records that a token was used.
func (s *Store) TouchToken(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE api_tokens SET last_used_at = ? WHERE id = ?`), time.Now().Unix(), id)
	return err
}

func (s *Store) DeleteToken(ctx context.Context, actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		err := tx.QueryRowContext(ctx, s.q(`SELECT name FROM api_tokens WHERE id = ?`), id).Scan(&name)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: token %q", ErrNotFound, id)
		} else if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM api_tokens WHERE id = ?`), id); err != nil {
			return err
		}
		return s.written(ctx, tx, actor, "token.delete", name, map[string]string{"id": id})
	})
}

// Audit returns the most recent audit entries, newest first.
func (s *Store) Audit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT at, actor, action, target, detail FROM audit_log ORDER BY at DESC LIMIT ?`), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&at, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		e.At = time.UnixMilli(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// written bumps the revision and records an audit entry.
func (s *Store) written(ctx context.Context, tx *sql.Tx, actor, action, target string, detail any) error {
	if _, err := tx.ExecContext(ctx, `UPDATE meta SET value = value + 1 WHERE key = 'revision'`); err != nil {
		return err
	}
	var d []byte
	if detail != nil {
		d, _ = json.Marshal(detail)
	}
	now := time.Now()
	_, err := tx.ExecContext(ctx, s.q(`INSERT INTO audit_log (at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)`),
		now.UnixMilli(), actor, action, target, string(d))
	if err == nil && s.OnAudit != nil {
		prev, _ := s.pending.Load(tx)
		entries, _ := prev.([]AuditEntry)
		s.pending.Store(tx, append(entries, AuditEntry{At: now, Actor: actor, Action: action, Target: target, Detail: string(d)}))
	}
	return err
}

func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		s.pending.Delete(tx)
		return err
	}
	if err := tx.Commit(); err != nil {
		s.pending.Delete(tx)
		return err
	}
	if entries, ok := s.pending.LoadAndDelete(tx); ok && s.OnAudit != nil {
		for _, e := range entries.([]AuditEntry) {
			s.OnAudit(e)
		}
	}
	return nil
}

// q rewrites "?" placeholders to PostgreSQL's $n form.
func (s *Store) q(query string) string {
	if !s.postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func uniq(values []string) []string {
	out := slices.Clone(values)
	slices.Sort(out)
	return slices.Compact(out)
}
