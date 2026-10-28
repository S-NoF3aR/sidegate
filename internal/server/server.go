// SPDX-License-Identifier: AGPL-3.0-only

// Package server implements the identity-aware proxy: host based routing,
// OIDC login, per-app group authorization and the app portal.
package server

import (
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"sidegate/internal/config"
	"sidegate/internal/session"
	"sidegate/internal/store"
)

type Server struct {
	log        *slog.Logger
	public     *url.URL
	portalHost string
	domain     string
	secure     bool

	cookieName      string
	lifetime        time.Duration
	refreshInterval time.Duration
	sessions        *session.Codec
	states          *session.Codec
	refreshes       refreshGroup

	oauth          *oauth2.Config
	verifier       *oidc.IDTokenVerifier
	endSessionURL  string
	oidcCfg        config.OIDC
	providerLogout bool

	store       *store.Store
	revision    atomic.Int64
	sessionsRev atomic.Int64
	// syncMu serializes swaps of routes, so a revocations-only sync never
	// overwrites a newer full sync.
	syncMu sync.Mutex
	live   liveSessions
	// checkInterval is how often live remote connections re-check their
	// session.
	checkInterval time.Duration
	// pingInterval is how often WebSocket tunnels are pinged, which keeps
	// idle connections open through load balancers and ends dead ones.
	pingInterval time.Duration
	// draining is closed when the server shuts down; liveRemote counts the
	// open remote connections Drain waits for.
	draining    chan struct{}
	drainOnce   sync.Once
	liveRemote  atomic.Int64
	downloads   *cliDownloads // nil if none are available
	cfg         *config.Config
	extensions  []Extension
	eventQueues []chan Event
	adminGroups map[string]bool
	adminUsers  map[string]bool
	csrfKey     []byte
	apiKey      []byte
	jwt         *jwtSigner
	cliTokens   *session.Codec
	cliCodes    *session.Codec
	guacd       string
	mfa         config.MFA
	metrics     *metrics

	routes atomic.Pointer[routes]
	portal http.Handler
	tmpl   *template.Template
}

// routes is the reloadable part of the configuration.
type routes struct {
	apps   []*app
	bySub  map[string]*app
	byName map[string]*app
	// groups holds every group ID referenced by an app or the admin
	// settings. Only these are kept in the session cookie, which keeps it
	// small even for users in hundreds of groups.
	groups map[string]bool
	// groupNames maps group IDs back to their friendly names.
	groupNames map[string]string
	// groupList is every named group, sorted by name.
	groupList []store.Group
	// Sessions issued before these times (Unix ms) are revoked: globally,
	// and per subject. Sessions in ended were ended by logout.
	revokedAll   int64
	revokedUsers map[string]int64
	ended        map[string]bool
	// changed is closed when these routes are replaced, waking live
	// connections to re-check their session right away.
	changed chan struct{}
}

type app struct {
	config.App
	URL         string
	groups      map[string]bool
	users       map[string]bool
	anyone      bool
	publicExact map[string]bool
	publicPre   []string
	proxy       http.Handler
	transport   *http.Transport
}

// isPublicPath reports whether the request path matches one of the app's
// public paths. Paths an upstream might normalize differently (dot
// segments, encoded slashes, ';' parameters, backslashes) never match, so
// "/static/../admin" or "/static/..;/admin" can't sneak past
// authentication.
func (a *app) isPublicPath(u *url.URL) bool {
	if len(a.publicExact) == 0 && len(a.publicPre) == 0 {
		return false
	}
	// RawPath is only set when the request used a non-default encoding
	// such as %2F; a '%' left after decoding means double encoding.
	p := u.Path
	if u.RawPath != "" || !config.CanonicalPath(p) || strings.ContainsAny(p, ";\\%") {
		return false
	}
	if a.publicExact[p] {
		return true
	}
	for _, pre := range a.publicPre {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// stepUp reports whether sess must sign in again before using the app:
// with MFA, and/or because the last authentication is older than maxAge
// seconds (0 if recent enough).
func (a *app) stepUp(sess *session.Session) (mfa bool, maxAge int) {
	if a.MaxAuthAgeMinutes > 0 && time.Since(time.Unix(sess.AuthTime, 0)) > time.Duration(a.MaxAuthAgeMinutes)*time.Minute {
		return a.RequireMFA, a.MaxAuthAgeMinutes * 60
	}
	return a.RequireMFA && !sess.MFA, 0
}

func (a *app) allows(s *session.Session) bool {
	if a.Public || a.anyone {
		return true
	}
	return matchesUser(a.users, s) || slices.ContainsFunc(s.Groups, func(g string) bool { return a.groups[g] })
}

// matchesUser reports whether the user of s is in users (normalized with
// config.NormalizeUser): by subject, email or username.
func matchesUser(users map[string]bool, s *session.Session) bool {
	return users["sub:"+s.Subject] ||
		(s.Email != "" && users[strings.ToLower(s.Email)]) ||
		(s.Username != "" && users[strings.ToLower(s.Username)])
}

// New discovers the OIDC provider, loads the apps from st and builds the
// server. ctx must outlive the server, as it is also used to refresh the
// provider's signing keys.
func New(ctx context.Context, cfg *config.Config, st *store.Store, log *slog.Logger) (*Server, error) {
	public, err := url.Parse(cfg.PublicURL)
	if err != nil {
		return nil, err
	}
	public.Path = ""

	provider, err := oidc.NewProvider(ctx, cfg.OIDC.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}

	sessions, err := session.NewCodec(cfg.Session.Secret, "session")
	if err != nil {
		return nil, err
	}
	states, err := session.NewCodec(cfg.Session.Secret, "oauth-state")
	if err != nil {
		return nil, err
	}
	tmpl, err := parseTemplates(public.String(), cfg.SourceURL)
	if err != nil {
		return nil, err
	}
	csrfKey, err := session.DeriveKey(cfg.Session.Secret, "csrf")
	if err != nil {
		return nil, err
	}
	apiKey, err := session.DeriveKey(cfg.Session.Secret, "api-token")
	if err != nil {
		return nil, err
	}
	jwt, err := newJWTSigner(cfg.Session.Secret)
	if err != nil {
		return nil, err
	}
	cliTokens, err := session.NewCodec(cfg.Session.Secret, "cli-session")
	if err != nil {
		return nil, err
	}
	cliCodes, err := session.NewCodec(cfg.Session.Secret, "cli-code")
	if err != nil {
		return nil, err
	}
	downloads, err := loadCLIDownloads(cfg.CLIDownloads)
	if err != nil {
		return nil, fmt.Errorf("Sidegate CLI downloads: %w", err)
	}
	if downloads == nil {
		log.Info("no Sidegate CLI downloads found; the /cli page shows build instructions", "dir", cfg.CLIDownloads)
	}

	s := &Server{
		log:             log,
		public:          public,
		portalHost:      strings.ToLower(public.Hostname()),
		domain:          cfg.Domain,
		secure:          public.Scheme == "https",
		cookieName:      cfg.Session.CookieName,
		lifetime:        cfg.Session.Lifetime,
		refreshInterval: cfg.OIDC.RefreshInterval,
		sessions:        sessions,
		states:          states,
		oauth: &oauth2.Config{
			ClientID:     cfg.OIDC.ClientID,
			ClientSecret: cfg.OIDC.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  public.JoinPath("/oauth2/callback").String(),
			Scopes:       cfg.OIDC.Scopes,
		},
		verifier:       provider.Verifier(&oidc.Config{ClientID: cfg.OIDC.ClientID}),
		endSessionURL:  meta.EndSession,
		oidcCfg:        cfg.OIDC,
		providerLogout: cfg.OIDC.LogoutFromProvider,
		tmpl:           tmpl,
		store:          st,
		adminGroups:    map[string]bool{},
		adminUsers:     map[string]bool{},
		csrfKey:        csrfKey,
		apiKey:         apiKey,
		jwt:            jwt,
		cliTokens:      cliTokens,
		cliCodes:       cliCodes,
		guacd:          cfg.Guacd,
		mfa:            cfg.OIDC.MFA,
		metrics:        newMetrics(),
		checkInterval:  defaultCheckInterval,
		pingInterval:   defaultPingInterval,
		draining:       make(chan struct{}),
		downloads:      downloads,
		cfg:            cfg,
		refreshes:      refreshGroup{ttl: defaultRefreshResultTTL},
	}
	for _, g := range cfg.Admin.Groups {
		s.adminGroups[g] = true
	}
	for _, u := range cfg.Admin.Users {
		u = config.NormalizeUser(u)
		s.adminUsers[u] = true
		if !strings.HasPrefix(u, "sub:") {
			log.Warn("admin.users matches the email or username claim, which some identity providers let users change; prefer admin.groups or sub:<subject>", "entry", u)
		}
	}
	if len(s.adminGroups) == 0 && len(s.adminUsers) == 0 {
		log.Warn("no admin groups or users configured; the admin UI is unavailable")
	}
	if !s.secure && !isLocalHost(s.portalHost) {
		log.Warn("publicURL uses plain HTTP: session cookies are sent unencrypted; use https in production", "publicURL", cfg.PublicURL)
	}
	st.OnAudit = func(e store.AuditEntry) {
		s.emit(Event{Type: EventConfigChange, Time: e.At, User: e.Actor, Fields: map[string]string{"action": e.Action, "target": e.Target}})
	}
	if err := s.initExtensions(); err != nil {
		return nil, fmt.Errorf("extensions: %w", err)
	}
	s.portal = s.portalMux()
	if err := s.Sync(ctx); err != nil {
		return nil, fmt.Errorf("load apps: %w", err)
	}
	return s, nil
}

// Sync loads apps, groups and session revocations from the database and
// swaps them in.
func (s *Server) Sync(ctx context.Context) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	_, sessionsRev, err := s.store.Revisions(ctx)
	if err != nil {
		s.metrics.syncErrors.Inc()
		return err
	}
	apps, groups, rev, err := s.store.Load(ctx)
	if err != nil {
		s.metrics.syncErrors.Inc()
		return err
	}
	revs, err := s.store.Revocations(ctx)
	if err != nil {
		s.metrics.syncErrors.Inc()
		return err
	}
	s.reload(apps, groups, revs)
	s.revision.Store(rev)
	s.sessionsRev.Store(sessionsRev)
	s.metrics.revision.Set(float64(rev))
	return nil
}

// syncRevocations reloads only the session revocations, e.g. after a
// logout, keeping apps and their upstream connections as they are.
func (s *Server) syncRevocations(ctx context.Context) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	_, sessionsRev, err := s.store.Revisions(ctx)
	if err != nil {
		s.metrics.syncErrors.Inc()
		return err
	}
	revs, err := s.store.Revocations(ctx)
	if err != nil {
		s.metrics.syncErrors.Inc()
		return err
	}
	old := s.routes.Load()
	rt := *old
	rt.revokedAll, rt.revokedUsers, rt.ended = revs.All, revs.Users, revs.Ended
	rt.changed = make(chan struct{})
	s.routes.Store(&rt)
	close(old.changed)
	s.sessionsRev.Store(sessionsRev)
	return nil
}

// pruneAudit deletes audit log entries past the retention period. Every
// replica runs it; deleting concurrently is harmless.
func (s *Server) pruneAudit(ctx context.Context, now time.Time) {
	if s.cfg.Audit.RetentionDays == nil || *s.cfg.Audit.RetentionDays == 0 {
		return // keep forever
	}
	days := *s.cfg.Audit.RetentionDays
	n, err := s.store.PruneAudit(ctx, now.AddDate(0, 0, -days))
	switch {
	case err != nil:
		s.log.Warn("prune audit log", "error", err)
	case n > 0:
		s.log.Info("deleted audit log entries past retention", "entries", n, "retentionDays", days)
	}
}

// Watch polls the database revision and syncs when another replica (or a
// direct database edit that bumps the revision) changed something. Once an
// hour it also prunes the audit log.
func (s *Server) Watch(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	var pruned time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if time.Since(pruned) >= time.Hour {
			pruned = time.Now()
			s.pruneAudit(ctx, pruned)
		}
		rev, sessionsRev, err := s.store.Revisions(ctx)
		if err != nil {
			s.metrics.syncErrors.Inc()
			s.log.Warn("poll database revision", "error", err)
			continue
		}
		switch {
		case rev != s.revision.Load():
			err = s.Sync(ctx)
		case sessionsRev != s.sessionsRev.Load():
			err = s.syncRevocations(ctx)
		}
		if err != nil {
			s.log.Warn("sync from database", "error", err)
		}
	}
}

func (s *Server) reload(apps []config.App, groups []store.Group, revs store.Revocations) {
	rt := &routes{
		bySub:        map[string]*app{},
		byName:       map[string]*app{},
		groups:       map[string]bool{},
		groupNames:   map[string]string{},
		groupList:    groups,
		revokedAll:   revs.All,
		revokedUsers: revs.Users,
		ended:        revs.Ended,
		changed:      make(chan struct{}),
	}
	for _, g := range groups {
		rt.groupNames[g.ID] = g.Name
	}
	for g := range s.adminGroups {
		rt.groups[g] = true
	}
	for _, ac := range apps {
		a := &app{
			App:         ac,
			URL:         s.appURL(ac.Subdomain),
			groups:      map[string]bool{},
			users:       map[string]bool{},
			publicExact: map[string]bool{},
		}
		for _, p := range ac.PublicPaths {
			if pre, ok := strings.CutSuffix(p, "*"); ok {
				a.publicPre = append(a.publicPre, pre)
			} else {
				a.publicExact[p] = true
			}
		}
		for _, g := range ac.AllowedGroups {
			if g == "*" {
				a.anyone = true
				continue
			}
			a.groups[g] = true
			rt.groups[g] = true
		}
		for _, u := range ac.AllowedUsers {
			a.users[config.NormalizeUser(u)] = true
		}
		if a.Protocol() == "" {
			a.proxy, a.transport = s.newProxy(a)
		}
		rt.apps = append(rt.apps, a)
		rt.bySub[a.Subdomain] = a
		rt.byName[a.Name] = a
	}
	slices.SortFunc(rt.apps, func(x, y *app) int {
		return strings.Compare(strings.ToLower(x.DisplayTitle()), strings.ToLower(y.DisplayTitle()))
	})

	old := s.routes.Swap(rt)
	if old != nil {
		close(old.changed)
		for _, a := range old.apps {
			if a.transport != nil {
				a.transport.CloseIdleConnections()
			}
		}
	}
	s.metrics.apps.Set(float64(len(rt.apps)))
	s.log.Info("routes loaded", "apps", len(rt.apps), "groups", len(groups))
}

func (s *Server) isAdmin(sess *session.Session) bool {
	if sess == nil {
		return false
	}
	if matchesUser(s.adminUsers, sess) {
		return true
	}
	return slices.ContainsFunc(sess.Groups, func(g string) bool { return s.adminGroups[g] })
}

func (s *Server) appURL(sub string) string {
	host := sub + "." + s.domain
	if p := s.public.Port(); p != "" {
		host = net.JoinHostPort(host, p)
	}
	return s.public.Scheme + "://" + host + "/"
}

// Handler returns the proxy handler wrapped with access logging.
func (s *Server) Handler() http.Handler {
	return s.accessLog(s)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.secure {
		// Every host under the domain is served by the proxy, so the policy
		// can include subdomains.
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
	host := canonicalHost(r.Host)
	if host == s.portalHost {
		setLogApp(r, appPortal)
		s.portal.ServeHTTP(w, r)
		return
	}
	if sub, ok := strings.CutSuffix(host, "."+s.domain); ok {
		if a := s.routes.Load().bySub[sub]; a != nil {
			setLogApp(r, a.Name)
			s.serveApp(w, r, a)
			return
		}
	}
	setLogApp(r, appUnknown)
	s.renderError(w, r, http.StatusNotFound, "Application not found",
		fmt.Sprintf("No application is configured for %s.", host))
}

func (s *Server) serveApp(w http.ResponseWriter, r *http.Request, a *app) {
	sess := s.authenticate(w, r)
	if sess == nil && a.Protocol() != "" {
		sess = s.authenticateBearer(w, r) // Sidegate CLI
	}
	if !a.Public && !a.isPublicPath(r.URL) {
		if sess == nil {
			s.metrics.denied.WithLabelValues(a.Name, "unauthenticated").Inc()
			s.emit(userEvent(EventAccessDenied, nil, a.Name, map[string]string{"reason": "unauthenticated"}))
			s.requireLogin(w, r)
			return
		}
		if !a.allows(sess) {
			s.metrics.denied.WithLabelValues(a.Name, "forbidden").Inc()
			s.emit(userEvent(EventAccessDenied, sess, a.Name, map[string]string{"reason": "forbidden"}))
			s.log.Info("access denied", "app", a.Name, "user", sess.Username, "sub", sess.Subject)
			s.renderError(w, r, http.StatusForbidden, "Access denied",
				fmt.Sprintf("You are signed in as %s, but you are not allowed to access %s. Ask an administrator to add you to one of the app's groups.", sess.Display(), a.DisplayTitle()))
			return
		}
		if mfa, maxAge := a.stepUp(sess); mfa || maxAge > 0 {
			s.metrics.denied.WithLabelValues(a.Name, "step_up").Inc()
			s.emit(userEvent(EventAccessDenied, sess, a.Name, map[string]string{"reason": "step_up"}))
			s.requireStepUp(w, r, mfa, maxAge)
			return
		}
	}
	setLogUser(r, sess)
	if a.Protocol() != "" {
		s.serveRemote(w, r, a, sess)
		return
	}
	a.proxy.ServeHTTP(w, r.WithContext(withSession(r.Context(), sess)))
}

// visibleApps returns the apps listed in the portal for sess.
func (s *Server) visibleApps(sess *session.Session) []*app {
	var out []*app
	for _, a := range s.routes.Load().apps {
		if !a.Hidden && a.allows(sess) {
			out = append(out, a)
		}
	}
	return out
}

// isLocalHost reports whether host only resolves to this machine, where
// plain HTTP is acceptable (local demos and tests).
func isLocalHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		host == "localtest.me" || strings.HasSuffix(host, ".localtest.me")
}

func canonicalHost(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

type ctxKey struct{}

func withSession(ctx context.Context, s *session.Session) context.Context {
	return context.WithValue(ctx, ctxKey{}, s)
}

func sessionFrom(ctx context.Context) *session.Session {
	s, _ := ctx.Value(ctxKey{}).(*session.Session)
	return s
}
