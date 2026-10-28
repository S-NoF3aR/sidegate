// SPDX-License-Identifier: AGPL-3.0-only

// Package config loads and validates the sidegate startup settings.
//
// Apps and groups live in the database and are managed in the admin UI.
// Settings come from an optional YAML file, overridden by SIDEGATE_*
// environment variables.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Listen is the address of the main proxy listener.
	Listen string `yaml:"listen"`
	// HealthListen serves /healthz and /readyz on a separate port so probes
	// never collide with an app's own paths.
	HealthListen string `yaml:"healthListen"`
	// PublicURL is the external URL of the portal, e.g. https://apps.example.com.
	// It hosts the app overview, the admin UI and the OIDC callback.
	PublicURL string `yaml:"publicURL"`
	// Domain is the parent domain of all apps; app "grafana" is served
	// at grafana.<domain>. The session cookie is scoped to this domain.
	Domain   string `yaml:"domain"`
	LogLevel string `yaml:"logLevel"`

	Database Database `yaml:"database"`
	// Guacd is the host:port of guacd (Apache Guacamole's protocol daemon),
	// which renders RDP and SSH sessions for the browser. Without it,
	// remote apps are only reachable through the Sidegate CLI.
	Guacd string `yaml:"guacd"`
	// CLIDownloads is a directory with the Sidegate CLI binaries (as built by
	// "make release" into dist/cli), offered on the portal's /cli page.
	CLIDownloads string `yaml:"cliDownloads"`
	// SourceURL is linked from every page as the place to get this
	// version's source code, as the AGPL requires for network use. Point it
	// at your fork if you run a modified version.
	SourceURL string  `yaml:"sourceURL"`
	Admin     Admin   `yaml:"admin"`
	Session   Session `yaml:"session"`
	OIDC      OIDC    `yaml:"oidc"`

	Recording Recording `yaml:"recording"`
	Audit     Audit     `yaml:"audit"`

	// Groups and Apps seed an empty database on first start, which eases
	// migrating from file based configuration. Afterwards they are ignored.
	Groups map[string]string `yaml:"groups"`
	Apps   []App             `yaml:"apps"`
}

// Recording configures session recording of browser RDP and SSH
// sessions. Which apps are recorded is chosen in the admin UI.
// Audit configures the audit log.
type Audit struct {
	// RetentionDays is how long audit log entries are kept; 0 keeps them
	// forever. Unset means 365.
	RetentionDays *int `yaml:"retentionDays"`
}

type Recording struct {
	// Dir is where recordings are stored. With several replicas it must
	// be shared (e.g. a ReadWriteMany volume). Empty disables recording.
	Dir string `yaml:"dir"`
	// RetentionDays is how long recordings are kept.
	RetentionDays int `yaml:"retentionDays"`
}

type Database struct {
	// URL is postgres://user:pass@host/db or sqlite:/path/to/file.db.
	URL string `yaml:"url"`
}

// Admin lists who may use the admin UI. Groups are IdP group IDs.
type Admin struct {
	Groups []string `yaml:"groups"`
	Users  []string `yaml:"users"`
}

type Session struct {
	CookieName string        `yaml:"cookieName"`
	Secret     string        `yaml:"secret"`
	Lifetime   time.Duration `yaml:"lifetime"`
}

type OIDC struct {
	Issuer       string   `yaml:"issuer"`
	ClientID     string   `yaml:"clientID"`
	ClientSecret string   `yaml:"clientSecret"`
	Scopes       []string `yaml:"scopes"`
	// GroupsClaim is the ID token claim holding group memberships. Dotted
	// paths reach into nested objects, e.g. "realm_access.roles".
	GroupsClaim   string `yaml:"groupsClaim"`
	UsernameClaim string `yaml:"usernameClaim"`
	// RefreshInterval is how often a session is revalidated with the IdP
	// using its refresh token. Disabled users and changed group
	// memberships take effect within this interval.
	RefreshInterval time.Duration `yaml:"refreshInterval"`
	// LogoutFromProvider also ends the IdP session on logout.
	LogoutFromProvider bool `yaml:"logoutFromProvider"`
	MFA                MFA  `yaml:"mfa"`
}

// MFA defines how apps with requireMFA ask for and recognize multi-factor
// sign-ins.
type MFA struct {
	// AMR values that count as MFA in the ID token's amr claim.
	AMR []string `yaml:"amr"`
	// ACR values that count as MFA in the acr claim (or Entra's acrs).
	ACR []string `yaml:"acr"`
	// AuthParams are added to the authorization request for a step-up,
	// e.g. acr_values, or Entra's claims parameter for an authentication
	// context.
	AuthParams map[string]string `yaml:"authParams"`
}

type App struct {
	Name        string `yaml:"name" json:"name"`
	Title       string `yaml:"title" json:"title,omitempty"`
	Description string `yaml:"description" json:"description,omitempty"`
	// Icon is an image URL or a short text such as an emoji.
	Icon string `yaml:"icon" json:"icon,omitempty"`
	// Category groups apps in the portal; "/" nests categories, e.g.
	// "Monitoring/Logs". Empty means uncategorized.
	Category  string `yaml:"category" json:"category,omitempty"`
	Subdomain string `yaml:"subdomain" json:"subdomain"`
	Upstream  string `yaml:"upstream" json:"upstream"`
	// AllowedGroups lists group IDs (or, in the seed file, names from
	// Config.Groups). "*" allows every authenticated user.
	AllowedGroups []string `yaml:"allowedGroups" json:"allowedGroups,omitempty"`
	// AllowedUsers matches the email or username claim (case-insensitive),
	// or the subject with "sub:<subject>" (case-sensitive).
	AllowedUsers []string `yaml:"allowedUsers" json:"allowedUsers,omitempty"`
	// Public apps are proxied without authentication.
	Public bool `yaml:"public" json:"public,omitempty"`
	// PublicPaths skip authentication on an otherwise protected app:
	// "/health" matches exactly, "/static/*" matches the prefix "/static/".
	PublicPaths []string `yaml:"publicPaths" json:"publicPaths,omitempty"`
	// Hidden apps are reachable but not listed in the portal.
	Hidden bool `yaml:"hidden" json:"hidden,omitempty"`
	// PassHostHeader forwards the original Host instead of the upstream's.
	PassHostHeader bool `yaml:"passHostHeader" json:"passHostHeader,omitempty"`
	// RequireMFA only admits sessions whose sign-in included MFA (see
	// OIDC.MFA); others are sent back to the IdP for a step-up.
	RequireMFA bool `yaml:"requireMFA" json:"requireMFA,omitempty"`
	// MaxAuthAgeMinutes, if set, requires a sign-in within that many
	// minutes; older sessions must sign in again.
	MaxAuthAgeMinutes int `yaml:"maxAuthAgeMinutes" json:"maxAuthAgeMinutes,omitempty"`
	// HostHeader, if set, is sent as the Host header to the upstream.
	HostHeader         string `yaml:"hostHeader" json:"hostHeader,omitempty"`
	InsecureSkipVerify bool   `yaml:"insecureSkipVerify" json:"insecureSkipVerify,omitempty"`
}

// DisplayTitle returns the title shown in the portal.
func (a *App) DisplayTitle() string {
	if a.Title != "" {
		return a.Title
	}
	return a.Name
}

// DefaultSourceURL is where this build's source code is published; set at
// build time with -ldflags "-X sidegate/internal/config.DefaultSourceURL=...".
var DefaultSourceURL = "https://github.com/s-nof3ar/sidegate"

var (
	envRef    = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	dnsLabel  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	appName   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
	hostValue = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(:[0-9]{1,5})?$`)
	minSecret = 32
)

// Load reads the config file at path, if it exists, applies SIDEGATE_*
// environment overrides and validates the result. An empty path means
// environment only.
func Load(path string) (*Config, error) {
	var data []byte
	if path != "" {
		var err error
		if data, err = os.ReadFile(path); err != nil {
			return nil, err
		}
	}
	return Parse(data)
}

// Parse expands ${VAR} references from the environment, decodes the YAML,
// applies SIDEGATE_* overrides and validates the result.
func Parse(data []byte) (*Config, error) {
	expanded := envRef.ReplaceAllFunc(data, func(m []byte) []byte {
		return []byte(os.Getenv(string(m[2 : len(m)-1])))
	})
	cfg := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(expanded))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.applyEnv(); err != nil {
		return nil, err
	}
	cfg.setDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// applyEnv overrides settings from SIDEGATE_* variables, so the proxy can
// run without a config file.
func (c *Config) applyEnv() error {
	var errs []error
	str := func(key string, dst *string) {
		if v, ok := os.LookupEnv("SIDEGATE_" + key); ok {
			*dst = v
		}
	}
	list := func(key string, dst *[]string) {
		if v, ok := os.LookupEnv("SIDEGATE_" + key); ok {
			*dst = strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' })
		}
	}
	dur := func(key string, dst *time.Duration) {
		if v, ok := os.LookupEnv("SIDEGATE_" + key); ok {
			d, err := time.ParseDuration(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("SIDEGATE_%s: %w", key, err))
			}
			*dst = d
		}
	}
	integer := func(key string, dst *int) {
		if v, ok := os.LookupEnv("SIDEGATE_" + key); ok {
			n, err := strconv.Atoi(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("SIDEGATE_%s: %w", key, err))
			}
			*dst = n
		}
	}
	boolean := func(key string, dst *bool) {
		if v, ok := os.LookupEnv("SIDEGATE_" + key); ok {
			b, err := strconv.ParseBool(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("SIDEGATE_%s: %w", key, err))
			}
			*dst = b
		}
	}

	str("LISTEN", &c.Listen)
	str("HEALTH_LISTEN", &c.HealthListen)
	str("PUBLIC_URL", &c.PublicURL)
	str("DOMAIN", &c.Domain)
	str("LOG_LEVEL", &c.LogLevel)
	str("DATABASE_URL", &c.Database.URL)
	str("GUACD", &c.Guacd)
	str("CLI_DOWNLOADS", &c.CLIDownloads)
	str("SOURCE_URL", &c.SourceURL)
	str("RECORDING_DIR", &c.Recording.Dir)
	integer("RECORDING_RETENTION_DAYS", &c.Recording.RetentionDays)
	if _, ok := os.LookupEnv("SIDEGATE_AUDIT_RETENTION_DAYS"); ok {
		c.Audit.RetentionDays = new(int)
		integer("AUDIT_RETENTION_DAYS", c.Audit.RetentionDays)
	}
	list("ADMIN_GROUPS", &c.Admin.Groups)
	list("ADMIN_USERS", &c.Admin.Users)
	str("SESSION_COOKIE_NAME", &c.Session.CookieName)
	str("SESSION_SECRET", &c.Session.Secret)
	dur("SESSION_LIFETIME", &c.Session.Lifetime)
	str("OIDC_ISSUER", &c.OIDC.Issuer)
	str("OIDC_CLIENT_ID", &c.OIDC.ClientID)
	str("OIDC_CLIENT_SECRET", &c.OIDC.ClientSecret)
	list("OIDC_SCOPES", &c.OIDC.Scopes)
	str("OIDC_GROUPS_CLAIM", &c.OIDC.GroupsClaim)
	str("OIDC_USERNAME_CLAIM", &c.OIDC.UsernameClaim)
	dur("OIDC_REFRESH_INTERVAL", &c.OIDC.RefreshInterval)
	boolean("OIDC_LOGOUT_FROM_PROVIDER", &c.OIDC.LogoutFromProvider)
	list("OIDC_MFA_AMR", &c.OIDC.MFA.AMR)
	list("OIDC_MFA_ACR", &c.OIDC.MFA.ACR)
	if v, ok := os.LookupEnv("SIDEGATE_OIDC_MFA_AUTH_PARAMS"); ok {
		q, err := url.ParseQuery(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("SIDEGATE_OIDC_MFA_AUTH_PARAMS: %w", err))
		}
		c.OIDC.MFA.AuthParams = map[string]string{}
		for k := range q {
			c.OIDC.MFA.AuthParams[k] = q.Get(k)
		}
	}
	return errors.Join(errs...)
}

func (c *Config) setDefaults() {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.HealthListen == "" {
		c.HealthListen = ":8081"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.SourceURL == "" {
		c.SourceURL = DefaultSourceURL
	}
	if c.Audit.RetentionDays == nil {
		days := 365
		c.Audit.RetentionDays = &days
	}
	if c.Recording.RetentionDays == 0 {
		c.Recording.RetentionDays = 90
	}
	if c.CLIDownloads == "" {
		c.CLIDownloads = "/usr/share/sidegate/cli" // where the image puts them
	}
	if c.Session.CookieName == "" {
		c.Session.CookieName = "_sidegate"
	}
	if c.Session.Lifetime == 0 {
		c.Session.Lifetime = 12 * time.Hour
	}
	if len(c.OIDC.Scopes) == 0 {
		c.OIDC.Scopes = []string{"openid", "profile", "email"}
	}
	if c.OIDC.GroupsClaim == "" {
		c.OIDC.GroupsClaim = "groups"
	}
	if c.OIDC.UsernameClaim == "" {
		c.OIDC.UsernameClaim = "preferred_username"
	}
	if c.OIDC.RefreshInterval == 0 {
		c.OIDC.RefreshInterval = 5 * time.Minute
	}
	if len(c.OIDC.MFA.AMR) == 0 && len(c.OIDC.MFA.ACR) == 0 {
		c.OIDC.MFA.AMR = []string{"mfa"}
	}
	c.Domain = strings.TrimSuffix(strings.ToLower(c.Domain), ".")
	for i := range c.Apps {
		c.Apps[i].Normalize()
	}
}

// PortalHost returns the lower-cased host name of PublicURL.
func (c *Config) PortalHost() string {
	u, err := url.Parse(c.PublicURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func (c *Config) validate() error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if c.Recording.RetentionDays < 1 {
		fail("recording.retentionDays must be at least 1")
	}
	if *c.Audit.RetentionDays < 0 {
		fail("audit.retentionDays must be 0 (keep forever) or more")
	}

	pub, err := url.Parse(c.PublicURL)
	switch {
	case c.PublicURL == "":
		fail("publicURL (SIDEGATE_PUBLIC_URL) is required")
	case err != nil:
		fail("publicURL: %v", err)
	case pub.Scheme != "http" && pub.Scheme != "https":
		fail("publicURL must use http or https")
	case pub.Host == "" || (pub.Path != "" && pub.Path != "/"):
		fail("publicURL must be a bare origin such as https://apps.example.com")
	}
	if c.Domain == "" {
		fail("domain (SIDEGATE_DOMAIN) is required")
	} else if pub != nil && pub.Host != "" {
		h := strings.ToLower(pub.Hostname())
		if h != c.Domain && !strings.HasSuffix(h, "."+c.Domain) {
			fail("publicURL host %q must be inside domain %q", h, c.Domain)
		}
	}
	if c.Database.URL == "" {
		fail("database.url (SIDEGATE_DATABASE_URL) is required")
	}
	if len(c.Session.Secret) < minSecret {
		fail("session.secret (SIDEGATE_SESSION_SECRET) must be at least %d characters", minSecret)
	}
	if c.Session.Lifetime < time.Minute {
		fail("session.lifetime must be at least 1m")
	}
	if c.OIDC.Issuer == "" {
		fail("oidc.issuer (SIDEGATE_OIDC_ISSUER) is required")
	}
	if c.OIDC.ClientID == "" {
		fail("oidc.clientID (SIDEGATE_OIDC_CLIENT_ID) is required")
	}
	if c.OIDC.RefreshInterval < 30*time.Second {
		fail("oidc.refreshInterval must be at least 30s")
	}

	seen := map[string]string{}
	for i := range c.Apps {
		a := &c.Apps[i]
		if err := a.Validate(c.Domain, c.PortalHost()); err != nil {
			errs = append(errs, err)
		}
		if other, dup := seen[a.Subdomain]; dup {
			fail("app %s: subdomain %q already used by app %s", a.Name, a.Subdomain, other)
		}
		seen[a.Subdomain] = a.Name
	}
	return errors.Join(errs...)
}

// Normalize fills defaults and canonicalizes case.
func (a *App) Normalize() {
	a.Name = strings.TrimSpace(a.Name)
	if a.Subdomain == "" {
		a.Subdomain = a.Name
	}
	a.Subdomain = strings.ToLower(strings.TrimSpace(a.Subdomain))
	a.Upstream = strings.TrimSpace(a.Upstream)
	a.HostHeader = strings.TrimSpace(a.HostHeader)
	a.Category = NormalizeCategory(a.Category)
	for i, u := range a.AllowedUsers {
		a.AllowedUsers[i] = NormalizeUser(u)
	}
	for i, p := range a.PublicPaths {
		a.PublicPaths[i] = strings.TrimSpace(p)
	}
}

// Protocol returns "rdp" or "ssh" for remote apps (upstream rdp:// or
// ssh://), and "" for web apps.
func (a *App) Protocol() string {
	scheme, _, _ := strings.Cut(strings.ToLower(a.Upstream), "://")
	if scheme == "rdp" || scheme == "ssh" {
		return scheme
	}
	return ""
}

// RemoteTarget is the parsed upstream of an RDP or SSH app.
type RemoteTarget struct {
	Protocol string
	Host     string
	Port     string
	// Params are guacd connection parameters from the URL query.
	Params map[string]string
}

// Address returns host:port.
func (t RemoteTarget) Address() string { return net.JoinHostPort(t.Host, t.Port) }

// KnownHostsLine returns the configured SSH host key as a known_hosts
// entry, as guacd expects it, or "" if none is set.
func (t RemoteTarget) KnownHostsLine() string {
	key := t.Params["host-key"]
	if key == "" {
		return ""
	}
	host := t.Host
	if t.Port != "22" {
		host = "[" + t.Host + "]:" + t.Port
	}
	return host + " " + key
}

var (
	rdpSecurity = []string{"any", "nla", "nla-ext", "tls", "vmconnect", "rdp"}
	sshHostKey  = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]+={0,2}$`)
	remoteUsage = map[string]string{
		"rdp": "rdp://host[:port][?security=nla&ignore-cert=true&domain=CORP]",
		"ssh": "ssh://host[:port][?host-key=ssh-ed25519%20AAAA...]",
	}
)

// RemoteTarget parses the upstream of a remote app:
//
//	rdp://host[:port][?security=nla&ignore-cert=true&domain=CORP]  (port 3389)
//	ssh://host[:port][?host-key=ssh-ed25519%20AAAAC3Nza...]         (port 22)
//
// Query values are decoded without turning "+" into a space, so base64
// host keys can be pasted as they are.
func (a *App) RemoteTarget() (RemoteTarget, error) {
	proto := a.Protocol()
	u, err := url.Parse(a.Upstream)
	if proto == "" || err != nil || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.User != nil || u.Fragment != "" {
		return RemoteTarget{}, fmt.Errorf("upstream must look like %s", remoteUsage[proto])
	}
	t := RemoteTarget{Protocol: proto, Host: u.Hostname(), Port: u.Port(), Params: map[string]string{}}
	if t.Port == "" {
		t.Port = map[string]string{"rdp": "3389", "ssh": "22"}[proto]
	}
	if p, err := strconv.Atoi(t.Port); err != nil || p < 1 || p > 65535 {
		return t, fmt.Errorf("invalid port %q", t.Port)
	}
	for kv := range strings.SplitSeq(u.RawQuery, "&") {
		if kv == "" {
			continue
		}
		rk, rv, _ := strings.Cut(kv, "=")
		k, err1 := url.PathUnescape(rk)
		val, err2 := url.PathUnescape(rv)
		if err1 != nil || err2 != nil {
			return t, fmt.Errorf("invalid option %q", kv)
		}
		switch {
		case proto == "rdp" && k == "security":
			if !slices.Contains(rdpSecurity, val) {
				return t, fmt.Errorf("security must be one of %s", strings.Join(rdpSecurity, ", "))
			}
		case proto == "rdp" && k == "ignore-cert":
			if val != "true" && val != "false" {
				return t, errors.New("ignore-cert must be true or false")
			}
		case proto == "rdp" && k == "domain":
		case proto == "ssh" && k == "host-key":
			// Key type and key as printed by ssh-keyscan; the space is
			// written as %20.
			if !sshHostKey.MatchString(val) {
				return t, errors.New("host-key must be the key type and base64 key as printed by ssh-keyscan, e.g. ssh-ed25519%20AAAAC3Nza...")
			}
		default:
			return t, fmt.Errorf("unknown option %q for %s (usage: %s)", k, proto, remoteUsage[proto])
		}
		t.Params[k] = val
	}
	return t, nil
}

// NormalizeCategory trims every segment of a category path and drops empty
// ones, so " Monitoring / Logs/ " becomes "Monitoring/Logs".
func NormalizeCategory(c string) string {
	var segs []string
	for seg := range strings.SplitSeq(c, "/") {
		if seg = strings.Join(strings.Fields(seg), " "); seg != "" {
			segs = append(segs, seg)
		}
	}
	return strings.Join(segs, "/")
}

// ValidPublicPath reports whether p is a usable public path pattern: an
// absolute, canonical path, optionally ending in "*" for a prefix match.
func ValidPublicPath(p string) bool {
	prefix, wildcard := strings.CutSuffix(p, "*")
	if !strings.HasPrefix(prefix, "/") || strings.ContainsAny(prefix, "*?#;\\ \t%") {
		return false
	}
	if wildcard && prefix == "/" {
		return false // that's a public app
	}
	return CanonicalPath(prefix)
}

// CanonicalPath reports whether p contains no "." or ".." segments and no
// duplicate slashes. A trailing slash is allowed.
// ValidAppName reports whether name is a valid app name.
func ValidAppName(name string) bool { return appName.MatchString(name) }

// NormalizeUser normalizes an entry of allowedUsers or admin.users: emails
// and usernames are matched case-insensitively, "sub:<subject>" entries
// exactly.
func NormalizeUser(u string) string {
	u = strings.TrimSpace(u)
	if len(u) > 4 && strings.EqualFold(u[:4], "sub:") {
		return "sub:" + strings.TrimSpace(u[4:])
	}
	return strings.ToLower(u)
}

func CanonicalPath(p string) bool {
	clean := path.Clean(p)
	if strings.HasSuffix(p, "/") && clean != "/" {
		clean += "/"
	}
	return clean == p
}

// Validate checks a single app. Uniqueness across apps is checked by the
// caller (or enforced by the database).
func (a *App) Validate(domain, portalHost string) error {
	var errs []error
	label := a.Name
	if label == "" {
		label = "(unnamed)"
	}
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("app %s: "+format, append([]any{label}, args...)...))
	}
	if !appName.MatchString(a.Name) {
		fail("name must be 1-63 letters, digits, '.', '_' or '-'")
	}
	if !dnsLabel.MatchString(a.Subdomain) {
		fail("subdomain %q is not a valid DNS label (lowercase letters, digits and dashes)", a.Subdomain)
	}
	if portalHost != "" && a.Subdomain+"."+domain == portalHost {
		fail("subdomain collides with the portal host")
	}
	if a.Protocol() != "" {
		if _, err := a.RemoteTarget(); err != nil {
			fail("%v", err)
		}
		if a.Public || len(a.PublicPaths) > 0 || a.HostHeader != "" || a.PassHostHeader || a.InsecureSkipVerify {
			fail("RDP and SSH apps can't be public or use public paths, Host header or TLS options")
		}
	} else if u, err := url.Parse(a.Upstream); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		fail("upstream must be an absolute http(s) URL, rdp://host[:port] for a remote desktop or ssh://host[:port] for a shell")
	}
	if a.MaxAuthAgeMinutes < 0 || a.MaxAuthAgeMinutes > 525600 {
		fail("maxAuthAgeMinutes must be between 0 (off) and 525600 (one year)")
	}
	if a.Public && (a.RequireMFA || a.MaxAuthAgeMinutes > 0) {
		fail("a public app can't require MFA or a recent sign-in")
	}
	if len(a.Category) > 200 || strings.Count(a.Category, "/") > 4 {
		fail("category must be at most 200 characters and 5 levels deep")
	}
	for _, p := range a.PublicPaths {
		if !ValidPublicPath(p) {
			fail("public path %q must be an absolute path like /health or /static/* (* only at the end; no '.' or '..' segments, ';', '%%' or backslashes)", p)
		}
	}
	if a.HostHeader != "" {
		if a.PassHostHeader {
			fail("choose either the original Host header or a custom one, not both")
		}
		if !hostValue.MatchString(a.HostHeader) {
			fail("host header %q must be a host name with an optional port", a.HostHeader)
		}
	}
	if !a.Public && len(a.AllowedGroups) == 0 && len(a.AllowedUsers) == 0 {
		fail("choose at least one group or user, \"all signed-in users\", or make the app public")
	}
	return errors.Join(errs...)
}

// ResolveGroup maps a friendly group name from the seed file to its ID.
func (c *Config) ResolveGroup(g string) string {
	if id, ok := c.Groups[g]; ok {
		return id
	}
	return g
}
