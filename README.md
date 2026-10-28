# Sidegate

An identity-aware reverse proxy. Users sign in once via OIDC (e.g. Microsoft
Entra ID), get a portal listing the apps they may use, and every app is
exposed on its own subdomain with access restricted to configured groups.
Apps and permissions are stored in PostgreSQL (or SQLite) and managed in a
built-in admin UI.

```
                    ┌───────────────────────── Sidegate ──────────────────────────┐
browser ──https──▶  │ apps.example.com          → portal + /oauth2/* (login)      │
                    │ grafana.apps.example.com  → check groups → grafana:3000     │──▶ upstreams
                    │ argocd.apps.example.com   → check groups → argocd:443       │
                    │ apps.example.com/admin    → manage apps, groups, audit log  │
                    └───────────────┬──────────────────────────────┬──────────────┘
                                    │ OIDC (code flow + PKCE)      │ apps, access rules
                                    ▼                              ▼
                            Entra ID / any OIDC IdP        PostgreSQL / SQLite
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed diagrams.

## Features

- **OIDC login** (authorization code flow with PKCE and nonce), works with Entra ID, Keycloak, Okta, Google, Dex, …
- **Single sign-on across subdomains**: one encrypted session cookie scoped to the parent domain.
- **Session revalidation** with refresh tokens (every 5 min by default): users disabled in the IdP lose access within minutes, and group changes apply without signing in again.
- **Per-app authorization** by group, by user, for any signed-in user, or public.
- **Admin UI** to create, edit and delete apps, assign groups and users, name IdP groups, and review an **audit log** of every change.
- **Management API and Terraform provider**: manage apps and groups as code with API tokens.
- **SQL storage**: PostgreSQL for multi-replica deployments, SQLite for a single container. Changes reach all replicas within ~5 s, no restart needed.
- **Portal** at the root domain showing only the apps the user may access, grouped in a **category tree** (e.g. `Monitoring/Logs`) with collapsible sections and search (`/` to focus), plus `/api/me` as JSON.
- **Identity headers** for upstreams: `X-Forwarded-User`, `X-Forwarded-Email`, `X-Forwarded-Preferred-Username`, `X-Forwarded-Groups` (oauth2-proxy compatible), plus a **signed JWT** apps can verify. Spoofed copies from clients are stripped, including `_` variants.
- **Per-app MFA and maximum sign-in age** with step-up authentication (works with Entra Conditional Access authentication contexts).
- **Sign out a user, or everyone, immediately** from the admin UI or API.
- **Prometheus metrics** on the internal port.
- **Remote access to RDP and SSH** behind the same sign-in and permissions: in the browser (via guacd) or with native clients (mstsc, ssh, scp, VS Code, …) through `sidegate`.
- **Session recording** of browser RDP and SSH sessions, with playback in the admin UI and audited access.
- The proxy's session cookie is **never forwarded** to upstreams.
- WebSockets, SSE and streaming responses are supported.
- **No session store**: sessions live in AES-GCM encrypted cookies, so you can run any number of replicas without Redis or sticky sessions.
- **No config file required**: every setting can come from `SIDEGATE_*` environment variables.
- Small distroless image running as non-root, with a read-only root filesystem.

### Why Go?

Go fits this well. `net/http/httputil.ReverseProxy` handles HTTP/1.1, HTTP/2,
WebSockets and streaming, `coreos/go-oidc` is the de facto OIDC library, and
the result is a single static binary in a ~20 MB image. The established tools
in this space (oauth2-proxy, Pomerium, Traefik) are written in Go for the same
reasons. Rust would give a slightly lower memory footprint but slower
development and a less mature OIDC ecosystem, so it's not worth switching.

## Quick start (local demo, no Entra needed)

```sh
docker compose up --build
```

Open <http://apps.localtest.me:8080> (`*.localtest.me` resolves to 127.0.0.1).
The demo uses a mock IdP: enter any username and as claims e.g.

```json
{"groups": ["developers"], "email": "me@example.com", "name": "Me"}
```

You'll see *Who Am I* (echoes the identity headers) but get a 403 on
*Admin Tool*. Sign in with `"groups": ["admins"]` to also get the **Admin**
button (<http://apps.localtest.me:8080/admin>). The demo stores its data in a
PostgreSQL container; `docker compose down -v` resets it.

## Configuration

Configuration has two parts:

- **Startup settings** (domain, OIDC, secrets, database, admins): a YAML file
  and/or `SIDEGATE_*` environment variables. Changing them needs a restart.
- **Apps, access rules and group names**: stored in the database and managed
  in the [admin UI](#admin-ui). Changes apply immediately.

### Startup settings

The file is read from `-config <path>` (or `SIDEGATE_CONFIG`), by default
`/etc/sidegate/config.yaml` if it exists. Environment variables override the
file, so you can run with environment variables alone. `${VAR}` references
inside the file are also expanded.

| YAML | Environment variable | Default |
|---|---|---|
| `publicURL` | `SIDEGATE_PUBLIC_URL` | required, e.g. `https://apps.example.com` (portal, admin UI, OIDC callback) |
| `domain` | `SIDEGATE_DOMAIN` | required; apps live at `<subdomain>.<domain>` |
| `database.url` | `SIDEGATE_DATABASE_URL` | required: `postgres://user:pass@host:5432/db?sslmode=require` or `sqlite:/data/sidegate.db` |
| `admin.groups` | `SIDEGATE_ADMIN_GROUPS` | IdP group IDs allowed to use the admin UI (comma-separated in env) |
| `admin.users` | `SIDEGATE_ADMIN_USERS` | users allowed to use the admin UI: `sub:<subject>` (recommended), or email/username (logged as a warning, since some IdPs let users change those) |
| `session.secret` | `SIDEGATE_SESSION_SECRET` | required, ≥ 32 chars, e.g. `openssl rand -base64 48` |
| `session.lifetime` | `SIDEGATE_SESSION_LIFETIME` | `12h`, absolute maximum before signing in again |
| `session.cookieName` | `SIDEGATE_SESSION_COOKIE_NAME` | `_sidegate` |
| `oidc.issuer` | `SIDEGATE_OIDC_ISSUER` | required, e.g. `https://login.microsoftonline.com/<tenant-id>/v2.0` |
| `oidc.clientID` | `SIDEGATE_OIDC_CLIENT_ID` | required |
| `oidc.clientSecret` | `SIDEGATE_OIDC_CLIENT_SECRET` | |
| `oidc.scopes` | `SIDEGATE_OIDC_SCOPES` | `openid profile email`; add `offline_access` for Entra refresh tokens |
| `oidc.refreshInterval` | `SIDEGATE_OIDC_REFRESH_INTERVAL` | `5m` (min `30s`), see [Session revalidation](#session-revalidation) |
| `oidc.groupsClaim` | `SIDEGATE_OIDC_GROUPS_CLAIM` | `groups`; dotted paths work, e.g. `realm_access.roles` |
| `oidc.usernameClaim` | `SIDEGATE_OIDC_USERNAME_CLAIM` | `preferred_username` |
| `oidc.logoutFromProvider` | `SIDEGATE_OIDC_LOGOUT_FROM_PROVIDER` | `false`; also end the IdP session on sign-out |
| `listen` | `SIDEGATE_LISTEN` | `:8080` |
| `healthListen` | `SIDEGATE_HEALTH_LISTEN` | `:8081` (`/healthz`, `/readyz`) |
| `logLevel` | `SIDEGATE_LOG_LEVEL` | `info` |
| `guacd` | `SIDEGATE_GUACD` | none; `host:port` of guacd for RDP/SSH in the browser |
| `cliDownloads` | `SIDEGATE_CLI_DOWNLOADS` | `/usr/share/sidegate/cli`; Sidegate CLI binaries for the `/cli` page |
| `recording.dir` | `SIDEGATE_RECORDING_DIR` | none; where session recordings are stored (see [Session recording](#session-recording)) |
| `recording.retentionDays` | `SIDEGATE_RECORDING_RETENTION_DAYS` | `90` |
| `audit.retentionDays` | `SIDEGATE_AUDIT_RETENTION_DAYS` | `365`; audit log entries older than this are deleted (hourly); `0` keeps them forever |

Example: [`deploy/kubernetes/configmap.yaml`](deploy/kubernetes/configmap.yaml) (Entra ID).

### Database

The schema is created and migrated automatically on startup (safe with
several replicas starting at once on PostgreSQL).

- **PostgreSQL**: use for Kubernetes or any setup with more than one
  replica, e.g. a managed database or [CloudNativePG](https://cloudnative-pg.io/).
- **SQLite**: fine for a single container; mount a volume for the file
  (`sqlite:/data/sidegate.db`). Don't use it with several replicas.

Every replica keeps the apps in memory and polls a revision counter every
5 s. If the database becomes unreachable the proxy keeps serving with the
last known apps; only admin changes fail.

### Admin UI

Users in `admin.groups`/`admin.users` see an **Admin** button in the portal
(`/admin`):

- **Apps**: create, edit, delete; the list is grouped by category and can be
  filtered. Per app: subdomain, upstream URL, title, description, icon (image
  URL or emoji), category, and access:
  - *Public*: no sign-in at all
  - *All signed-in users*
  - *Groups*: tick named groups, or enter other group IDs or names
  - *Users*: email addresses or usernames, or `sub:<subject>` (the IdP's
    immutable user ID, matched exactly; prefer it where users can change
    their email or username)

  A user can open the app if they match **any** rule. Apps without any rule
  are rejected, so nothing gets exposed by accident.
  - *Public paths*: paths reachable without sign-in on an otherwise
    protected app, e.g. `/health` (exact match) or `/static/*` (prefix
    `/static/`). If the visitor is signed in, identity headers are still sent.
  - *Host header* sent to the upstream: the upstream's own host (default),
    the original host (`grafana.apps.example.com`), or a custom value such as
    `grafana.internal.example.com`. `X-Forwarded-Host` always carries the
    original host.
  - *Sign-in requirements*: require MFA and/or a sign-in within N minutes
    (see [MFA and sign-in age](#mfa-and-sign-in-age)).
  - Further options: hide from the portal, skip upstream TLS verification.
- **Categories**: an app's category decides where it appears in the portal.
  `/` nests categories, e.g. `Monitoring/Logs`. The portal shows a category
  tree in a sidebar (top-level chips on phones). Clicking a category narrows
  the view to that subtree and puts it in the URL (`#/Monitoring/Logs`), so
  it can be bookmarked. Sections can be collapsed, which is remembered per
  browser. Apps without a category are listed under *Other*. If no app has a
  category, the portal stays a flat grid.
- **Groups**: give IdP group IDs (Entra object IDs) readable names. Named
  groups can be ticked on the app form and are sent by name in
  `X-Forwarded-Groups`.
- **Users**: everyone who signed in, with last sign-in. **Sign out** ends all
  sessions of a user immediately (on other replicas within ~5 s); **Sign out
  everyone** ends all sessions, e.g. after an incident. Users can sign in
  again unless the IdP blocks them, so disable the account in Entra to lock
  someone out for good.
- **Audit log**: who changed what and when, with the full app definition.
  Kept for `audit.retentionDays` (default 365 days; `0` keeps entries
  forever).

Forms are protected against CSRF (a per-session token plus `Origin` and
`Sec-Fetch-Site` checks), which matters because app subdomains count as the
same site as the portal.

### Management API and Terraform

Apps and groups can be managed as code through the
[Terraform provider](terraform-provider-sidegate/README.md):

```hcl
resource "sidegate_group" "developers" {
  group_id = "33333333-3333-3333-3333-333333333333"
  name     = "developers"
}

resource "sidegate_app" "grafana" {
  name           = "grafana"
  upstream       = "http://grafana.monitoring.svc:3000"
  allowed_groups = [sidegate_group.developers.group_id]
  public_paths   = ["/api/health"]
}
```

Both use the JSON API at `<publicURL>/api/v1`, authenticated with
`Authorization: Bearer <token>`. Admins create and revoke tokens under
**Admin → API tokens**; a token is shown once and can manage all apps and
groups. The session cookie doesn't grant API access.

| Method | Path | |
|---|---|---|
| `GET` | `/api/v1/apps` | List apps |
| `POST` | `/api/v1/apps` | Create an app (`201`) |
| `GET` | `/api/v1/apps/{name}` | Get an app |
| `PUT` | `/api/v1/apps/{name}` | Replace an app (all fields; omitted fields are reset) |
| `DELETE` | `/api/v1/apps/{name}` | Delete an app (`204`) |
| `GET` | `/api/v1/users` | Users who signed in |
| `POST` | `/api/v1/sessions/revoke` | Sign a user out everywhere, body `{"subject": "…"}` (`204`), e.g. from an offboarding workflow |
| `POST` | `/api/v1/sessions/revoke-all` | Sign everybody out (`204`) |
| `GET` | `/api/v1/groups` | List named groups |
| `GET` | `/api/v1/groups/{id}` | Get a group |
| `PUT` | `/api/v1/groups/{id}` | Create or rename a group, body `{"name": "…"}` |
| `DELETE` | `/api/v1/groups/{id}` | Remove a group name (`204`) |

App body (all fields except `name` and `upstream` optional; `url` is read-only):

```json
{
  "name": "grafana", "subdomain": "grafana", "upstream": "http://grafana:3000",
  "title": "Grafana", "description": "", "icon": "", "category": "Monitoring",
  "public": false, "hidden": false,
  "allowedGroups": ["33333333-…"], "allowedUsers": ["alice@example.com"],
  "publicPaths": ["/api/health"],
  "passHostHeader": false, "hostHeader": "", "insecureSkipVerify": false,
  "requireMFA": false, "maxAuthAgeMinutes": 0
}
```

Errors are JSON: `{"error": "…"}`, plus `"details": [...]` for validation
errors (`400`). Unknown fields are rejected. `404`/`409` mean not found or a
conflict (name, subdomain or group name taken). API reads go to the database
directly, so a write through one replica is immediately visible through all.

### Migrating from a YAML config

If the config file still contains `groups:` and `apps:`, they are imported
into the database on startup **when it has no apps yet**:

```yaml
groups:
  developers: 33333333-3333-3333-3333-333333333333
apps:
  - name: grafana
    upstream: http://grafana.monitoring.svc:3000
    category: Monitoring/Dashboards
    allowedGroups: [developers]          # names from groups:, IDs, or "*"
    allowedUsers: [alice@example.com]
    publicPaths: [/api/health, /public/*]
    hostHeader: grafana.internal.example.com   # or passHostHeader: true
    # also: subdomain, title, description, icon, public, hidden, insecureSkipVerify
```

 After that, the file's apps are ignored, and the admin UI is the
source of truth. [`deploy/compose/config.yaml`](deploy/compose/config.yaml)
uses this to seed the demo.

## Microsoft Entra ID setup

1. **App registration** → *New registration*. Redirect URI (Web):
   `https://apps.example.com/oauth2/callback`.
2. *Certificates & secrets* → new client secret → `OIDC_CLIENT_SECRET`.
3. *Token configuration* → *Add groups claim* → *Security groups* and select
   **Group ID** for the ID token.
4. Recommended: under *Enterprise applications → your app → Properties*, set
   *Assignment required* = Yes, assign the relevant groups, and in the
   manifest set `"groupMembershipClaims": "ApplicationGroup"`. The token then
   only contains assigned groups, which avoids the **groups overage** problem
   (Entra drops the `groups` claim entirely when a user is in more than 200
   groups; the proxy logs a warning when this happens).
5. Add `offline_access` to `oidc.scopes` so Entra issues refresh tokens
   (see [Session revalidation](#session-revalidation)).
6. If `logoutFromProvider: true`, also add
   `https://apps.example.com/oauth2/signed-out` as a redirect URI.
7. Use `issuer: https://login.microsoftonline.com/<tenant-id>/v2.0` with the
   tenant **ID** (not `common`), and the group **object IDs** in the config
   (optionally named via `groups:`).

Alternatively, use **app roles** instead of groups: define roles in the app
registration, assign groups to them and set `groupsClaim: roles`. Role names
are readable and never overflow.

## Session revalidation

At login the proxy stores the IdP's refresh token (encrypted) in the session.
Every `refreshInterval` it redeems the token on the user's next request and
rebuilds the identity from the new ID token:

| IdP response | Effect |
|---|---|
| success | name, email and **groups updated**; new refresh token stored |
| `400`/`401` (e.g. `invalid_grant`: user disabled or deleted, sessions revoked via *Revoke sessions* in Entra, password reset) | session ends immediately; browsers are sent to the login page, API calls get `401` |
| network error / `5xx` | session kept, retried after 30 s, so an IdP outage doesn't lock everyone out |

So a user disabled in Entra loses access at most `refreshInterval` (default
5 min) after their last refresh. Parallel requests share one refresh, so
refresh-token rotation is safe on a single replica. The newest refreshed state
of each session is also kept in the database (encrypted with
`session.secret`), so a client that holds an older copy, e.g. after a
long RDP session or on another replica, continues from it instead of
redeeming a rotated token. Two replicas may still occasionally redeem the
same token at the very same moment. That's harmless with Entra, which
doesn't invalidate the old token, but IdPs with strict rotation and no grace
period could end that session.

If the IdP returns no refresh token (a warning is logged at login), sessions
can't be revalidated and last until `session.lifetime`.

Large refresh tokens (Entra's are a few KB) are split across numbered
cookies (`_sidegate`, `_sidegate_1`, …). None of them are forwarded to upstreams.

Not supported: OIDC back-channel/front-channel logout notifications (Entra ID
doesn't offer back-channel logout, and front-channel logout via third-party
iframes is unreliable in today's browsers).

## Remote access (RDP and SSH)

Apps whose upstream is `rdp://…` or `ssh://…` are remote apps. They get a
subdomain, a portal tile (tagged *RDP* or *SSH*), groups, users, MFA,
sign-in age and the audit log like any other app.

```
rdp://win1.corp.example.com:3389?security=nla&ignore-cert=true&domain=CORP
ssh://bastion.corp.example.com:22?host-key=ecdsa-sha2-nistp256%20AAAAE2VjZHNh...
```

| Protocol | Option | Values | Default |
|---|---|---|---|
| RDP (port 3389) | `security` | `any`, `nla`, `nla-ext`, `tls`, `rdp`, `vmconnect` | `any` |
| | `ignore-cert` | `true`, `false` | `false` |
| | `domain` | Windows domain passed to the host | none |
| SSH (port 22) | `host-key` | the server's public key, type and key as printed by `ssh-keyscan`, with the space written as `%20` | none: any key is accepted |

No credentials are stored. Users sign in to Windows or the SSH server
themselves: RDP with NLA asks in a form before connecting (username
prefilled), SSH prompts in the terminal.

**Pin SSH host keys** for browser access, so guacd can't be fooled by a
man in the middle. guacd checks a single key and negotiates **ECDSA**
first, so pin the ECDSA key if the server has one, otherwise Ed25519, then
RSA:

```sh
ssh-keyscan -t ecdsa bastion.corp.example.com   # → ecdsa-sha2-nistp256 AAAA…
```

On a mismatch the browser shows "Aborted" and guacd logs "Host key does not
match". Native `ssh` clients check host keys themselves (see below).

Users can connect in two ways.

### In the browser

Opening `https://win1.apps.example.com` shows the remote desktop, and
`https://bastion.apps.example.com` a terminal, in the browser tab, with
keyboard, mouse and touch, full screen, the remote size following the
window, best-effort clipboard sync, and a Ctrl+Alt+Del button for RDP.
The proxy relays the Guacamole protocol to **guacd**, Apache Guacamole's
protocol daemon, which you run next to it:

```yaml
guacd: guacd:4822        # SIDEGATE_GUACD; in Kubernetes the guacd Service (deploy/kubernetes/guacd.yaml)
```

The proxy performs the guacd handshake itself: the browser never chooses the
target host or any connection option. The tunnel only accepts WebSocket
requests from the app's own origin.

### With native clients: the Sidegate CLI

`sidegate` lets mstsc, the Windows App or Microsoft Remote Desktop
(macOS), xfreerdp, Remmina, `ssh`, `scp`, `rsync`, VS Code Remote-SSH,
Ansible and friends connect through the proxy:

```sh
sidegate login https://apps.example.com   # opens the browser to sign in
sidegate apps                             # list your apps
sidegate rdp win1                         # tunnel + start your RDP client
sidegate ssh alice@bastion                # ssh through the proxy
sidegate ssh alice@bastion uptime         # …with a remote command
sidegate tunnel bastion -port 2222        # just a local port, for any client
```

For everything SSH-based, a `~/.ssh/config` entry is the most convenient:

```
Host *.apps.example.com
    ProxyCommand sidegate proxy %h
```

Then `ssh bastion.apps.example.com`, `scp file bastion.apps.example.com:`,
`rsync`, `git` over SSH or VS Code all go through the proxy. `sidegate ssh`
does the same without the config entry. Host keys are remembered under the
app's host name (`HostKeyAlias`), so `ssh` verifies them as usual.

Each connection is tunneled over a WebSocket (`/.sidegate/tcp` on the app's
host) to the target. Signing in shows a confirmation page, then runs a
separate OIDC sign-in. The browser hands only a one-minute code to the CLI's
listener on `127.0.0.1`; the CLI exchanges it for its token together with a
secret that never leaves the CLI (PKCE), so the code is useless to anyone
who finds it, e.g. in the browser history. The token is stored with mode
`0600` in the user config dir.
The proxy revalidates it like a browser session and sends refreshed tokens
back. If an app requires MFA or a recent sign-in, the CLI opens the browser
again.

#### Installing the Sidegate CLI

Users get it from the portal at **`https://apps.example.com/cli`** (linked
from the portal and from every RDP/SSH page). The page picks their operating
system and offers a one-line install, manual downloads with SHA-256 checksums,
and next steps with their own portal URL and apps:

```powershell
# Windows (PowerShell, no admin rights): installs to %LOCALAPPDATA%\Programs\sidegate, adds it to PATH
irm https://apps.example.com/cli/install.ps1 | iex
```

```sh
# Linux and macOS: installs to ~/.local/bin (or $SIDEGATE_CLI_DIR)
curl -fsSL https://apps.example.com/cli/install.sh | sh
```

The page also has step-by-step guides for remote desktop (per OS client),
SSH (one-off commands, the `~/.ssh/config` entry for scp/rsync/VS Code,
port forwarding), troubleshooting and a command reference.

The installers verify the checksum before installing anything. Binaries are
offered for Windows, Linux and macOS on x64 and ARM64. Downloads need no
sign-in, so scripts and device management tools can fetch them directly from
`/cli/download/<file>` (with `/cli/download/SHA256SUMS`).

The Docker image includes the binaries. Elsewhere, build them with
`make release` and point `cliDownloads` (`SIDEGATE_CLI_DOWNLOADS`, default
`/usr/share/sidegate/cli`) at `dist/cli`. The binaries are not code-signed;
for a managed rollout, sign them and distribute them via Intune, winget or
your package manager.

### Session recording

Browser sessions of selected RDP and SSH apps can be recorded and played back
in the admin UI (**Admin → Recordings**):

- **What is recorded:** everything shown on screen (the Guacamole stream guacd
  sends to the browser), not keystrokes. The proxy writes the recording
  itself, so guacd needs no storage.
- **Users are told:** the app's page shows a notice and a *Recorded* badge
  before and during the session.
- **Fail closed:** if a recording can't be started or written (e.g. a full
  disk), the session doesn't start or is ended.
- **Native sessions** through the Sidegate CLI are end-to-end encrypted between
  the user's client and the host, so they can't be recorded. They stay
  allowed and are logged as usual (user, app, start, duration).
- **Access is audited:** every playback is written to the audit log
  (`recording.view`), and changes to the settings too (`setting.save`).
  Admins can't delete recordings; they expire after the retention period.

```yaml
recording:
  dir: /recordings        # SIDEGATE_RECORDING_DIR; shared by all replicas (ReadWriteMany volume)
  retentionDays: 90       # SIDEGATE_RECORDING_RETENTION_DAYS
```

Then choose the apps under **Admin → Recordings**. Recordings are stored as
`<dir>/<yyyymmdd>/<id>.guac` (Guacamole's recording format) with a `.json`
metadata file, readable only by the proxy's user. Size depends on what
happens on screen: roughly tens of KB per minute for a terminal and up to
several MB per minute for a busy desktop. In Kubernetes, enable the
`recordings` component (see [Kubernetes](#kubernetes)).

### Live sessions

Remote sessions can run for hours, so the proxy keeps checking each open
connection, browser or native. The same applies to WebSockets (and other
upgraded connections) of web apps. A connection ends, with a message in the
browser for RDP/SSH, when:

| Event | Ends open connections |
|---|---|
| The user signs out in the portal | that browser session's connections, immediately |
| `sidegate logout` | that CLI session's connections, immediately |
| An admin signs the user (or everyone) out | all of the user's connections, immediately |
| The user loses access to the app, or the app is deleted | immediately |
| The app now requires MFA the session lacks, or its max sign-in age has passed | immediately when the app changes, otherwise within 30 s |
| The IdP revokes the session (account disabled in Entra, sessions revoked, password reset) | at the next session refresh (`oidc.refreshInterval`, default 5 min) |
| The session reaches `session.lifetime` | within 30 s |
| The Sidegate instance shuts down (deploy, scale-down) | immediately, with a "please reconnect" message |

"Immediately" means at once on the replica that handled the change, and
within ~5 s on the others, when they pick it up from the database. A
temporarily unreachable IdP does not end connections. Starts and ends are logged with user, app, protocol,
client and duration, and counted in `sidegate_remote_sessions_total` /
`sidegate_remote_sessions_active`.

An open connection and the browser (or CLI) share the same session. They
share refresh results too (in memory, and via the database once the
connection has closed or on another replica), so neither presents a refresh
token the other already redeemed. That matters with IdPs that accept every
refresh token only once (Entra doesn't).

The demo (`docker compose up`) includes guacd, a Linux desktop (xrdp, sign in
as `ubuntu` / `ubuntu`) and an SSH server (`demo` / `demo`).

## MFA and sign-in age

Per app, *Require MFA* only admits sessions whose sign-in included
multi-factor authentication, and *maximum sign-in age* requires a sign-in
within N minutes. Users who don't meet them are sent back to the IdP
("step-up"), and the result is checked. If the IdP doesn't deliver, the user
gets an explanation instead of a redirect loop. API calls and WebSockets get
`401` with `{"error":"step-up authentication required"}`.

How MFA is requested and recognized is configured once:

```yaml
oidc:
  mfa:
    amr: [mfa]            # amr claim values that count as MFA (default)
    acr: []               # acr claim (or Entra "acrs") values that count as MFA
    authParams: {}        # extra authorization parameters for a step-up
```

**Entra ID**: v2.0 ID tokens usually carry no `amr` claim, so use a
Conditional Access *authentication context*:

1. Entra admin center → Protection → Conditional Access → Authentication
   contexts: create one, e.g. `c1` "Require MFA".
2. Create a Conditional Access policy targeting that authentication context
   that requires MFA (or phishing-resistant MFA).
3. Configure the proxy to request and check it:

```yaml
oidc:
  mfa:
    acr: [c1]
    authParams:
      claims: '{"id_token":{"acrs":{"essential":true,"value":"c1"}}}'
```

**Keycloak and others**: request a level of authentication with
`authParams: {acr_values: "gold"}` and set `acr: [gold]`, or rely on
`amr: [mfa]` if your IdP emits it.

For the sign-in age, the proxy sends `max_age` and `prompt=login`, and checks
the ID token's `auth_time`. Without a plausible `auth_time` the sign-in age is
unknown, and apps with `maxAuthAgeMinutes` refuse access with an
explanation. **Entra ID** only includes `auth_time` as an optional claim: add
it under *Token configuration → Add optional claim → ID → auth_time*. MFA
and sign-in time come from the original sign-in; background session
refreshes don't change them. A long RDP/SSH connection therefore ends once
the app's max sign-in age has passed.

Environment: `SIDEGATE_OIDC_MFA_AMR`, `SIDEGATE_OIDC_MFA_ACR` (comma-separated),
`SIDEGATE_OIDC_MFA_AUTH_PARAMS` (URL query syntax, e.g. `acr_values=gold`).

## Identity for upstreams

Every proxied request of a signed-in user carries:

- `X-Forwarded-User`, `X-Forwarded-Preferred-Username`, `X-Forwarded-Email`,
  `X-Forwarded-Groups`: plain headers, fine for apps only reachable through
  the proxy.
- `X-Sidegate-Jwt-Assertion`: a JWT signed by the proxy (ES256), valid for
  5 minutes, which apps can verify and so don't have to trust the network:

```json
{
  "iss": "https://apps.example.com",
  "aud": "https://grafana.apps.example.com",
  "sub": "…", "preferred_username": "alice@example.com", "email": "alice@example.com",
  "name": "Alice", "groups": ["developers"], "mfa": true, "auth_time": 1761570000,
  "iat": 1761570123, "nbf": 1761570093, "exp": 1761570423
}
```

Verify it with the public keys at `https://apps.example.com/.well-known/jwks.json`
and check that `iss` is the portal URL and `aud` is the app's own origin, so a
token sent to one app can't be replayed to another. Many apps support this
directly, e.g. Grafana (`[auth.jwt]` with `header_name =
X-Sidegate-Jwt-Assertion`, `jwk_set_url`, `email_claim = email`). The signing
key is derived from `session.secret`, so all replicas share it; changing the
secret rotates it.

### Internal host names in responses

If an upstream builds absolute URLs from its own host name (common with a
custom Host header), the proxy rewrites `Location`/`Content-Location`
headers pointing at the upstream's host to the app's public host, and drops
cookie `Domain` attributes naming the internal host. Relative URLs and other
hosts are left alone.

## Metrics

Prometheus metrics are served at `:8081/metrics` (the internal health port,
never via the public listener):

| Metric | Labels |
|---|---|
| `sidegate_requests_total` | `app`, `method`, `code` |
| `sidegate_request_duration_seconds` | `app` (histogram, excludes WebSockets) |
| `sidegate_upstream_errors_total` | `app` |
| `sidegate_access_denied_total` | `app`, `reason` = `unauthenticated` / `forbidden` / `step_up` |
| `sidegate_logins_total` | `result` = `success` / `failure` |
| `sidegate_session_refreshes_total` | `result` = `success` / `revoked` / `error` |
| `sidegate_revoked_sessions_rejected_total` | |
| `sidegate_remote_sessions_total`, `sidegate_remote_sessions_active` | `app`, `protocol` = `rdp` / `ssh`, `client` = `browser` / `native` |
| `sidegate_apps`, `sidegate_config_revision` | gauges |
| `sidegate_database_sync_errors_total` | |

`app` is the app name, `_portal` for the portal host and `_unknown` for
unknown hosts. Go runtime and process metrics are included. In Kubernetes,
scrape port `8081` (`health`) with a ServiceMonitor or pod annotations.

## Deployment

### Building

```sh
make test                     # all tests, with the race detector
make release VERSION=1.0.0    # dist/: proxy for linux/amd64+arm64, dist/cli/: the CLI for all platforms,
                              #   checksums, LICENSE, NOTICE, THIRD_PARTY_NOTICES
make image VERSION=1.0.0      # Docker image sidegate:1.0.0
make notices                  # dist/THIRD_PARTY_NOTICES: license texts of every bundled dependency

# Where your published source lives (linked in the UI as the AGPL requires):
make release VERSION=1.0.0 SOURCE_URL=https://github.com/acme/sidegate
```

The image contains the Sidegate CLI binaries for the download page (about
40 MB). Build with `--build-arg CLI_PLATFORMS=""` to leave them out, or list
only the platforms you need.

### Docker

Single container with SQLite, configured entirely via environment variables:

```sh
docker build -t sidegate .
docker run -d -p 8080:8080 -v sidegate-data:/data \
  -e SIDEGATE_PUBLIC_URL=https://apps.example.com \
  -e SIDEGATE_DOMAIN=apps.example.com \
  -e SIDEGATE_DATABASE_URL=sqlite:/data/sidegate.db \
  -e SIDEGATE_SESSION_SECRET="$(openssl rand -base64 48)" \
  -e SIDEGATE_OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0 \
  -e SIDEGATE_OIDC_CLIENT_ID=<application-id> \
  -e SIDEGATE_OIDC_CLIENT_SECRET=… \
  -e SIDEGATE_OIDC_SCOPES="openid profile email offline_access" \
  -e SIDEGATE_ADMIN_GROUPS=<admin-group-object-id> \
  sidegate
```

Generate the session secret once and keep it; a new secret signs everybody out.

Put TLS in front of it (load balancer, Traefik, Caddy, …) with a certificate
for `apps.example.com` and `*.apps.example.com`, and point a wildcard DNS
record at it.

### Kubernetes

```sh
kubectl create namespace sidegate
kubectl -n sidegate create secret generic sidegate-secrets \
  --from-literal=SIDEGATE_SESSION_SECRET="$(openssl rand -base64 48)" \
  --from-literal=SIDEGATE_OIDC_CLIENT_SECRET='…' \
  --from-literal=SIDEGATE_DATABASE_URL='postgres://sidegate:…@<host>:5432/sidegate?sslmode=require'
# edit deploy/kubernetes/configmap.yaml (domain, Entra IDs, admin group),
# httproute.yaml (your Gateway) and the image in kustomization.yaml
kubectl apply -k deploy/kubernetes
```

PostgreSQL is not part of the manifests: use a managed database or an
operator such as CloudNativePG, and create an empty database for the proxy.

The manifests include:

- a Deployment (probes, hardened security context, graceful shutdown) with a
  **HorizontalPodAutoscaler** (2–10 replicas on CPU; needs metrics-server;
  scales down slowly because removed pods end their RDP/SSH sessions),
- a Service (`http`, plus `metrics` on 8081), a PodDisruptionBudget,
- a Gateway API `HTTPRoute` for the portal host plus the wildcard, attached
  to your Gateway (Envoy Gateway, Cilium, Istio, NGINX Gateway Fabric,
  Traefik, your cloud's gateway, …). `ingress.yaml` is a fallback for
  clusters still on an Ingress controller. Wildcard certificates from
  cert-manager need a DNS-01 solver.

Optional parts, enabled in `kustomization.yaml`:

- `components: [recordings]`: a ReadWriteMany volume for
  [session recordings](#session-recording) (Azure Files, EFS, NFS, …); set
  the storage class in `recordings/pvc.yaml`.
- `networkpolicy.yaml`: only the gateway (port 8080) and
  Prometheus (8081) may connect; adjust the namespace labels first.
- `servicemonitor.yaml`: scraping with the Prometheus Operator. Without it,
  the pods' `prometheus.io` annotations work for annotation-based scraping.

**Gateway requirements.** Whatever gateway or ingress controller you use,
it must:

- not time out requests: RDP/SSH WebSockets stay open for hours. The
  `HTTPRoute` sets `timeouts.request: "0s"`, which disables the timeout on
  implementations that support it;
- stream responses (server-sent events, downloads) and uploads instead of
  buffering them;
- accept request and response headers up to ~32 KB: the session cookies
  can reach ~15 KB with large refresh tokens and many groups. Envoy-based
  gateways allow 60 KB by default; elsewhere, too small a limit shows up as
  *400* errors (request too large) or *502* errors (upstream header too big)
  for those users.

ingress-nginx is retired (no releases or security fixes since March 2026),
so the manifests no longer target it.

**Idle connections.** Sidegate pings RDP/SSH tunnels (browser and
Sidegate CLI) every 25 s, so idle sessions survive load balancer idle
timeouts (e.g. AWS ALB: 60 s), and dead clients are noticed.

**Rolling updates.** On SIGTERM the proxy fails its readiness probe, keeps
serving for 5 s until it no longer receives new requests, then tells open
RDP/SSH sessions that the server is restarting (users reconnect and land on
another pod), and finishes running requests within 20 s.

guacd runs as its own Deployment (`guacd.yaml`, 2 replicas, Service
`guacd:4822`, PodDisruptionBudget), so it scales independently of the proxy.
Size it by **concurrent browser RDP sessions**, not by users: roughly 1 CPU
core and 0.5–1 GiB of memory per 10–25 RDP sessions (SSH needs far less).
Each session stays on one guacd pod; restarting or scaling down a pod ends
its sessions. guacd has no authentication of its own, so a NetworkPolicy
lets only the proxy pods connect to it (this needs a CNI that enforces
NetworkPolicy, e.g. Calico or Cilium). If you only use the Sidegate CLI, remove
`guacd.yaml` from `kustomization.yaml` and `guacd` from the config.

## Endpoints

| Host | Path | Purpose |
|---|---|---|
| portal | `/` | App overview |
| portal | `/api/me` | Current user and accessible apps (JSON) |
| portal | `/admin` | Admin UI (apps, groups, API tokens, audit log) |
| portal | `/api/v1/*` | Management API (bearer token) |
| portal | `/oauth2/start?rd=…` | Begin login, return to `rd` (portal/app hosts only) |
| portal | `/oauth2/callback` | OIDC redirect URI |
| portal | `/oauth2/logout` | Sign out of all apps (`POST`; `GET` shows a confirmation) |
| app | `/*` | Proxied to the upstream after authorization |
| portal | `/.well-known/jwks.json` | Public keys for the identity JWT |
| portal | `/cli` | Sidegate CLI download page |
| portal | `/cli/install.sh`, `/cli/install.ps1`, `/cli/download/*` | Installers and binaries (no sign-in) |
| portal | `/cli/login`, `/cli/token`, `/cli/logout` | Sign-in, code exchange and sign-out for the Sidegate CLI |
| RDP/SSH app | `/` | Browser client (desktop or terminal) |
| RDP/SSH app | `/.sidegate/guac`, `/.sidegate/tcp` | WebSocket tunnels (browser via guacd, native via the Sidegate CLI) |
| `:8081` | `/healthz`, `/readyz`, `/metrics` | Liveness, readiness, Prometheus |

Unauthenticated browser navigations are redirected to the login page;
API calls (non-GET or `Sec-Fetch-Mode` other than `navigate`) and WebSocket
upgrades get `401` instead.

## Security notes

- Use a **dedicated domain** (e.g. `apps.example.com`): the session cookie is
  scoped to it, and any host under it that is *not* served by this proxy
  would receive that cookie.
- **Apps under the domain trust each other to a degree.** They are one
  "site" for the browser, so:
  - a page of one app can send requests (form posts, WebSockets) to another
    app with the user's session. Apps that rely only on Sidegate's identity
    headers should check `Origin` or use their own CSRF protection;
  - JavaScript on an app's pages could overwrite Sidegate's session cookie
    for the domain. Sidegate removes such cookies from app *responses*,
    but can't stop scripts.

  So only put apps under the domain whose content you trust, and keep
  untrusted or user-generated content on other domains.
- With an `https` `publicURL`, every response carries
  `Strict-Transport-Security: max-age=31536000; includeSubDomains`. Apps
  can't override it. A plain-`http` `publicURL` is only meant for local
  demos; the server warns about it at startup.
- Emails the IdP marks as unverified (`email_verified: false`) are ignored
  for `allowedUsers` and `admin.users`.
- Upstreams must only be reachable through the proxy (NetworkPolicies,
  internal services); otherwise the identity headers can be forged by
  calling the upstream directly.
- Signing out requires a `POST` from the portal or an app host, so other
  websites can't sign users out. It ends the session on the server, not just in the browser: the
  session's ID is recorded until it would have expired, so copies of the
  cookie (or a CLI token) stop working on every replica.
- Only groups referenced by some app are stored in the session to keep the
  cookie small. Group changes in the IdP, and groups newly referenced by an
  app, take effect at the user's next refresh (see
  [Session revalidation](#session-revalidation)).
- The session cookie contains the refresh token, encrypted with AES-256-GCM
  using a key derived from `session.secret`. Keep the secret safe; rotating it
  signs everybody out.
- Public paths are matched against the canonical request path only.
  Requests with `.`/`..` segments, duplicate slashes, `;`, backslashes or
  percent-encoded slashes/dots (e.g. `/static/..;/admin`,
  `/static/%2e%2e/admin`) always require sign-in, because upstreams such as
  Tomcat or IIS would normalize them to a protected path.
- The proxy (and guacd) need network access to RDP and SSH hosts; the hosts
  themselves should accept those connections only from there.
- guacd must only be reachable by the proxy: it has no authentication and
  connects to whatever host it is told to (see the NetworkPolicy in
  `deploy/kubernetes/guacd.yaml`).
- Admin access is granted only via `admin.groups`/`admin.users` in the
  startup settings, never via the database, so a database compromise can't
  grant someone admin rights. API tokens are stored as an HMAC keyed with a
  value derived from `session.secret`, so rows inserted into the database
  can't create working tokens either (rotating the secret invalidates all
  tokens). Anyone with write access to the database can
  still change app permissions, so protect it accordingly.

## Development

```sh
make test   # or: go test -race ./...
# also run the store tests against PostgreSQL:
SIDEGATE_TEST_POSTGRES_URL='postgres://postgres:pw@localhost:5432/postgres?sslmode=disable' go test ./internal/store
```

The tests include an end-to-end login flow against an in-process mock OIDC
provider, the RDP and SSH tunnels (against a fake guacd and a TCP echo host,
including origin checks, ping handling, host-key handling, CLI sign-in and
live-session revocation), session refresh (group changes, disabled user, IdP outage), chunked
cookies, authorization, header spoofing, cookie stripping, open-redirect
checks, the admin UI (permissions, CSRF, validation, create/update/delete,
audit log), the management API and tokens, session revocation, MFA and
sign-in-age step-up, signed identity JWTs, redirect rewriting, metrics, the store on SQLite and
PostgreSQL, multi-replica sync and WebSocket passthrough.

Third-party code: `internal/server/web/static/vendor/` contains
guacamole-common-js 1.5.0 (Apache License 2.0, license file alongside),
verified against the npm registry's integrity hash.

## License

| Part | License |
|---|---|
| Sidegate: server, CLI, web UI (everything outside `terraform-provider-sidegate/`) | [GNU AGPL v3](LICENSE) (`AGPL-3.0-only`) |
| `terraform-provider-sidegate/` | [Mozilla Public License 2.0](terraform-provider-sidegate/LICENSE) |
| Third-party components | their own licenses, collected in `THIRD_PARTY_NOTICES` (`make notices`; shipped in releases, at `/usr/share/doc/sidegate/` in the image and next to the CLI downloads) |

Every source file carries an SPDX license identifier.

**AGPL in practice:** you may use, modify and run Sidegate freely, also
commercially. If you run a *modified* version for others over a network, you
must offer them its source code. Every page links to it (footer, CLI
download page); set `sourceURL` (`SIDEGATE_SOURCE_URL`) to where your
modified source is published.

Contributions are accepted under the same licenses, with a sign-off (DCO),
see [CONTRIBUTING.md](CONTRIBUTING.md).

## Possible next steps

- Policies for clipboard, drive and printer redirection per app; S3 storage
  for session recordings
- SSH certificates issued by the proxy, so users need no keys on servers
- Other TCP services (databases, Kubernetes API) through the same tunnel
- Code-signed Sidegate CLI binaries and packages (winget, Homebrew, deb/rpm)
- Read-only or per-app scoped API tokens, token expiry
- Publish the Terraform provider to a registry
- Fetch groups from Microsoft Graph on overage
- Export of the audit log and events to a SIEM, SCIM provisioning
- Delegated admins (e.g. per category)
