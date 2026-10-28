# Architecture

How Sidegate is built. User documentation is in the [README](README.md).

## Components

```mermaid
flowchart TB
    subgraph clients["Clients"]
        browser["Browser<br/>portal, web apps, RDP/SSH in the browser"]
        cli["Sidegate CLI<br/>sidegate ssh, scp, VS Code, mstsc, xfreerdp"]
        tf["Terraform / CI<br/>API token sgt_…"]
        prom["Prometheus / Kubernetes probes"]
    end

    lb["Gateway / load balancer<br/>TLS, wildcard certificate *.domain"]

    subgraph proxy["Sidegate server (one or more replicas)"]
        router["accessLog → ServeHTTP<br/>routes by Host header"]

        subgraph portal["Portal host (publicURL)"]
            portalpage["/ portal + category tree<br/>/api/me"]
            oauth["/oauth2/* sign-in, callback, logout"]
            admin["/admin/* admin UI<br/>(admin.groups / admin.users, CSRF)"]
            api["/api/v1/* REST API"]
            clipages["/cli download page, installers<br/>/cli/login, /cli/logout"]
            jwks["/.well-known/jwks.json"]
            extroutes["/admin/recordings<br/>session recording module"]
        end

        subgraph appsub["App hosts (subdomain.domain)"]
            authn["1. authenticate<br/>session cookie or CLI token sgs_…"]
            authz["2. public path? allows?<br/>MFA / max sign-in age step-up"]
            rp["ReverseProxy<br/>identity headers + signed JWT,<br/>Host header, redirect rewriting"]
            remote["serveRemote (rdp:// ssh://)<br/>/.sidegate/guac · /.sidegate/tcp<br/>watchSession ends revoked sessions"]
        end

        sessions["sessions<br/>sealed cookies, refresh tokens,<br/>refreshGroup, liveSessions"]
        routes[("routes (in memory)<br/>apps, groups, revocations")]
        store["store<br/>SQL, migrations, audit log"]
        ext["Modules (internal/recording)<br/>hooks: remote streams, admin pages,<br/>events (login, remote.start/end, …)"]
    end

    health["Health port :8081<br/>/healthz /readyz /metrics"]

    subgraph external["Backends"]
        db[("PostgreSQL / SQLite<br/>apps, access, groups, users,<br/>tokens, revocations, audit")]
        idp["OIDC provider<br/>Entra ID, Keycloak, …"]
        upstreams["Web app upstreams"]
        guacd["guacd :4822"]
        hosts["RDP / SSH hosts"]
        recdir[("Recordings directory<br/>shared volume")]
    end

    browser --> lb
    cli --> lb
    tf --> lb
    prom --> health
    lb --> router
    router -->|portal host| portal
    router -->|app subdomain| authn
    authn --> authz
    authz -->|web app| rp
    authz -->|remote app| remote

    authn -.-> sessions
    oauth -.-> sessions
    sessions <-->|code flow + PKCE,<br/>refresh tokens| idp
    oauth --> idp

    admin --> store
    api --> store
    authz -.->|lookups| routes
    store -->|Sync every 5 s| routes
    store --> db
    store -.->|OnAudit| ext
    remote -.->|screen stream| ext
    ext -->|recordings| recdir

    rp --> upstreams
    remote -->|browser, Guacamole protocol| guacd
    guacd --> hosts
    remote -->|sidegate, raw TCP| hosts
```

Sessions live in encrypted cookies, so replicas share nothing but the
database. Each replica keeps apps, groups and revocations in memory and polls
the database revision every 5 s.

## Sign-in and session revalidation

```mermaid
sequenceDiagram
    autonumber
    actor U as Browser
    participant P as Sidegate
    participant I as OIDC provider
    participant A as App upstream

    U->>P: GET https://grafana.apps.example.com/
    P-->>U: 302 /oauth2/start?rd=… (no session)
    U->>P: GET /oauth2/start
    P-->>U: 302 to IdP (state cookie with PKCE verifier + nonce)
    U->>I: authorize, user signs in (MFA if required)
    I-->>U: 302 /oauth2/callback?code=…
    U->>P: GET /oauth2/callback
    P->>I: exchange code (+ PKCE verifier)
    I-->>P: ID token + refresh token
    P-->>U: 302 back to app, session cookie for *.apps.example.com
    U->>P: GET https://grafana.apps.example.com/
    P->>P: check groups, MFA, sign-in age
    P->>A: proxied request + X-Forwarded-* + signed JWT
    A-->>P: response
    P-->>U: response

    Note over U,P: later, after refreshInterval (default 5 min)
    U->>P: next request
    P->>I: refresh_token grant
    alt user still active
        I-->>P: new tokens (groups updated)
        P-->>U: response + refreshed cookie
    else user disabled / sessions revoked (400/401)
        I-->>P: invalid_grant
        P-->>U: cookie cleared, redirect to sign-in
    end
```

## Remote access (RDP / SSH)

```mermaid
flowchart LR
    subgraph browserside["In the browser"]
        b["Browser<br/>guacamole-common-js"]
    end
    subgraph nativeside["Native clients"]
        n["ssh / scp / VS Code / mstsc"]
        c["Sidegate CLI<br/>local port or ProxyCommand"]
        n --> c
    end

    subgraph wp["Sidegate server, app host"]
        g["/.sidegate/guac<br/>proxy does the guacd handshake"]
        t["/.sidegate/tcp<br/>raw TCP over WebSocket"]
        w["watchSession<br/>every 30 s or on change:<br/>expired, logged out, revoked,<br/>access removed → close"]
    end

    guacd["guacd"]
    h["RDP / SSH host"]

    b -->|WebSocket + session cookie| g
    c -->|WebSocket + Bearer sgs_…| t
    g --> guacd --> h
    t --> h
    w -.-> g
    w -.-> t
```
