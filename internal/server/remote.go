// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"io"
	"io/fs"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"sidegate/internal/config"
	"sidegate/internal/guac"
	"sidegate/internal/session"
)

// Remote apps (RDP and SSH) are served on their subdomain like web apps:
//
//	/                     the browser client page (desktop or terminal)
//	/.sidegate/guac       WebSocket: Guacamole tunnel, relayed to guacd
//	/.sidegate/tcp        WebSocket: raw TCP to the host, for the Sidegate CLI
//	/.sidegate/static/*   client scripts (same origin, so ES modules load)

// defaultCheckInterval is how often live remote connections re-check the
// user's session, so revocations and lost access end them.
const defaultCheckInterval = 30 * time.Second

// defaultPingInterval keeps idle tunnels below common load balancer idle
// timeouts (AWS ALB: 60 s).
const defaultPingInterval = 25 * time.Second

// Drain ends all live remote connections with a message that the server is
// restarting and waits until they are closed or ctx ends. Call it on
// shutdown, once the instance no longer receives new requests.
func (s *Server) Drain(ctx context.Context) {
	s.drainOnce.Do(func() { close(s.draining) })
	for s.liveRemote.Load() > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// keepAlive pings ws every pingInterval and calls dead if a ping isn't
// answered within the interval.
func (s *Server) keepAlive(ctx context.Context, ws *websocket.Conn, dead func()) {
	t := time.NewTicker(s.pingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pctx, cancel := context.WithTimeout(ctx, s.pingInterval)
		err := ws.Ping(pctx)
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				dead()
			}
			return
		}
	}
}

// Guacamole status codes sent to the browser client.
const (
	guacUpstreamUnavailable = "519"
	guacServerError         = "512"
	guacUnauthorized        = "769"
	guacForbidden           = "771"
)

var timezoneRe = regexp.MustCompile(`^[A-Za-z0-9_+\-/]{1,64}$`)

func (s *Server) serveRemote(w http.ResponseWriter, r *http.Request, a *app, sess *session.Session) {
	switch path := r.URL.Path; {
	case path == "/" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		s.remotePage(w, a, sess)
	case path == "/.sidegate/guac":
		s.browserTunnel(w, r, a, sess)
	case path == "/.sidegate/tcp":
		s.tcpTunnel(w, r, a, sess)
	case strings.HasPrefix(path, "/.sidegate/static/"):
		static, _ := fs.Sub(webFS, "web/static")
		http.StripPrefix("/.sidegate/static/", noListing(http.FileServerFS(static))).ServeHTTP(w, r)
	default:
		s.renderError(w, r, http.StatusNotFound, "Not found", "Open "+a.URL+" to connect to "+a.DisplayTitle()+".")
	}
}

type remotePageData struct {
	User     *session.Session
	Admin    bool
	App      *app
	Protocol string // "rdp" or "ssh"
	Browser  bool   // guacd configured
	Username string
	// Notices from extensions, e.g. that browser sessions are recorded.
	Notices []string
}

func (s *Server) remotePage(w http.ResponseWriter, a *app, sess *session.Session) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: blob: "+s.public.String()+"; style-src 'self' "+s.public.String()+
		"; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	s.render(w, http.StatusOK, "remote", remotePageData{
		User: sess, Admin: s.isAdmin(sess), App: a, Protocol: a.Protocol(), Browser: s.guacd != "", Username: sess.Username,
		Notices: s.remoteNotices(a.Name),
	})
}

// browserTunnel relays the Guacamole protocol between the browser client
// and guacd. The proxy performs the connection handshake itself, so the
// browser never chooses the target host or any connection parameter.
func (s *Server) browserTunnel(w http.ResponseWriter, r *http.Request, a *app, sess *session.Session) {
	if s.guacd == "" {
		http.Error(w, "browser access to remote apps is not configured", http.StatusServiceUnavailable)
		return
	}
	target, err := a.RemoteTarget()
	if err != nil {
		http.Error(w, "invalid remote target", http.StatusInternalServerError)
		return
	}
	q := r.URL.Query()
	width := clampInt(q.Get("width"), 320, 8192, 1280)
	height := clampInt(q.Get("height"), 240, 8192, 720)
	dpi := clampInt(q.Get("dpi"), 48, 480, 96)
	tz := q.Get("timezone")
	if !timezoneRe.MatchString(tz) {
		tz = ""
	}

	// Accept checks that Origin matches the host, which stops other sites
	// from opening a tunnel with the user's cookies.
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		return
	}
	ws.SetReadLimit(4 << 20)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sendError := func(msg, code string) {
		ws.Write(ctx, websocket.MessageText, []byte(guac.New("error", msg, code).String()))
	}

	gc, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", s.guacd)
	if err != nil {
		s.log.Error("connect to guacd", "addr", s.guacd, "error", err)
		sendError("The remote access service is unavailable.", guacUpstreamUnavailable)
		ws.Close(websocket.StatusTryAgainLater, "guacd unavailable")
		return
	}
	defer gc.Close()

	params := guacParams(target)
	reader := guac.NewReader(gc)
	gc.SetDeadline(time.Now().Add(20 * time.Second))
	id, err := guac.Handshake(gc, reader, target.Protocol, params, width, height, dpi, tz, sess.Display())
	if err != nil {
		s.log.Warn("guacd handshake", "app", a.Name, "error", err)
		sendError("Could not start the remote session.", guacServerError)
		ws.Close(websocket.StatusInternalError, "handshake failed")
		return
	}
	gc.SetDeadline(time.Time{})
	// Observers (e.g. session recording) must see everything the user
	// sees, so a session they can't observe doesn't start.
	streams, err := s.observeRemote(RemoteSession{
		App: a.Name, Title: a.DisplayTitle(), Protocol: target.Protocol, User: sess,
		Start: time.Now(), Width: width, Height: height,
	})
	if err != nil {
		s.log.Error("observe remote session", "app", a.Name, "user", sess.Username, "error", err)
		sendError("The session can't be recorded right now, so it can't start. Please try again later or contact an administrator.", guacServerError)
		ws.Close(websocket.StatusInternalError, "observer failed")
		return
	}
	var reason atomic.Value
	defer func() {
		why, _ := reason.Load().(string)
		if why == "" {
			why = "disconnected"
		}
		for _, st := range streams {
			st.Close(why)
		}
	}()
	// The client treats the first internal instruction as the tunnel UUID.
	if err := ws.Write(ctx, websocket.MessageText, []byte(guac.New(guac.InternalOpcode, id).String())); err != nil {
		return
	}

	end := s.trackRemote(a, sess, "browser")
	defer end()
	go s.watchSession(ctx, a, sess, func(why string) {
		reason.Store(why)
		sendError("Disconnected: "+why+".", guacUnauthorized)
		cancel()
	})
	go s.keepAlive(ctx, ws, func() {
		reason.Store("the browser stopped responding")
		cancel()
	})

	// guacd → browser. The client expects whole instructions per message,
	// so complete ones are batched up to a size limit.
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		defer cancel()
		var batch strings.Builder
		for {
			raw, err := reader.ReadRaw()
			if err != nil {
				return
			}
			batch.Reset()
			batch.WriteString(raw)
			for reader.Buffered() > 0 && batch.Len() < 64<<10 {
				raw, err := reader.ReadRaw()
				if err != nil {
					break
				}
				batch.WriteString(raw)
			}
			for _, st := range streams {
				if err := st.Output(batch.String()); err != nil {
					s.log.Error("observe remote session", "app", a.Name, "user", sess.Username, "error", err)
					reason.Store("session recording failed")
					sendError("Disconnected: the session can't be recorded right now.", guacServerError)
					return
				}
			}
			if ws.Write(ctx, websocket.MessageText, []byte(batch.String())) != nil {
				return
			}
		}
	}()
	// browser → guacd. Tunnel-internal instructions (pings) are answered
	// here and never reach guacd.
	go func() {
		defer cancel()
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				return
			}
			parts, err := guac.Split(string(data))
			if err != nil {
				return
			}
			var out strings.Builder
			for _, raw := range parts {
				if strings.HasPrefix(raw, "0.,") {
					if in, err := guac.Parse(raw); err == nil && len(in.Args) > 0 && in.Args[0] == "ping" {
						ws.Write(ctx, websocket.MessageText, []byte(raw))
					}
					continue
				}
				out.WriteString(raw)
			}
			if out.Len() > 0 {
				if _, err := io.WriteString(gc, out.String()); err != nil {
					return
				}
			}
		}
	}()
	<-ctx.Done()
	gc.Close()
	<-outputDone // streams are closed only after their last Output
	why, _ := reason.Load().(string)
	ws.Close(websocket.StatusNormalClosure, why)
}

// tcpTunnel connects the WebSocket to the remote host's TCP port. It's used
// by the Sidegate CLI, which lets native RDP and SSH clients connect.
func (s *Server) tcpTunnel(w http.ResponseWriter, r *http.Request, a *app, sess *session.Session) {
	target, err := a.RemoteTarget()
	if err != nil {
		http.Error(w, "invalid remote target", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tc, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", target.Address())
	if err != nil {
		s.log.Warn("connect to remote host", "app", a.Name, "addr", target.Address(), "error", err)
		http.Error(w, "the remote host is not reachable", http.StatusBadGateway)
		return
	}
	defer tc.Close()
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"sidegate-tcp"}})
	if err != nil {
		return
	}
	nc := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer nc.Close()

	end := s.trackRemote(a, sess, "native")
	defer end()
	go s.watchSession(ctx, a, sess, func(why string) {
		ws.Close(websocket.StatusPolicyViolation, why)
		cancel()
	})
	go s.keepAlive(ctx, ws, cancel)
	go func() {
		io.Copy(tc, nc)
		cancel()
	}()
	go func() {
		io.Copy(nc, tc)
		cancel()
	}()
	<-ctx.Done()
}

// guacParams returns the guacd connection parameters for target. Options
// from the app's URL override the defaults.
func guacParams(t config.RemoteTarget) map[string]string {
	p := map[string]string{"hostname": t.Host, "port": t.Port}
	switch t.Protocol {
	case "rdp":
		p["security"] = "any"
		p["ignore-cert"] = "false"
		p["resize-method"] = "display-update"
		p["enable-font-smoothing"] = "true"
		p["client-name"] = "sidegate"
		for k, v := range t.Params {
			p[k] = v
		}
	case "ssh":
		p["font-name"] = "monospace"
		p["font-size"] = "11"
		p["color-scheme"] = "gray-black"
		p["scrollback"] = "2000"
		p["terminal-type"] = "xterm-256color"
		// Without a host key, guacd accepts any key the server presents.
		p["host-key"] = t.KnownHostsLine()
	}
	return p
}

// trackRemote logs and counts a remote connection; the returned func ends
// it.
func (s *Server) trackRemote(a *app, sess *session.Session, client string) func() {
	start := time.Now()
	proto := a.Protocol()
	s.liveRemote.Add(1)
	s.metrics.remoteSessions.WithLabelValues(a.Name, proto, client).Inc()
	s.metrics.remoteActive.WithLabelValues(a.Name, proto, client).Inc()
	s.log.Info("remote session started", "app", a.Name, "protocol", proto, "user", sess.Username, "client", client)
	s.emit(userEvent(EventRemoteStart, sess, a.Name, map[string]string{"protocol": proto, "client": client}))
	return func() {
		defer s.liveRemote.Add(-1)
		s.metrics.remoteActive.WithLabelValues(a.Name, proto, client).Dec()
		s.emit(userEvent(EventRemoteEnd, sess, a.Name, map[string]string{"protocol": proto, "client": client,
			"duration": time.Since(start).Round(time.Second).String()}))
		s.log.Info("remote session ended", "app", a.Name, "protocol", proto, "user", sess.Username, "client", client,
			"duration", time.Since(start).Round(time.Second))
	}
}

// watchSession periodically re-checks a live connection's session and calls
// end if it expired, was revoked (by an admin or the IdP), or the user lost
// access to the app.
func (s *Server) watchSession(ctx context.Context, a *app, sess *session.Session, end func(reason string)) {
	s.live.add(sess)
	defer s.live.remove(sess)
	t := time.NewTicker(s.checkInterval)
	defer t.Stop()
	for {
		// Wake up on the timer, or right away when revocations or apps
		// change (e.g. a logout on this replica, or one synced from
		// another).
		select {
		case <-ctx.Done():
			return
		case <-s.draining:
			s.log.Info("remote session terminated", "app", a.Name, "user", sess.Username, "reason", "server shutdown")
			end("the server is restarting, please reconnect in a moment")
			return
		case <-t.C:
		case <-s.routes.Load().changed:
		}
		var why string
		if fresh, _ := s.revalidate(ctx, sess); fresh == nil {
			why = "access was revoked by the identity provider"
		} else {
			sess = fresh
			cur := s.routes.Load().byName[a.Name]
			switch {
			case !sess.Valid(time.Now()):
				why = "your session expired"
			case s.revoked(sess):
				why = s.revocationReason(sess)
			case cur == nil || cur.Protocol() != a.Protocol() || !cur.allows(sess):
				why = "your access was removed"
			}
		}
		if why != "" {
			s.log.Info("remote session terminated", "app", a.Name, "user", sess.Username, "reason", why)
			end(why)
			return
		}
	}
}

func clampInt(v string, lo, hi, def int) int {
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return min(max(n, lo), hi)
}
