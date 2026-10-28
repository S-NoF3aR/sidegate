// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"sidegate/internal/config"
)

// openUpgrade opens an upgraded (echo) connection to app through the proxy
// with the browser's cookies.
func openUpgrade(t *testing.T, e *env, app string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", e.proxy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+app+".test.local\r\nUpgrade: echo\r\nConnection: Upgrade\r\n"+
		"Cookie: "+e.cookieHeader(t, app)+"\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %d", resp.StatusCode)
	}
	io.WriteString(conn, "ping\n")
	if line, _ := br.ReadString('\n'); line != "ping\n" {
		t.Fatalf("echo = %q", line)
	}
	return conn, br
}

// An app's WebSockets end like RDP/SSH tunnels when the session does.
func TestUpgradedConnectionsEndWithSession(t *testing.T) {
	e := newEnv(t, alice)
	fastSessionChecks(e)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "" {
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
		rw.Flush()
		io.Copy(conn, rw)
	}))
	t.Cleanup(upstream.Close)
	addRDPApp(t, e, config.App{Name: "chat", Upstream: upstream.URL, AllowedGroups: []string{"g-devs"}})
	e.get(t, e.url("chat", "/"))

	closed := func(conn net.Conn, br *bufio.Reader, what string) {
		t.Helper()
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := br.ReadByte(); err != io.EOF {
			t.Errorf("%s: connection still open (%v)", what, err)
		}
	}

	// Losing access to the app.
	conn, br := openUpgrade(t, e, "chat")
	a := e.srv.routes.Load().byName["chat"].App
	a.AllowedGroups = []string{"g-admins"}
	if err := e.srv.store.UpdateApp(context.Background(), "test", a); err != nil {
		t.Fatal(err)
	}
	e.srv.Sync(context.Background())
	closed(conn, br, "after access removal")

	// Logout.
	a.AllowedGroups = []string{"g-devs"}
	e.srv.store.UpdateApp(context.Background(), "test", a)
	e.srv.Sync(context.Background())
	conn, br = openUpgrade(t, e, "chat")
	noRedirects(e)
	e.post(t, "/oauth2/logout", nil, "Origin", e.srv.public.String())
	closed(conn, br, "after logout")
}

// A live tunnel ends when its app starts requiring MFA the session lacks.
func TestLiveTunnelEndsOnStepUp(t *testing.T) {
	e := newEnv(t, alice)
	fastSessionChecks(e)
	g := newFakeGuacd(t)
	e.srv.guacd = g.ln.Addr().String()
	addRDPApp(t, e, config.App{Name: "shell", Upstream: "ssh://bastion:22", AllowedGroups: []string{"*"}})
	e.get(t, e.url("shell", "/"))
	ws, _, err := websocket.Dial(context.Background(), e.wsURL("shell", "/.sidegate/guac"),
		&websocket.DialOptions{HTTPClient: e.client, Subprotocols: []string{"guacamole"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	readMsg(t, ws)

	a := e.srv.routes.Load().byName["shell"].App
	a.RequireMFA = true
	if err := e.srv.store.UpdateApp(context.Background(), "test", a); err != nil {
		t.Fatal(err)
	}
	e.srv.Sync(context.Background())
	if got := readMsg(t, ws); !strings.Contains(got, "requires you to sign in again") {
		t.Errorf("after requiring MFA: %q", got)
	}
}

// A connection's watcher refreshes the session, but only HTTP responses
// hand the result to the client. After the connection closes, the client's
// older copy must continue from the newest state, not redeem its rotated
// refresh token (which the mock IdP, like strict IdPs, rejects).
func TestRefreshesOutliveConnections(t *testing.T) {
	e := newEnv(t, alice)
	fastSessionChecks(e)
	e.srv.refreshes.ttl = 0   // no reuse of refresh results
	e.srv.refreshInterval = 0 // refresh on every request and every check
	g := newFakeGuacd(t)
	e.srv.guacd = g.ln.Addr().String()
	addRDPApp(t, e, config.App{Name: "shell", Upstream: "ssh://bastion:22", AllowedGroups: []string{"*"}})
	e.get(t, e.url("shell", "/"))
	ws, _, err := websocket.Dial(context.Background(), e.wsURL("shell", "/.sidegate/guac"),
		&websocket.DialOptions{HTTPClient: e.client, Subprotocols: []string{"guacamole"}})
	if err != nil {
		t.Fatal(err)
	}
	readMsg(t, ws)
	time.Sleep(100 * time.Millisecond) // a few watcher refreshes
	ws.Close(websocket.StatusNormalClosure, "")
	time.Sleep(100 * time.Millisecond) // the watcher is gone

	noRedirects(e) // the mock IdP would sign the user in again silently
	if resp, _ := e.get(t, e.url("whoami", "/")); resp.StatusCode != 200 {
		t.Errorf("after the connection closed: %d", resp.StatusCode)
	}
}
