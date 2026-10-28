// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"sidegate/internal/config"
)

// fastSessionChecks makes live connections re-check their session often.
func fastSessionChecks(e *env) { e.srv.checkInterval = 20 * time.Millisecond }

// cookieHeader returns the session cookies the browser holds for app.
func (e *env) cookieHeader(t *testing.T, app string) string {
	req, _ := http.NewRequest("GET", e.url(app, "/"), nil)
	for _, c := range e.client.Jar.Cookies(req.URL) {
		req.AddCookie(c)
	}
	return req.Header.Get("Cookie")
}

func TestLogoutEndsSessionServerSide(t *testing.T) {
	e := newEnv(t, alice)
	fastSessionChecks(e)
	if resp, _ := e.get(t, e.url("whoami", "/")); resp.StatusCode != 200 {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	stolen := e.cookieHeader(t, "whoami")
	noRedirects(e)
	e.post(t, "/oauth2/logout", nil, "Origin", e.srv.public.String())

	// A copy of the cookie (another tab, another device, an attacker) no
	// longer works.
	req, _ := http.NewRequest("GET", e.url("whoami", "/"), nil)
	req.Header.Set("Cookie", stolen)
	req.Header.Set("Sec-Fetch-Mode", "cors")
	resp, err := (&http.Client{Transport: e.client.Transport}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("old cookie after logout: %d, want 401", resp.StatusCode)
	}
}

// Live connections end right away on logout, not at their next periodic
// check (default 30s).
func TestLogoutEndsLiveBrowserTunnel(t *testing.T) {
	e := newEnv(t, alice)
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
	readMsg(t, ws) // tunnel UUID

	noRedirects(e)
	e.post(t, "/oauth2/logout", nil, "Origin", e.srv.public.String())
	if got := readMsg(t, ws); !strings.Contains(got, "Disconnected: you signed out") {
		t.Errorf("after logout: %q", got)
	}
}

// openNativeTunnel connects to app's TCP tunnel with a CLI token.
func openNativeTunnel(t *testing.T, e *env, app, token string) net.Conn {
	t.Helper()
	ctx := context.Background()
	ws, _, err := websocket.Dial(ctx, e.wsURL(app, "/.sidegate/tcp"), &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: e.client.Transport}, HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
	})
	if err != nil {
		t.Fatal(err)
	}
	nc := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	nc.SetDeadline(time.Now().Add(5 * time.Second))
	nc.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(nc, buf); err != nil {
		t.Fatalf("tunnel not working: %v", err)
	}
	return nc
}

// waitClosed asserts that the proxy closes the tunnel soon; a read that
// merely times out means it stayed open.
func waitClosed(t *testing.T, c net.Conn, what string) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	// Only a close frame from the proxy (or EOF) counts; the deadline shows
	// up as a canceled context.
	_, err := c.Read(make([]byte, 1))
	if websocket.CloseStatus(err) == -1 && !errors.Is(err, io.EOF) {
		t.Errorf("%s: tunnel still open (%v)", what, err)
	}
}

func TestLiveNativeTunnelsEnd(t *testing.T) {
	e := newEnv(t, alice) // default check interval: endings must be immediate
	addRDPApp(t, e, config.App{Name: "shell", Upstream: "ssh://" + echoServer(t), AllowedGroups: []string{"*"}})
	ctx := context.Background()

	// sidegate logout ends the token and its open tunnels.
	token := cliLogin(t, e, nil)
	nc := openNativeTunnel(t, e, "shell", token)
	req, _ := http.NewRequest("POST", e.url("portal", "/cli/logout"), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Transport: e.client.Transport}).Do(req)
	if err != nil || resp.StatusCode != 204 {
		t.Fatalf("cli logout: %v %v", resp, err)
	}
	waitClosed(t, nc, "after sidegate logout")
	if _, resp, err := websocket.Dial(ctx, e.wsURL("shell", "/.sidegate/tcp"), &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: e.client.Transport}, HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
	}); err == nil || resp.StatusCode != 401 {
		t.Errorf("token after logout: %v", err)
	}

	// An admin signing the user out ends open native tunnels too.
	token = cliLogin(t, e, nil)
	nc = openNativeTunnel(t, e, "shell", token)
	e.srv.store.RevokeSessions(ctx, "test", "alice-id")
	e.srv.Sync(ctx)
	waitClosed(t, nc, "after admin sign-out")
}

// TestLiveSessionSharesRefreshes: the mock IdP accepts each refresh token
// only once (like IdPs with strict rotation). The browser and the watcher
// of an open terminal hold the same session; without sharing refreshes, the
// second one to refresh would present a used token and be signed out.
func TestLiveSessionSharesRefreshes(t *testing.T) {
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
	defer ws.CloseNow()
	readMsg(t, ws)

	// Interleave browser requests with the watcher's checks.
	for i := range 10 {
		if resp, _ := e.get(t, e.url("whoami", "/")); resp.StatusCode != 200 {
			t.Fatalf("browser request %d: %d", i, resp.StatusCode)
		}
		time.Sleep(30 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, data, err := ws.Read(ctx); err == nil {
		t.Errorf("terminal was disconnected: %q", data)
	}
}

func TestTunnelKeepAlive(t *testing.T) {
	e := newEnv(t, alice)
	e.srv.pingInterval = 30 * time.Millisecond
	addRDPApp(t, e, config.App{Name: "shell", Upstream: "ssh://" + echoServer(t), AllowedGroups: []string{"*"}})
	token := cliLogin(t, e, nil)

	// An idle tunnel whose client answers pings (by reading) stays open.
	nc := openNativeTunnel(t, e, "shell", token)
	got := make(chan error, 1)
	go func() {
		nc.SetReadDeadline(time.Time{})
		_, err := nc.Read(make([]byte, 1))
		got <- err
	}()
	time.Sleep(300 * time.Millisecond)
	select {
	case err := <-got:
		t.Fatalf("idle tunnel closed: %v", err)
	default:
	}
	nc.Write([]byte("x"))
	if err := <-got; err != nil {
		t.Errorf("tunnel after idle time: %v", err)
	}

	// A client that stops answering is disconnected.
	nc = openNativeTunnel(t, e, "shell", token)
	time.Sleep(300 * time.Millisecond) // nobody reads, so pongs aren't processed
	waitClosed(t, nc, "dead client")
}

func TestDrainEndsRemoteSessions(t *testing.T) {
	e := newEnv(t, alice)
	g := newFakeGuacd(t)
	e.srv.guacd = g.ln.Addr().String()
	addRDPApp(t, e, config.App{Name: "desk", Upstream: "rdp://win1:3389", AllowedGroups: []string{"*"}})
	addRDPApp(t, e, config.App{Name: "shell", Upstream: "ssh://" + echoServer(t), AllowedGroups: []string{"*"}})
	ctx := context.Background()

	e.get(t, e.url("desk", "/")) // signs in
	ws, _, err := websocket.Dial(ctx, e.wsURL("desk", "/.sidegate/guac"),
		&websocket.DialOptions{HTTPClient: e.client, Subprotocols: []string{"guacamole"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	readMsg(t, ws) // tunnel UUID
	nc := openNativeTunnel(t, e, "shell", cliLogin(t, e, nil))
	if n := e.srv.liveRemote.Load(); n != 2 {
		t.Fatalf("live remote connections = %d", n)
	}

	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	drained := make(chan struct{})
	go func() { e.srv.Drain(dctx); close(drained) }()
	if got := readMsg(t, ws); !strings.Contains(got, "the server is restarting") {
		t.Errorf("browser message = %q", got)
	}
	waitClosed(t, nc, "native tunnel on drain")
	select {
	case <-drained:
	case <-time.After(3 * time.Second):
		t.Fatal("Drain didn't return")
	}
	if n := e.srv.liveRemote.Load(); n != 0 {
		t.Errorf("live remote connections after drain = %d", n)
	}
}
