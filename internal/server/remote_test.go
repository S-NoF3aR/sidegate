// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"sidegate/internal/config"
	"sidegate/internal/guac"
)

// fakeGuacd accepts one connection, completes the handshake and answers
// every "key" instruction with a "sync". It records what it received.
type fakeGuacd struct {
	ln       net.Listener
	mu       sync.Mutex
	protocol string
	connect  []string
	received []string
}

func newFakeGuacd(t *testing.T) *fakeGuacd {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := &fakeGuacd{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go g.serve(c)
		}
	}()
	return g
}

func (g *fakeGuacd) serve(c net.Conn) {
	defer c.Close()
	r := guac.NewReader(c)
	sel, err := r.Read()
	if err != nil || sel.Opcode != "select" || len(sel.Args) != 1 {
		return
	}
	g.mu.Lock()
	g.protocol = sel.Args[0]
	g.mu.Unlock()
	// A superset of RDP and SSH parameter names.
	io.WriteString(c, guac.New("args", "VERSION_1_5_0", "hostname", "port", "security", "username", "password", "host-key", "color-scheme").String())
	for {
		in, err := r.Read()
		if err != nil {
			return
		}
		if in.Opcode == "connect" {
			g.mu.Lock()
			g.connect = in.Args
			g.mu.Unlock()
			break
		}
	}
	io.WriteString(c, guac.New("ready", "$conn-1").String())
	for {
		raw, err := r.ReadRaw()
		if err != nil {
			return
		}
		g.mu.Lock()
		g.received = append(g.received, raw)
		g.mu.Unlock()
		if strings.HasPrefix(raw, "3.key,") {
			io.WriteString(c, guac.New("sync", "42").String())
		}
	}
}

// echoServer stands in for an RDP host.
func echoServer(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func addRDPApp(t *testing.T, e *env, a config.App) {
	t.Helper()
	a.Normalize()
	if err := a.Validate(e.srv.domain, e.srv.portalHost); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.store.CreateApp(context.Background(), "test", a); err != nil {
		t.Fatal(err)
	}
	e.srv.Sync(context.Background())
}

func (e *env) wsURL(app, path string) string {
	return "ws" + strings.TrimPrefix(e.url(app, path), "http")
}

func readMsg(t *testing.T, ws *websocket.Conn) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, data, err := ws.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(data)
}

func TestRDPBrowserTunnel(t *testing.T) {
	e := newEnv(t, alice)
	fastSessionChecks(e)
	g := newFakeGuacd(t)
	e.srv.guacd = g.ln.Addr().String()
	addRDPApp(t, e, config.App{Name: "desk", Upstream: "rdp://win1.corp:3390?security=nla&domain=CORP", AllowedGroups: []string{"*"}})
	ctx := context.Background()

	// Unauthenticated tunnels are refused.
	if _, resp, err := websocket.Dial(ctx, e.wsURL("desk", "/.sidegate/guac"), &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: e.client.Transport}, Subprotocols: []string{"guacamole"},
	}); err == nil || resp.StatusCode != 401 {
		t.Fatalf("unauthenticated tunnel: %v", err)
	}

	// The page needs a sign-in, then loads the client.
	resp, page := e.get(t, e.url("desk", "/"))
	if resp.StatusCode != 200 || !strings.Contains(page, `data-browser="true"`) || !strings.Contains(page, "/.sidegate/static/remote.js") {
		t.Fatalf("rdp page: %d", resp.StatusCode)
	}
	if resp, _ := e.get(t, e.url("desk", "/.sidegate/static/vendor/guacamole-common-1.5.0.min.js")); resp.StatusCode != 200 {
		t.Errorf("client library: %d", resp.StatusCode)
	}

	// Another site can't open a tunnel with the user's cookies.
	if _, resp, err := websocket.Dial(ctx, e.wsURL("desk", "/.sidegate/guac"), &websocket.DialOptions{
		HTTPClient: e.client, Subprotocols: []string{"guacamole"}, HTTPHeader: http.Header{"Origin": {"http://evil.example"}},
	}); err == nil || resp.StatusCode != 403 {
		t.Errorf("cross-origin tunnel: err=%v", err)
	}

	ws, _, err := websocket.Dial(ctx, e.wsURL("desk", "/.sidegate/guac?width=1024&height=99999&dpi=96&timezone=Europe/Zurich"),
		&websocket.DialOptions{HTTPClient: e.client, Subprotocols: []string{"guacamole"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	if got := readMsg(t, ws); got != guac.New("", "$conn-1").String() {
		t.Fatalf("first message = %q, want the tunnel UUID", got)
	}
	g.mu.Lock()
	connect := strings.Join(g.connect, "|")
	g.mu.Unlock()
	// The proxy, not the browser, chooses host, port and RDP options.
	if connect != "VERSION_1_5_0|win1.corp|3390|nla||||" {
		t.Errorf("connect args = %q", connect)
	}

	// Pings are answered by the proxy and never reach guacd.
	ping := guac.New("", "ping", "123").String()
	ws.Write(ctx, websocket.MessageText, []byte(ping))
	if got := readMsg(t, ws); got != ping {
		t.Errorf("ping echo = %q", got)
	}
	ws.Write(ctx, websocket.MessageText, []byte(guac.New("key", "65307", "1").String()))
	if got := readMsg(t, ws); got != guac.New("sync", "42").String() {
		t.Errorf("relay = %q", got)
	}
	g.mu.Lock()
	for _, raw := range g.received {
		if strings.HasPrefix(raw, "0.,") {
			t.Errorf("internal instruction leaked to guacd: %q", raw)
		}
	}
	g.mu.Unlock()

	// Signing the user out ends the live session with a message.
	e.srv.store.RevokeSessions(ctx, "test", "alice-id")
	e.srv.Sync(ctx)
	if got := readMsg(t, ws); !strings.Contains(got, "signed out by an administrator") {
		t.Errorf("after revocation: %q", got)
	}
}

// cliLogin runs the CLI sign-in in the test client and returns the token
// the proxy hands to the (simulated) local listener.
func cliLogin(t *testing.T, e *env, extra url.Values) string {
	t.Helper()
	verifier := "test-verifier-0123456789-0123456789-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"port": {"15555"}, "state": {"0123456789abcdefXYZ"}, "challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}}
	for k, v := range extra {
		q[k] = v
	}
	if resp, page := e.get(t, e.url("portal", "/cli/login?"+q.Encode())); resp.StatusCode != 200 || !strings.Contains(page, "Sign in the Sidegate CLI?") {
		t.Fatalf("confirmation page: %d", resp.StatusCode)
	}
	if resp, _ := e.post(t, "/cli/login", q); resp.StatusCode != 403 {
		t.Errorf("confirmation without Origin: %d, want 403", resp.StatusCode)
	}
	var callback *url.URL
	e.client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if req.URL.Host == "127.0.0.1:15555" {
			callback = req.URL
			return http.ErrUseLastResponse
		}
		return nil
	}
	defer func() { e.client.CheckRedirect = nil }()
	e.post(t, "/cli/login", q, "Origin", e.srv.public.String())
	if callback == nil || callback.Query().Get("state") != q.Get("state") {
		t.Fatalf("no callback to the CLI: %v", callback)
	}
	code := callback.Query().Get("code")
	if code == "" || callback.Query().Get("token") != "" {
		t.Fatalf("callback must carry a code, not a token: %v", callback)
	}
	exchange := func(code, verifier string) (int, string) {
		body, _ := json.Marshal(map[string]string{"code": code, "verifier": verifier})
		resp, err := (&http.Client{Transport: e.client.Transport}).Post(e.url("portal", "/cli/token"), "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct{ Token string }
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out.Token
	}
	// Someone who finds the code (e.g. in the browser history) can't use it
	// without the verifier.
	if status, tok := exchange(code, "wrong-verifier"); status != 400 || tok != "" {
		t.Errorf("exchange with wrong verifier: %d, got a token: %v", status, tok != "")
	}
	if status, _ := exchange(code[:len(code)-2]+"xx", verifier); status != 400 {
		t.Errorf("exchange with tampered code: %d", status)
	}
	status, token := exchange(code, verifier)
	if status != 200 || !strings.HasPrefix(token, cliTokenPrefix) {
		t.Fatalf("exchange: %d %q", status, token)
	}
	return token
}

func TestRDPNativeTunnel(t *testing.T) {
	e := newEnv(t, alice)
	addRDPApp(t, e, config.App{Name: "desk", Upstream: "rdp://" + echoServer(t), AllowedGroups: []string{"g-devs"}})
	addRDPApp(t, e, config.App{Name: "secure-desk", Upstream: "rdp://" + echoServer(t), AllowedGroups: []string{"*"}, RequireMFA: true})
	token := cliLogin(t, e, nil)
	ctx := context.Background()
	bearer := http.Header{"Authorization": {"Bearer " + token}}
	plain := &http.Client{Transport: e.client.Transport} // no cookies: the CLI only has its token

	// The token works for the portal API, which lists the desktop as RDP.
	req, _ := http.NewRequest("GET", e.url("portal", "/api/me"), nil)
	req.Header = bearer
	resp, err := plain.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"name":"desk"`) || !strings.Contains(string(body), `"type":"rdp"`) {
		t.Fatalf("/api/me with CLI token: %d %s", resp.StatusCode, body)
	}

	ws, _, err := websocket.Dial(ctx, e.wsURL("desk", "/.sidegate/tcp"), &websocket.DialOptions{
		HTTPClient: plain, HTTPHeader: bearer, Subprotocols: []string{"sidegate-tcp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	nc := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer nc.Close()
	nc.SetDeadline(time.Now().Add(5 * time.Second))
	nc.Write([]byte("\x03\x00\x00\x13hello rdp"))
	buf := make([]byte, 13)
	if _, err := io.ReadFull(nc, buf); err != nil || string(buf) != "\x03\x00\x00\x13hello rdp" {
		t.Errorf("tunnel echo = %q %v", buf, err)
	}

	// A desktop requiring MFA tells the CLI to step up.
	_, resp, err = websocket.Dial(ctx, e.wsURL("secure-desk", "/.sidegate/tcp"), &websocket.DialOptions{HTTPClient: plain, HTTPHeader: bearer})
	if err == nil || resp.StatusCode != 401 {
		t.Fatalf("step-up: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), `"mfa":true`) {
		t.Errorf("step-up body = %s", b)
	}

	// CLI tokens are revoked together with the user's sessions.
	e.srv.store.RevokeSessions(ctx, "test", "alice-id")
	e.srv.Sync(ctx)
	if _, resp, err := websocket.Dial(ctx, e.wsURL("desk", "/.sidegate/tcp"), &websocket.DialOptions{HTTPClient: plain, HTTPHeader: bearer}); err == nil || resp.StatusCode != 401 {
		t.Errorf("revoked CLI token: %v", err)
	}
	// Bearer tokens never authorize web apps (only RDP tunnels and /api/me).
	req, _ = http.NewRequest("GET", e.url("whoami", "/"), nil)
	req.Header = bearer
	req.Header.Set("Sec-Fetch-Mode", "cors")
	if resp, _ := plain.Do(req); resp.StatusCode != 401 {
		t.Errorf("web app with CLI token: %d", resp.StatusCode)
	}
}

func TestSSHBrowserTunnel(t *testing.T) {
	e := newEnv(t, alice)
	g := newFakeGuacd(t)
	e.srv.guacd = g.ln.Addr().String()
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI+abc/def="
	addRDPApp(t, e, config.App{Name: "shell", Upstream: "ssh://bastion.corp:2222?host-key=" + strings.ReplaceAll(key, " ", "%20"), AllowedGroups: []string{"*"}})
	resp, page := e.get(t, e.url("shell", "/"))
	if resp.StatusCode != 200 || !strings.Contains(page, `data-protocol="ssh"`) || strings.Contains(page, `id="cad"`) ||
		!strings.Contains(page, "sidegate ssh shell") {
		t.Fatalf("ssh page: %d", resp.StatusCode)
	}
	ctx := context.Background()
	ws, _, err := websocket.Dial(ctx, e.wsURL("shell", "/.sidegate/guac"), &websocket.DialOptions{HTTPClient: e.client, Subprotocols: []string{"guacamole"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	readMsg(t, ws) // tunnel UUID
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.protocol != "ssh" {
		t.Errorf("guacd protocol = %q", g.protocol)
	}
	// The host key reaches guacd as a known_hosts entry; '+' survives.
	if want := "VERSION_1_5_0|bastion.corp|2222||||[bastion.corp]:2222 " + key + "|gray-black"; strings.Join(g.connect, "|") != want {
		t.Errorf("connect = %q\nwant      %q", strings.Join(g.connect, "|"), want)
	}
}

func TestSSHNativeTunnel(t *testing.T) {
	e := newEnv(t, alice)
	addRDPApp(t, e, config.App{Name: "shell", Upstream: "ssh://" + echoServer(t), AllowedGroups: []string{"*"}})
	token := cliLogin(t, e, nil)
	ctx := context.Background()
	ws, _, err := websocket.Dial(ctx, e.wsURL("shell", "/.sidegate/tcp"), &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: e.client.Transport}, HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
	})
	if err != nil {
		t.Fatal(err)
	}
	nc := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer nc.Close()
	nc.SetDeadline(time.Now().Add(5 * time.Second))
	nc.Write([]byte("SSH-2.0-test\r\n"))
	buf := make([]byte, 14)
	if _, err := io.ReadFull(nc, buf); err != nil || string(buf) != "SSH-2.0-test\r\n" {
		t.Errorf("tunnel echo = %q %v", buf, err)
	}
}

func TestRemoteValidation(t *testing.T) {
	base := config.App{Name: "d", Subdomain: "d", AllowedGroups: []string{"*"}}
	for up, ok := range map[string]bool{
		"ssh://bastion":      true,
		"ssh://bastion:2222": true,
		"ssh://bastion?host-key=ssh-ed25519%20AAAAC3Nza+/x=":        true,
		"ssh://bastion?host-key=AAAAC3Nza":                          false, // key type missing
		"ssh://bastion?security=nla":                                false, // RDP option
		"ssh://root@bastion":                                        false,
		"rdp://win1?host-key=x":                                     false, // SSH option
		"rdp://win1":                                                true,
		"rdp://win1:3390?security=nla&ignore-cert=true&domain=CORP": true,
		"rdp://10.0.0.5":                                            true,
		"rdp://win1:0":                                              false,
		"rdp://win1/path":                                           false,
		"rdp://win1?security=bogus":                                 false,
		"rdp://win1?username=admin":                                 false,
		"rdp://user:pw@win1":                                        false,
	} {
		a := base
		a.Upstream = up
		if err := a.Validate("example.com", ""); (err == nil) != ok {
			t.Errorf("%s: err = %v, want ok=%v", up, err, ok)
		}
	}
	a := base
	a.Upstream, a.PublicPaths = "rdp://win1", []string{"/x"}
	if a.Validate("example.com", "") == nil {
		t.Error("RDP app with public paths should be invalid")
	}
}
