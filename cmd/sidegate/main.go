// SPDX-License-Identifier: AGPL-3.0-only

// Command sidegate connects native clients (ssh, scp, mstsc, xfreerdp,
// Microsoft Remote Desktop) to RDP and SSH apps behind a Sidegate server. It signs in
// through the browser and tunnels each connection over a WebSocket through
// the proxy, which enforces the same groups, MFA and session rules as in the
// browser.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/coder/websocket"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `sidegate connects native RDP and SSH clients to apps behind a Sidegate server.

Usage:
  sidegate login <portal-url>          sign in (opens the browser)
  sidegate apps                        list the apps you can use
  sidegate rdp <app> [-port N]         tunnel and start your RDP client
  sidegate ssh [user@]<app> [args...]  run ssh through the proxy
  sidegate proxy <app>                 tunnel stdin/stdout (ssh ProxyCommand)
  sidegate tunnel <app> [-port N]      only open a local port to the app
  sidegate logout                      sign out (also closes open tunnels)
  sidegate version                     print the version

<app> is the app's name, URL or host name. The portal URL is remembered
after login. For plain ssh/scp/rsync, add to ~/.ssh/config:

  Host *.apps.example.com
      ProxyCommand sidegate proxy %h

Environment: SIDEGATE_CLI_BROWSER overrides the command that opens the browser.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "login":
		if len(args) != 1 {
			err = errors.New("usage: sidegate login <portal-url>")
			break
		}
		c := &cli{}
		c.cfg.Portal = strings.TrimSuffix(args[0], "/")
		err = c.login(ctx, false, 0)
		if err == nil {
			fmt.Fprintln(os.Stderr, "Signed in to", c.cfg.Portal)
		}
	case "logout":
		err = cmdLogout(ctx)
	case "apps":
		err = cmdApps(ctx)
	case "rdp", "tunnel":
		err = cmdTunnel(ctx, args, cmd == "rdp")
	case "ssh":
		err = cmdSSH(ctx, args)
	case "proxy":
		err = cmdProxy(ctx, args)
	case "version", "--version":
		fmt.Println("sidegate", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		err = fmt.Errorf("unknown command %q\n\n%s", cmd, usage)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// cmdLogout ends the session on the proxy, which also closes open tunnels
// using it, and forgets it locally.
func cmdLogout(ctx context.Context) error {
	c, err := loadCLI()
	if err != nil {
		return nil // not signed in
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Portal+"/cli/logout", nil)
	req.Header.Set("Authorization", "Bearer "+c.token())
	if resp, err := http.DefaultClient.Do(req); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not reach the proxy to end the session:", err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusUnauthorized {
			fmt.Fprintln(os.Stderr, "warning: the proxy didn't end the session:", resp.Status)
		}
	}
	if err := os.Remove(configPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Fprintln(os.Stderr, "Signed out.")
	return nil
}

type config struct {
	Portal string `json:"portal"`
	Token  string `json:"token"`
}

func configPath() string {
	if p := os.Getenv("SIDEGATE_CLI_CONFIG"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "sidegate", "cli.json")
}

type cli struct {
	mu  sync.Mutex
	cfg config
}

func loadCLI() (*cli, error) {
	c := &cli{}
	data, err := os.ReadFile(configPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("not signed in; run: sidegate login <portal-url>")
	}
	if err != nil {
		return nil, err
	}
	return c, json.Unmarshal(data, &c.cfg)
}

func (c *cli) save() error {
	p := configPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(c.cfg, "", "  ")
	return os.WriteFile(p, data, 0o600) // holds a session token
}

func (c *cli) token() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg.Token
}

// updateToken stores a session the proxy refreshed.
func (c *cli) updateToken(h http.Header) {
	if t := h.Get("X-Sidegate-Session"); t != "" {
		c.mu.Lock()
		c.cfg.Token = t
		c.save()
		c.mu.Unlock()
	}
}

// login signs in through the browser: the proxy redirects back to a local
// listener with a session token.
func (c *cli) login(ctx context.Context, mfa bool, maxAge int) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	state := randomString()
	// The browser only carries a code back; exchanging it for a token needs
	// the verifier, which never leaves this process (PKCE).
	verifier := randomString() + randomString()
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	codes := make(chan string, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/callback" || q.Get("state") != state || q.Get("code") == "" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><title>Signed in</title>
<body style="font:16px system-ui;display:grid;place-items:center;height:90vh"><p>sidegate is signed in. You can close this tab.</p></body>`)
		select {
		case codes <- q.Get("code"):
		default:
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()

	q := url.Values{"port": {strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)}, "state": {state}, "challenge": {challenge}}
	if mfa {
		q.Set("mfa", "1")
	}
	if maxAge > 0 {
		q.Set("max_age", strconv.Itoa(maxAge))
	}
	loginURL := c.cfg.Portal + "/cli/login?" + q.Encode()
	fmt.Fprintf(os.Stderr, "Opening your browser to sign in. If it doesn't open, visit:\n  %s\n", loginURL)
	if err := openBrowser(loginURL); err != nil {
		fmt.Fprintln(os.Stderr, "(could not open the browser:", err, ")")
	}
	select {
	case code := <-codes:
		t, err := c.exchange(ctx, code, verifier)
		if err != nil {
			return err
		}
		c.mu.Lock()
		c.cfg.Token = t
		err = c.save()
		c.mu.Unlock()
		return err
	case <-time.After(5 * time.Minute):
		return errors.New("timed out waiting for the browser sign-in")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// exchange trades the sign-in code for a CLI token.
func (c *cli) exchange(ctx context.Context, code, verifier string) (string, error) {
	body, _ := json.Marshal(map[string]string{"code": code, "verifier": verifier})
	req, err := http.NewRequestWithContext(ctx, "POST", c.cfg.Portal+"/cli/token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct{ Token, Error string }
	json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
	if resp.StatusCode != http.StatusOK || out.Token == "" {
		return "", fmt.Errorf("sign-in failed: %s (%d)", out.Error, resp.StatusCode)
	}
	return out.Token, nil
}

func randomString() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func openBrowser(u string) error {
	if cmd := os.Getenv("SIDEGATE_CLI_BROWSER"); cmd != "" {
		return exec.Command(cmd, u).Start()
	}
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	case "darwin":
		return exec.Command("open", u).Start()
	default:
		return exec.Command("xdg-open", u).Start()
	}
}

type app struct {
	Name  string `json:"name"`
	Title string `json:"title"`
	URL   string `json:"url"`
	Type  string `json:"type"`
}

// stepUp is the proxy's answer when an app needs a stronger sign-in.
type stepUp struct {
	Error  string `json:"error"`
	MFA    bool   `json:"mfa"`
	MaxAge int    `json:"maxAge"`
}

// apps lists the user's apps, signing in again if the session is gone.
func (c *cli) apps(ctx context.Context) ([]app, error) {
	for attempt := 0; ; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.Portal+"/api/me", nil)
		req.Header.Set("Authorization", "Bearer "+c.token())
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		c.updateToken(resp.Header)
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			if err := c.login(ctx, false, 0); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("portal returned %s", resp.Status)
		}
		var me struct {
			Apps []app `json:"apps"`
		}
		return me.Apps, json.Unmarshal(body, &me)
	}
}

func cmdApps(ctx context.Context) error {
	c, err := loadCLI()
	if err != nil {
		return err
	}
	apps, err := c.apps(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tTYPE\tTITLE\tURL")
	for _, a := range apps {
		typ := a.Type
		if typ == "" {
			typ = "web"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", a.Name, typ, a.Title, a.URL)
	}
	return tw.Flush()
}

func cmdTunnel(ctx context.Context, args []string, launch bool) error {
	fs := flag.NewFlagSet("tunnel", flag.ContinueOnError)
	port := fs.Int("port", 0, "local port (default: a free one)")
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: sidegate rdp <app> [-port N]")
	}
	name := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	c, target, err := resolveApp(ctx, name)
	if err != nil {
		return err
	}
	if launch && target.Type != "rdp" {
		return fmt.Errorf("%s is not a remote desktop", target.Name)
	}

	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)))
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	addr := ln.Addr().String()
	fmt.Fprintf(os.Stderr, "Forwarding %s to %s. Press Ctrl+C to stop.\n", addr, target.Title)
	if launch {
		launchRDP(addr)
	}

	t := newTunnel(c, target)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return ctx.Err()
		}
		go t.serve(ctx, conn)
	}
}

// safeName matches app names and host names: letters, digits, '.', '_'
// and '-' only.
var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$`)

// resolveApp finds a remote app among the user's apps by name, URL or host
// name (as ssh passes it to a ProxyCommand as %h).
func resolveApp(ctx context.Context, name string) (*cli, *app, error) {
	c, err := loadCLI()
	if err != nil {
		return nil, nil, err
	}
	apps, err := c.apps(ctx)
	if err != nil {
		return nil, nil, err
	}
	for i, a := range apps {
		u, _ := url.Parse(a.URL)
		// Names and hosts end up in ssh's ProxyCommand, which ssh runs
		// through a shell: never trust the server with that.
		if !safeName.MatchString(a.Name) || u == nil || !safeName.MatchString(u.Hostname()) {
			continue
		}
		if a.Name == name || strings.TrimSuffix(a.URL, "/") == strings.TrimSuffix(name, "/") || (u != nil && u.Hostname() == name) {
			if a.Type != "rdp" && a.Type != "ssh" {
				return nil, nil, fmt.Errorf("%s is a web app; open %s in the browser", a.Name, a.URL)
			}
			return c, &apps[i], nil
		}
	}
	return nil, nil, fmt.Errorf("no app %q among your apps (see: sidegate apps)", name)
}

// cmdProxy connects stdin/stdout to the app, for ssh's ProxyCommand.
// Everything else goes to stderr, which ssh shows to the user.
func cmdProxy(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sidegate proxy <app>")
	}
	c, target, err := resolveApp(ctx, args[0])
	if err != nil {
		return err
	}
	ws, err := newTunnel(c, target).dial(ctx)
	if err != nil {
		return err
	}
	nc := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer nc.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(nc, os.Stdin); done <- struct{}{} }()
	go func() { io.Copy(os.Stdout, nc); done <- struct{}{} }()
	<-done
	return nil
}

// cmdSSH runs ssh with this binary as its ProxyCommand. Arguments after
// [user@]<app> are passed to ssh, e.g. a remote command.
func cmdSSH(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sidegate ssh [user@]<app> [ssh args...]")
	}
	user, name, ok := strings.Cut(args[0], "@")
	if !ok {
		user, name = "", args[0]
	}
	// Resolve (and sign in) before ssh takes over the terminal.
	_, target, err := resolveApp(ctx, name)
	if err != nil {
		return err
	}
	if target.Type != "ssh" {
		return fmt.Errorf("%s is not an SSH app", target.Name)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	u, _ := url.Parse(target.URL)
	dest := u.Hostname()
	if user != "" {
		dest = user + "@" + dest
	}
	sshArgs := []string{
		"-o", `ProxyCommand="` + self + `" proxy ` + target.Name,
		// Remember the host key under the app's name, not the tunnel.
		"-o", "HostKeyAlias=" + u.Hostname(),
		dest,
	}
	cmd := exec.Command("ssh", append(sshArgs, args[1:]...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	signal.Ignore(os.Interrupt) // Ctrl+C belongs to the remote shell
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			os.Exit(exit.ExitCode())
		}
		return err
	}
	return nil
}

// newTunnel prepares connections to the app's TCP tunnel endpoint.
func newTunnel(c *cli, a *app) *tunnel {
	// http://… → ws://…, https://… → wss://…
	return &tunnel{cli: c, wsURL: "ws" + strings.TrimPrefix(strings.TrimSuffix(a.URL, "/"), "http") + "/.sidegate/tcp"}
}

type tunnel struct {
	cli   *cli
	wsURL string
	login sync.Mutex // one browser sign-in at a time
}

func (t *tunnel) serve(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	ws, err := t.dial(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connection failed:", err)
		return
	}
	nc := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer nc.Close()
	fmt.Fprintln(os.Stderr, "connected", conn.RemoteAddr())
	done := make(chan struct{}, 3)
	go func() { io.Copy(nc, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, nc); done <- struct{}{} }()
	go func() { keepAlive(ctx, ws); done <- struct{}{} }()
	<-done
	fmt.Fprintln(os.Stderr, "disconnected", conn.RemoteAddr())
}

// dial opens the tunnel WebSocket, signing in again (with MFA or freshly,
// if the app demands it) when the proxy refuses the session.
func (t *tunnel) dial(ctx context.Context) (*websocket.Conn, error) {
	for attempt := 0; ; attempt++ {
		token := t.cli.token()
		h := http.Header{"Authorization": {"Bearer " + token}}
		ws, resp, err := websocket.Dial(ctx, t.wsURL, &websocket.DialOptions{HTTPHeader: h, Subprotocols: []string{"sidegate-tcp"}})
		if resp != nil {
			t.cli.updateToken(resp.Header)
		}
		if err == nil {
			ws.SetReadLimit(-1)
			return ws, nil
		}
		if resp == nil || attempt > 0 {
			return nil, err
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			var su stepUp
			if resp.Body != nil {
				json.NewDecoder(io.LimitReader(resp.Body, 1024)).Decode(&su)
			}
			t.login.Lock()
			if t.cli.token() == token { // not already renewed by another connection
				if su.MFA || su.MaxAge > 0 {
					fmt.Fprintln(os.Stderr, "This app requires a stronger or more recent sign-in.")
				}
				err = t.cli.login(ctx, su.MFA, su.MaxAge)
			}
			t.login.Unlock()
			if err != nil {
				return nil, err
			}
		case http.StatusForbidden:
			return nil, errors.New("you don't have access to this app")
		default:
			return nil, err
		}
	}
}

// launchRDP starts the platform's RDP client for addr, if one is found.
func launchRDP(addr string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("mstsc", "/v:"+addr)
	case "darwin":
		cmd = exec.Command("open", "rdp://full%20address=s:"+addr)
	default:
		for _, bin := range []string{"xfreerdp3", "xfreerdp", "wlfreerdp"} {
			if p, err := exec.LookPath(bin); err == nil {
				cmd = exec.Command(p, "/v:"+addr, "/dynamic-resolution")
				break
			}
		}
		if cmd == nil {
			if p, err := exec.LookPath("remmina"); err == nil {
				cmd = exec.Command(p, "-c", "rdp://"+addr)
			}
		}
	}
	if cmd == nil {
		fmt.Fprintf(os.Stderr, "No RDP client found; connect yours to %s\n", addr)
		return
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Could not start %s (%v); connect your RDP client to %s\n", cmd.Path, err, addr)
	}
}

// pingInterval keeps idle tunnels (e.g. an ssh session nobody types in)
// below common load balancer idle timeouts.
const pingInterval = 25 * time.Second

// keepAlive pings the proxy until ctx ends or a ping isn't answered in
// time, which means the connection is dead.
func keepAlive(ctx context.Context, ws *websocket.Conn) {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pctx, cancel := context.WithTimeout(ctx, pingInterval)
		err := ws.Ping(pctx)
		cancel()
		if err != nil {
			return
		}
	}
}
