// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sidegate/internal/config"
	"sidegate/internal/session"
)

func TestUpgradePassthrough(t *testing.T) {
	idp := newMockIdP(t, nil)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-User") != "bob" {
			http.Error(w, "no identity", http.StatusUnauthorized)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
		rw.Flush()
		io.Copy(conn, rw) // echo
	}))
	defer upstream.Close()

	cfg, err := config.Parse([]byte(`
publicURL: http://portal.test.local
domain: test.local
session: {secret: "0123456789abcdef0123456789abcdef"}
oidc: {issuer: "` + idp.URL + `", clientID: client}
database: {url: "sqlite:` + t.TempDir() + `/sidegate.db"}
apps: [{name: ws, upstream: "` + upstream.URL + `", allowedGroups: ["*"]}]
`))
	if err != nil {
		t.Fatal(err)
	}
	srv := newTestServer(t, cfg)
	proxy := httptest.NewServer(srv.Handler())
	defer proxy.Close()

	cookie, _ := srv.sessions.Seal(srv.cookieName, session.Session{
		Subject: "b", Username: "bob", Expiry: time.Now().Add(time.Hour).Unix(),
	})
	conn, err := net.Dial("tcp", proxy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: ws.test.local\r\nUpgrade: echo\r\nConnection: Upgrade\r\n"+
		"Cookie: _sidegate="+cookie+"\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	io.WriteString(conn, "ping\n")
	line, _ := br.ReadString('\n')
	if strings.TrimSpace(line) != "ping" {
		t.Errorf("echo = %q", line)
	}
}
