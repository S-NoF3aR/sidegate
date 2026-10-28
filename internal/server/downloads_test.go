// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sidegate/internal/config"
)

// fakeRelease writes a dist/cli-style directory and returns its checksums.
func fakeRelease(t *testing.T) (string, map[string]string) {
	dir := t.TempDir()
	sums := map[string]string{}
	var lines []string
	for _, name := range []string{"sidegate-linux-amd64", "sidegate-darwin-arm64", "sidegate-windows-amd64.exe"} {
		body := []byte("binary " + name)
		os.WriteFile(filepath.Join(dir, name), body, 0o755)
		h := sha256.Sum256(body)
		sums[name] = hex.EncodeToString(h[:])
		lines = append(lines, sums[name]+"  "+name)
	}
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "VERSION"), []byte("1.2.3\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "LICENSE"), []byte("GNU AFFERO GENERAL PUBLIC LICENSE"), 0o644)
	os.WriteFile(filepath.Join(dir, "THIRD_PARTY_NOTICES"), []byte("Third-party software notices"), 0o644)
	return dir, sums
}

func TestCLIDownloads(t *testing.T) {
	e := newEnv(t, alice)
	dir, sums := fakeRelease(t)
	d, err := loadCLIDownloads(dir)
	if err != nil || d == nil || d.Version != "1.2.3" || len(d.Files) != 3 {
		t.Fatalf("load: %+v %v", d, err)
	}
	e.srv.downloads = d
	addRDPApp(t, e, config.App{Name: "bastion", Upstream: "ssh://bastion:22", AllowedGroups: []string{"*"}})
	portal := e.srv.public.String()

	// The page is for signed-in users and personalizes the examples.
	_, page := e.get(t, e.url("portal", "/cli"))
	for _, want := range []string{
		"Version <code>1.2.3</code>",
		"irm " + portal + "/cli/install.ps1 | iex",
		"curl -fsSL " + portal + "/cli/install.sh | sh",
		"sidegate login " + portal,
		"sidegate ssh alice@bastion",
		"ssh bastion.test.local",
		"sidegate rdp win1 -port 13389", // placeholder: the user has no RDP app
		"Host *.test.local",
		`AppData\Local\Programs\sidegate\sidegate.exe proxy %h`,
		`id="troubleshooting"`,
		`href="` + portal + `/cli/download/sidegate-windows-amd64.exe"`,
		sums["sidegate-linux-amd64"],
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if _, portalPage := e.get(t, e.url("portal", "/")); !strings.Contains(portalPage, "Get the Sidegate CLI") {
		t.Error("portal doesn't link the CLI for users with remote apps")
	}

	// Downloads need no sign-in, and only listed files are served.
	plain := &http.Client{Transport: e.client.Transport}
	fetch := func(path string) (int, string, http.Header) {
		resp, err := plain.Get(e.url("portal", path))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), resp.Header
	}
	if status, body, h := fetch("/cli/download/sidegate-linux-amd64"); status != 200 || body != "binary sidegate-linux-amd64" ||
		!strings.Contains(h.Get("Content-Disposition"), "attachment") {
		t.Errorf("download: %d %q %v", status, body, h)
	}
	if status, body, _ := fetch("/cli/download/SHA256SUMS"); status != 200 || !strings.Contains(body, sums["sidegate-darwin-arm64"]) {
		t.Errorf("SHA256SUMS: %d", status)
	}
	if status, body, h := fetch("/cli/download/LICENSE"); status != 200 || !strings.Contains(body, "AFFERO") || !strings.HasPrefix(h.Get("Content-Type"), "text/plain") {
		t.Errorf("LICENSE: %d", status)
	}
	if status, _, _ := fetch("/cli/download/THIRD_PARTY_NOTICES"); status != 200 {
		t.Errorf("THIRD_PARTY_NOTICES: %d", status)
	}
	for _, bad := range []string{"/cli/download/VERSION", "/cli/download/sidegate-linux-arm64", "/cli/download/..%2FVERSION", "/cli/download/%2e%2e%2fSHA256SUMS"} {
		if status, _, _ := fetch(bad); status != 404 {
			t.Errorf("%s: %d, want 404", bad, status)
		}
	}

	// Install scripts embed the portal and the checksums for their platforms.
	_, sh, _ := fetch("/cli/install.sh")
	if !strings.Contains(sh, "portal='"+portal+"'") || !strings.Contains(sh, "sidegate-linux-amd64) expected="+sums["sidegate-linux-amd64"]) ||
		!strings.Contains(sh, "sidegate-darwin-arm64) expected=") || strings.Contains(sh, ".exe") {
		t.Errorf("install.sh:\n%s", sh)
	}
	_, ps1, _ := fetch("/cli/install.ps1")
	if !strings.Contains(ps1, fmt.Sprintf("'sidegate-windows-amd64.exe' = '%s'", sums["sidegate-windows-amd64.exe"])) ||
		strings.Contains(ps1, "linux") {
		t.Errorf("install.ps1:\n%s", ps1)
	}
}

func TestCLIDownloadsMissing(t *testing.T) {
	if d, err := loadCLIDownloads(t.TempDir()); d != nil || err != nil {
		t.Fatalf("empty dir: %v %v", d, err)
	}
	dir, _ := fakeRelease(t)
	os.Remove(filepath.Join(dir, "sidegate-linux-amd64"))
	if _, err := loadCLIDownloads(dir); err == nil {
		t.Error("a file listed in SHA256SUMS but missing should be an error")
	}

	e := newEnv(t, alice) // the test config has no downloads
	_, page := e.get(t, e.url("portal", "/cli"))
	if !strings.Contains(page, "No downloads available") {
		t.Error("page without downloads")
	}
	resp, _ := (&http.Client{Transport: e.client.Transport}).Get(e.url("portal", "/cli/install.sh"))
	if resp.StatusCode != 404 {
		t.Errorf("install.sh without downloads: %d", resp.StatusCode)
	}
}
