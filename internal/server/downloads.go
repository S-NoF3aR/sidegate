// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"sidegate/internal/session"
)

// The portal's /cli page offers the Sidegate CLI for download, together with
// install scripts that verify checksums. The binaries come from a directory
// laid out like "make release" writes dist/cli:
//
//	sidegate-<os>-<arch>[.exe]
//	SHA256SUMS
//	VERSION

// cliDocFiles are served next to the binaries: checksums and, as the
// binaries are AGPL, their license and third-party notices.
var cliDocFiles = []string{"SHA256SUMS", "LICENSE", "THIRD_PARTY_NOTICES"}

var cliFileRe = regexp.MustCompile(`^sidegate-(windows|linux|darwin)-(amd64|arm64)(\.exe)?$`)

type cliDownloads struct {
	dir     string
	Version string
	Files   []cliFile
}

type cliFile struct {
	Name, OS, Arch, SHA256 string
	Size                   int64
}

// loadCLIDownloads reads the download directory. A missing directory or
// checksum file means no downloads, not an error.
func loadCLIDownloads(dir string) (*cliDownloads, error) {
	sums, err := os.Open(filepath.Join(dir, "SHA256SUMS"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer sums.Close()
	d := &cliDownloads{dir: dir, Version: "unknown"}
	if v, err := os.ReadFile(filepath.Join(dir, "VERSION")); err == nil {
		d.Version = strings.TrimSpace(string(v))
	}
	sc := bufio.NewScanner(sums)
	for sc.Scan() {
		hash, name, ok := strings.Cut(sc.Text(), "  ")
		m := cliFileRe.FindStringSubmatch(name)
		if !ok || m == nil || len(hash) != 64 {
			continue
		}
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("%s listed in SHA256SUMS: %w", name, err)
		}
		d.Files = append(d.Files, cliFile{Name: name, OS: m[1], Arch: m[2], SHA256: hash, Size: fi.Size()})
	}
	if len(d.Files) == 0 {
		return nil, nil
	}
	return d, sc.Err()
}

func (d *cliDownloads) file(name string) *cliFile {
	if d == nil {
		return nil
	}
	i := slices.IndexFunc(d.Files, func(f cliFile) bool { return f.Name == name })
	if i < 0 {
		return nil
	}
	return &d.Files[i]
}

// ForOS returns the files for one operating system.
func (d *cliDownloads) ForOS(os string) []cliFile {
	var out []cliFile
	for _, f := range d.Files {
		if f.OS == os {
			out = append(out, f)
		}
	}
	return out
}

type cliPageData struct {
	User      *session.Session
	Admin     bool
	Portal    string
	Domain    string
	Downloads *cliDownloads
	// Examples are the user's own RDP and SSH apps.
	RDP, SSH []portalApp
}

func (s *Server) handleCLIPage(w http.ResponseWriter, r *http.Request) {
	sess := s.authenticate(w, r)
	if sess == nil {
		s.requireLogin(w, r)
		return
	}
	setLogUser(r, sess)
	d := cliPageData{User: sess, Admin: s.isAdmin(sess), Portal: s.public.String(), Domain: s.domain, Downloads: s.downloads}
	for _, a := range s.portalData(sess).Apps {
		switch a.Type {
		case "rdp":
			d.RDP = append(d.RDP, a)
		case "ssh":
			d.SSH = append(d.SSH, a)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, http.StatusOK, "cli", d)
}

// handleCLIDownload serves a binary. Downloads need no sign-in: they hold
// no secrets, and install scripts fetch them with plain curl.
func (s *Server) handleCLIDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	doc := slices.Contains(cliDocFiles, name)
	if s.downloads == nil || (!doc && s.downloads.file(name) == nil) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	if doc {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	}
	http.ServeFile(w, r, filepath.Join(s.downloads.dir, name))
}

func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	if s.downloads == nil {
		http.Error(w, "Sidegate CLI downloads are not available on this proxy", http.StatusNotFound)
		return
	}
	tmpl := installSh
	if strings.HasSuffix(r.URL.Path, ".ps1") {
		tmpl = installPs1
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	tmpl.Execute(w, map[string]any{"Portal": s.public.String(), "Downloads": s.downloads})
}

// Install scripts. The expected checksums are embedded, so a truncated or
// corrupted download is never installed.
var installSh = template.Must(template.New("install.sh").Parse(`#!/bin/sh
# Installs the Sidegate CLI {{.Downloads.Version}} for Linux and macOS.
#   curl -fsSL {{.Portal}}/cli/install.sh | sh
# Set SIDEGATE_CLI_DIR to choose the directory (default ~/.local/bin).
set -eu
portal='{{.Portal}}'
case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "sidegate: unsupported OS $(uname -s); see $portal/cli" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "sidegate: unsupported CPU $(uname -m); see $portal/cli" >&2; exit 1 ;;
esac
name="sidegate-$os-$arch"
case "$name" in
{{- range .Downloads.Files}}{{if ne .OS "windows"}}
  {{.Name}}) expected={{.SHA256}} ;;{{end}}{{end}}
  *) echo "sidegate: no build for $os/$arch; see $portal/cli" >&2; exit 1 ;;
esac
dir="${SIDEGATE_CLI_DIR:-$HOME/.local/bin}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "Downloading $name {{.Downloads.Version}}..."
curl -fsSL -o "$tmp/sidegate" "$portal/cli/download/$name"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/sidegate" | cut -d' ' -f1)"
else
  actual="$(shasum -a 256 "$tmp/sidegate" | cut -d' ' -f1)"
fi
if [ "$actual" != "$expected" ]; then
  echo "sidegate: checksum mismatch, not installing" >&2
  exit 1
fi
mkdir -p "$dir"
install -m 755 "$tmp/sidegate" "$dir/sidegate"
echo "Installed $dir/sidegate"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Note: $dir is not in your PATH; add it, e.g. in ~/.profile" ;;
esac
echo "Next: sidegate login $portal"
`))

var installPs1 = template.Must(template.New("install.ps1").Parse(`# Installs the Sidegate CLI {{.Downloads.Version}} for Windows, for the current user.
#   irm {{.Portal}}/cli/install.ps1 | iex
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$portal = '{{.Portal}}'
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$name = "sidegate-windows-$arch.exe"
$hashes = @{
{{- range .Downloads.Files}}{{if eq .OS "windows"}}
  '{{.Name}}' = '{{.SHA256}}'{{end}}{{end}}
}
if (-not $hashes.ContainsKey($name)) { throw "No sidegate build for windows/$arch; see $portal/cli" }
$dir = Join-Path $env:LOCALAPPDATA 'Programs\sidegate'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$dest = Join-Path $dir 'sidegate.exe'
$tmp = "$dest.download"
Write-Host "Downloading $name {{.Downloads.Version}}..."
Invoke-WebRequest -UseBasicParsing -Uri "$portal/cli/download/$name" -OutFile $tmp
$actual = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash.ToLower()
if ($actual -ne $hashes[$name]) {
  Remove-Item $tmp
  throw 'sidegate: checksum mismatch, not installing'
}
Move-Item -Force -Path $tmp -Destination $dest
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
if (($userPath -split ';') -notcontains $dir) {
  [Environment]::SetEnvironmentVariable('Path', (($userPath.TrimEnd(';') + ';' + $dir).TrimStart(';')), 'User')
  $env:Path = "$env:Path;$dir"
  Write-Host "Added $dir to your PATH (new terminals pick it up)."
}
Write-Host "Installed $dest"
Write-Host "Next: sidegate login $portal"
`))
