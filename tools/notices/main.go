// SPDX-License-Identifier: AGPL-3.0-only

// Command notices writes the license and notice files of every third-party
// Go module the given packages are built from, for shipping with binaries:
//
//	go run ./tools/notices [-C dir] [-extra name=file]... ./cmd/... > THIRD_PARTY_NOTICES
//
// It fails if a module has no license file, so nothing slips through.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

var licenseFile = regexp.MustCompile(`(?i)^(LICEN[CS]E|COPYING|NOTICE)(\..*|-.*)?$`)

type extras []string

func (e *extras) String() string     { return strings.Join(*e, ",") }
func (e *extras) Set(v string) error { *e = append(*e, v); return nil }

func main() {
	dir := flag.String("C", ".", "module directory to run go list in")
	goStd := flag.Bool("gostd", true, "include the Go standard library's license (compiled into every binary)")
	var extra extras
	flag.Var(&extra, "extra", "additional component as name=path/to/LICENSE (repeatable)")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: notices [-C dir] [-extra name=file]... packages...")
		os.Exit(2)
	}

	args := append([]string{"list", "-deps", "-f", "{{with .Module}}{{if not .Main}}{{.Path}}\t{{.Version}}\t{{.Dir}}{{end}}{{end}}"}, flag.Args()...)
	cmd := exec.Command("go", args...)
	cmd.Dir = *dir
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		fail("go list: %v", err)
	}
	type module struct{ path, version, dir string }
	seen := map[string]module{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) == 3 {
			seen[f[0]] = module{f[0], f[1], f[2]}
		}
	}
	var mods []module
	for _, m := range seen {
		mods = append(mods, m)
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].path < mods[j].path })

	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	fmt.Fprintf(w, "Third-party software notices\n============================\n\nThis product includes the following third-party components, each under its\nown license reproduced below.\n\n")
	for _, m := range mods {
		fmt.Fprintf(w, "  - %s %s\n", m.path, m.version)
	}
	goLicense := ""
	if *goStd {
		goLicense = findGoLicense()
		fmt.Fprintf(w, "  - Go standard library %s\n", runtime.Version())
	}
	for _, e := range extra {
		name, _, _ := strings.Cut(e, "=")
		fmt.Fprintf(w, "  - %s\n", name)
	}
	for _, m := range mods {
		entries, err := os.ReadDir(m.dir)
		if err != nil {
			fail("%s: %v", m.path, err)
		}
		var files []string
		for _, e := range entries {
			if !e.IsDir() && licenseFile.MatchString(e.Name()) {
				files = append(files, filepath.Join(m.dir, e.Name()))
			}
		}
		if len(files) == 0 {
			fail("%s %s: no license file found", m.path, m.version)
		}
		section(w, m.path+" "+m.version, files)
	}
	if goLicense != "" {
		files := []string{goLicense}
		if patents := filepath.Join(filepath.Dir(goLicense), "PATENTS"); fileExists(patents) {
			files = append(files, patents)
		}
		section(w, "Go standard library "+runtime.Version(), files)
	}
	for _, e := range extra {
		name, file, ok := strings.Cut(e, "=")
		if !ok {
			fail("-extra %q: want name=file", e)
		}
		section(w, name, []string{file})
	}
}

func section(w *bufio.Writer, title string, files []string) {
	fmt.Fprintf(w, "\n\n%s\n%s\n", title, strings.Repeat("-", len(title)))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			fail("%v", err)
		}
		fmt.Fprintf(w, "\n%s:\n\n%s\n", filepath.Base(f), strings.TrimRight(string(data), "\n"))
	}
}

// findGoLicense locates the Go distribution's LICENSE; some Linux
// packages move it out of GOROOT.
func findGoLicense() string {
	out, _ := exec.Command("go", "env", "GOROOT").Output()
	candidates := []string{filepath.Join(strings.TrimSpace(string(out)), "LICENSE")}
	for _, pattern := range []string{"/usr/share/licenses/golang*/LICENSE", "/usr/share/doc/golang*/LICENSE"} {
		m, _ := filepath.Glob(pattern)
		candidates = append(candidates, m...)
	}
	for _, c := range candidates {
		if fileExists(c) {
			return c
		}
	}
	fail("Go standard library LICENSE not found (tried %s); pass -gostd=false and -extra instead", strings.Join(candidates, ", "))
	return ""
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "notices: "+format+"\n", args...)
	os.Exit(1)
}
