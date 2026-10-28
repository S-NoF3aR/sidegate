// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"strings"
	"testing"
)

func TestBuildCategoryTree(t *testing.T) {
	flat := buildCategoryTree([]portalApp{{Name: "a"}, {Name: "b"}})
	if len(flat.Children) != 0 || len(flat.Apps) != 2 || flat.Count != 2 {
		t.Errorf("without categories the tree must stay flat: %+v", flat)
	}

	tree := buildCategoryTree([]portalApp{
		{Name: "loki", Category: "Monitoring/Logs"},
		{Name: "grafana", Category: "Monitoring"},
		{Name: "misc"},
		{Name: "argocd", Category: "CI/CD"},
		{Name: "tempo", Category: "Monitoring/Traces"},
		{Name: "wiki", Category: "docs"},
	})
	var names []string
	for _, c := range tree.Children {
		names = append(names, c.Name)
	}
	// Case-insensitive order, uncategorized last as "Other".
	if got := strings.Join(names, ","); got != "CI,docs,Monitoring,Other" {
		t.Errorf("top level = %s", got)
	}
	mon := tree.Children[2]
	if mon.Count != 3 || len(mon.Apps) != 1 || len(mon.Children) != 2 || mon.Children[0].Path != "Monitoring/Logs" {
		t.Errorf("Monitoring = %+v", mon)
	}
	if other := tree.Children[3]; other.Apps[0].Category != otherCategory {
		t.Errorf("uncategorized app should be filed under Other: %+v", other.Apps[0])
	}
	if tree.Count != 6 {
		t.Errorf("total count = %d", tree.Count)
	}
	ids := map[string]bool{}
	var walk func(c *categoryNode)
	walk = func(c *categoryNode) {
		for _, ch := range c.Children {
			if ch.ID == "" || ids[ch.ID] {
				t.Errorf("missing or duplicate id %q", ch.ID)
			}
			ids[ch.ID] = true
			walk(ch)
		}
	}
	walk(tree)
}

func TestPortalShowsCategories(t *testing.T) {
	e := newEnv(t, root)
	token := e.createToken(t, "t")
	for _, body := range []string{
		`{"name":"loki","upstream":"http://x","allowedGroups":["*"],"category":" Monitoring / Logs "}`,
		`{"name":"grafana2","upstream":"http://x","allowedGroups":["*"],"category":"Monitoring"}`,
	} {
		if status, resp := e.api(t, token, "POST", "/apps", body); status != 201 {
			t.Fatalf("create: %d %s", status, resp)
		}
	}
	if status, body := e.api(t, token, "GET", "/apps/loki", ""); status != 200 || !strings.Contains(body, `"category":"Monitoring/Logs"`) {
		t.Errorf("category not normalized: %s", body)
	}
	_, page := e.get(t, e.url("portal", "/"))
	for _, want := range []string{`class="cat-nav"`, `data-cat="Monitoring/Logs"`, `>Logs <span class="count">1</span>`, `>Monitoring <span class="count">2</span>`, `>Other <span`} {
		if !strings.Contains(page, want) {
			t.Errorf("portal missing %q", want)
		}
	}
	// The admin form offers existing categories, including parents.
	_, form := e.get(t, e.url("portal", "/admin/apps/new"))
	if !strings.Contains(form, `<option value="Monitoring">`) || !strings.Contains(form, `<option value="Monitoring/Logs">`) {
		t.Error("category suggestions missing on the admin form")
	}
}
