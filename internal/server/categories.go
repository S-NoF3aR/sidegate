// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"slices"
	"strconv"
	"strings"
)

// otherCategory collects uncategorized apps once any app has a category.
const otherCategory = "Other"

// categoryNode is one level of the portal's category tree.
type categoryNode struct {
	ID       string // DOM id, unique per page
	Name     string // last path segment
	Path     string // full path, e.g. "Monitoring/Logs"
	Depth    int
	Apps     []portalApp
	Children []*categoryNode
	Count    int // apps in this subtree
}

// buildCategoryTree groups apps by their "/"-separated category paths. If no
// app has a category, all apps stay on the root and the portal shows a flat
// grid.
func buildCategoryTree(apps []portalApp) *categoryNode {
	root := &categoryNode{}
	categorized := slices.ContainsFunc(apps, func(a portalApp) bool { return a.Category != "" })
	index := map[string]*categoryNode{}
	for _, a := range apps {
		if !categorized {
			root.Apps = append(root.Apps, a)
			continue
		}
		if a.Category == "" {
			a.Category = otherCategory
		}
		node, path := root, ""
		for i, seg := range strings.Split(a.Category, "/") {
			if path != "" {
				path += "/"
			}
			path += seg
			child := index[path]
			if child == nil {
				child = &categoryNode{Name: seg, Path: path, Depth: i + 1}
				node.Children = append(node.Children, child)
				index[path] = child
			}
			node = child
		}
		node.Apps = append(node.Apps, a)
	}
	n := 0
	var finish func(c *categoryNode) int
	finish = func(c *categoryNode) int {
		slices.SortFunc(c.Children, func(x, y *categoryNode) int {
			// Uncategorized apps go last on the top level.
			if xo, yo := x.Path == otherCategory, y.Path == otherCategory; xo != yo {
				if xo {
					return 1
				}
				return -1
			}
			return strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name))
		})
		c.Count = len(c.Apps)
		for _, ch := range c.Children {
			n++
			ch.ID = "cat-" + strconv.Itoa(n)
			c.Count += finish(ch)
		}
		return c.Count
	}
	finish(root)
	return root
}
