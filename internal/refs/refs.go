// Package refs extracts what an add-on points to outside itself.
//
// A scan only sees a snapshot. A link in a skill can serve harmless docs
// at review time and an attack later (AIR Security, 2026), so every URL,
// repository and package is recorded. The watch loop re-fetches them and
// re-scans when their content hash changes.
package refs

import (
	"regexp"
	"sort"
	"strings"

	"github.com/jpyoda/ammit/internal/ir"
)

var (
	urlRe = regexp.MustCompile(`https?://[^\s'"<>()\[\]{}` + "`" + `\\]+`)
	gitRe = regexp.MustCompile(`(?i)\b(?:github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)`)
	pkgRe = regexp.MustCompile(`(?i)\b(pip3?|uv\s+pip|uvx|pipx|npm|pnpm|yarn|bun|npx|bunx|go|cargo|gem|brew)\s+(?:install|add|i|run|exec|-y)?\s*((?:-[-\w=]+\s+)*)([@A-Za-z0-9_./:+-][@A-Za-z0-9_./:+=-]*)`)
)

// Extract fills a.References from every text file, including derived ones.
func Extract(a *ir.Artifact) {
	seen := map[string]bool{}
	add := func(r ir.Reference) {
		k := r.Type + "\x00" + r.Value + "\x00" + r.File
		if seen[k] {
			return
		}
		seen[k] = true
		a.References = append(a.References, r)
	}
	for _, f := range a.Files {
		if f.Text == "" {
			continue
		}
		file := a.Origin(f)
		lines := strings.Split(f.Text, "\n")
		for i, line := range lines {
			if len(line) > 20000 {
				line = line[:20000]
			}
			for _, u := range urlRe.FindAllString(line, -1) {
				add(ir.Reference{Type: "url", Value: strings.TrimRight(u, ".,;:!?*_"), File: file, Line: i + 1})
			}
			for _, m := range gitRe.FindAllStringSubmatch(line, -1) {
				repo := strings.TrimSuffix(m[2], ".git")
				add(ir.Reference{Type: "git", Value: strings.ToLower(m[1] + "/" + repo), File: file, Line: i + 1})
			}
			for _, m := range pkgRe.FindAllStringSubmatch(line, -1) {
				name := m[3]
				if strings.HasPrefix(name, "-") || name == "install" || name == "." || len(name) < 2 {
					continue
				}
				add(ir.Reference{Type: "package", Value: strings.ToLower(strings.Fields(m[1])[0]) + ":" + name, File: file, Line: i + 1})
			}
		}
	}
	sort.SliceStable(a.References, func(i, j int) bool {
		if a.References[i].Type != a.References[j].Type {
			return a.References[i].Type < a.References[j].Type
		}
		return a.References[i].Value < a.References[j].Value
	})
}
