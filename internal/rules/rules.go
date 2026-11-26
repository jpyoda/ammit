// Package rules implements the pattern rule engine.
//
// Rules are JSON documents (see docs/rules.md). Patterns are Go RE2 regular
// expressions, which run in linear time, so a hostile add-on cannot make a
// rule hang (no catastrophic backtracking).
package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jpyoda/ammit/internal/finding"
	"github.com/jpyoda/ammit/internal/ir"
)

// Rule is one detection rule.
type Rule struct {
	ID          string           `json:"id"`
	Title       string           `json:"title"`
	Severity    finding.Severity `json:"severity"`
	Category    string           `json:"category"`
	Description string           `json:"description"`
	Remediation string           `json:"remediation,omitempty"`
	// FileKinds limits the rule to some file kinds (markdown, script,
	// config, text). Empty means every text file.
	FileKinds []string `json:"file_kinds,omitempty"`
	// Patterns are RE2 regular expressions.
	Patterns []string `json:"patterns"`
	// ExcludePatterns drop a match when the matched line also matches one
	// of them (for example, the official package registry).
	ExcludePatterns []string `json:"exclude_patterns,omitempty"`
	// Match is "any" (default: report each match of each pattern) or "all"
	// (every pattern must match somewhere in the same file).
	Match string `json:"match,omitempty"`
	// CaseSensitive turns off the default case-insensitive matching.
	CaseSensitive bool     `json:"case_sensitive,omitempty"`
	Confidence    float64  `json:"confidence,omitempty"`
	References    []string `json:"references,omitempty"`

	compiled []*regexp.Regexp
	excludes []*regexp.Regexp
	kinds    map[ir.FileKind]bool
}

// Pack is a file of rules.
type Pack struct {
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

// Set is a compiled collection of rules.
type Set struct {
	Rules []*Rule
}

// LoadFS loads every *.json pack in fsys.
func LoadFS(fsys fs.FS) (*Set, error) {
	s := &Set{}
	ids := map[string]string{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
			return err
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		var pk Pack
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&pk); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		for i := range pk.Rules {
			r := pk.Rules[i]
			if prev, dup := ids[r.ID]; dup {
				return fmt.Errorf("%s: duplicate rule id %s (also in %s)", p, r.ID, prev)
			}
			ids[r.ID] = p
			if err := r.compile(); err != nil {
				return fmt.Errorf("%s: rule %s: %w", p, r.ID, err)
			}
			s.Rules = append(s.Rules, &r)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(s.Rules, func(i, j int) bool { return s.Rules[i].ID < s.Rules[j].ID })
	return s, nil
}

// LoadDir loads packs from a directory on disk.
func LoadDir(dir string) (*Set, error) {
	return LoadFS(os.DirFS(filepath.Clean(dir)))
}

// Merge adds other's rules; rules with the same ID replace existing ones,
// so organizations can override a default rule.
func (s *Set) Merge(other *Set) {
	idx := map[string]int{}
	for i, r := range s.Rules {
		idx[r.ID] = i
	}
	for _, r := range other.Rules {
		if i, ok := idx[r.ID]; ok {
			s.Rules[i] = r
		} else {
			s.Rules = append(s.Rules, r)
		}
	}
}

func (r *Rule) compile() error {
	if r.ID == "" || r.Title == "" {
		return fmt.Errorf("id and title are required")
	}
	if len(r.Patterns) == 0 {
		return fmt.Errorf("at least one pattern is required")
	}
	switch r.Match {
	case "", "any", "all":
	default:
		return fmt.Errorf("match must be any or all, got %q", r.Match)
	}
	if r.Confidence == 0 {
		r.Confidence = 0.6
	}
	for _, p := range r.Patterns {
		if !r.CaseSensitive {
			p = "(?i)" + p
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return err
		}
		r.compiled = append(r.compiled, re)
	}
	for _, p := range r.ExcludePatterns {
		if !r.CaseSensitive {
			p = "(?i)" + p
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("exclude pattern: %w", err)
		}
		r.excludes = append(r.excludes, re)
	}
	if len(r.FileKinds) > 0 {
		r.kinds = map[ir.FileKind]bool{}
		for _, k := range r.FileKinds {
			fk := ir.FileKind(k)
			if !fk.IsText() {
				return fmt.Errorf("file_kinds: %q is not a text kind", k)
			}
			r.kinds[fk] = true
		}
	}
	return nil
}

// Analyzer runs a rule set over an artifact.
type Analyzer struct{ Set *Set }

func (Analyzer) Name() string { return "rules" }

const maxPerRuleFile = 10

func (an Analyzer) Analyze(ctx context.Context, a *ir.Artifact) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, f := range a.Files {
		if f.Text == "" || !f.Kind.IsText() {
			continue
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}
		origin := a.Origin(f)
		for _, r := range an.Set.Rules {
			if r.kinds != nil && !r.kinds[f.Kind] {
				continue
			}
			for _, m := range r.match(f.Text) {
				ev := finding.Clip(m.text, 160)
				if r.Category == "secrets" {
					ev = "[redacted: matched a credential pattern]"
				}
				fd := finding.Finding{RuleID: r.ID, Title: r.Title, Severity: r.Severity, Category: r.Category,
					Message: r.Description, File: origin, Line: m.line, Evidence: ev,
					Confidence: r.Confidence, Remediation: r.Remediation}
				if f.Path != origin {
					fd.Location = f.Path
					if f.Derived {
						fd.Line = 0 // line numbers in derived files don't map to the origin
						fd.Message += " (found in content decoded from " + origin + ")"
					}
				}
				out = append(out, fd)
			}
		}
	}
	return out, nil
}

type match struct {
	line int
	text string
}

func (r *Rule) excluded(line string) bool {
	for _, re := range r.excludes {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

func (r *Rule) match(text string) []match {
	if r.Match == "all" {
		var first []int
		for i, re := range r.compiled {
			loc := re.FindStringIndex(text)
			if loc == nil {
				return nil
			}
			if i == 0 {
				first = loc
			}
		}
		lt := lineText(text, first[0])
		if r.excluded(lt) {
			return nil
		}
		return []match{{lineOf(text, first[0]), lt}}
	}
	var out []match
	seen := map[int]bool{}
	for _, re := range r.compiled {
		for _, loc := range re.FindAllStringIndex(text, maxPerRuleFile) {
			ln := lineOf(text, loc[0])
			if seen[ln] {
				continue
			}
			lt := lineText(text, loc[0])
			if r.excluded(lt) {
				continue
			}
			seen[ln] = true
			out = append(out, match{ln, lt})
			if len(out) >= maxPerRuleFile {
				return out
			}
		}
	}
	return out
}

func lineOf(s string, off int) int { return strings.Count(s[:off], "\n") + 1 }

func lineText(s string, off int) string {
	start := strings.LastIndexByte(s[:off], '\n') + 1
	end := strings.IndexByte(s[off:], '\n')
	if end < 0 {
		end = len(s)
	} else {
		end += off
	}
	if end-start > 400 {
		if off-start > 200 {
			start = off - 100
		}
		if end-start > 400 {
			end = start + 400
		}
	}
	return s[start:end]
}
