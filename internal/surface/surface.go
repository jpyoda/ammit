// Package surface labels where a finding sits: in code the agent runs, in
// instructions the agent follows, or somewhere it is only mentioned.
//
// The label is reporting metadata first. Rules marked context_sensitive may
// be demoted one severity step on the docs, tests and comments surfaces;
// nothing else is ever demoted, and instructions always count like code,
// because an agent acts on them. (Idea credited to NVIDIA SkillSpector.)
package surface

import (
	"path"
	"strings"

	"github.com/jpyoda/ammit/internal/ir"
)

// Surface names.
const (
	Code         = "code"
	Instructions = "instructions"
	Config       = "config"
	Docs         = "docs"
	Tests        = "tests"
	Comments     = "comments"
)

// Passive reports whether a surface only mentions things rather than doing
// or instructing them.
func Passive(s string) bool { return s == Docs || s == Tests || s == Comments }

var testDirs = map[string]bool{
	"test": true, "tests": true, "__tests__": true, "spec": true, "specs": true,
	"testdata": true, "fixtures": true, "evals": true, "eval": true,
}

var docNames = []string{"readme", "license", "licence", "notice", "changelog", "contributing",
	"code_of_conduct", "security", "authors", "copying", "third_party_notices"}

// Of labels a file by its logical path and kind. Paths inside archives are
// labeled by their inner path.
func Of(p string, kind ir.FileKind) string {
	if i := strings.LastIndex(p, "!/"); i >= 0 {
		p = p[i+2:]
	}
	p = strings.ToLower(p)
	base := path.Base(p)
	for _, seg := range strings.Split(path.Dir(p), "/") {
		if testDirs[seg] {
			return Tests
		}
		if seg == "docs" || seg == "doc" {
			return Docs
		}
	}
	if strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.go") || strings.HasSuffix(base, "_test.py") ||
		strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") || base == "conftest.py" {
		return Tests
	}
	stem := strings.TrimSuffix(base, path.Ext(base))
	for _, d := range docNames {
		if stem == d {
			return Docs
		}
	}
	switch kind {
	case ir.FileMarkdown, ir.FileText:
		// Any other markdown can be pulled in by SKILL.md or an agent file,
		// so it counts as instructions.
		return Instructions
	case ir.FileConfig:
		return Config
	}
	return Code
}

// IsCommentLine reports whether a line of a script or config file is a comment.
func IsCommentLine(line string, kind ir.FileKind) bool {
	if kind != ir.FileScript && kind != ir.FileConfig {
		return false
	}
	t := strings.TrimSpace(line)
	for _, p := range []string{"#", "//", "/*", "* ", "--", ";", "rem "} {
		if strings.HasPrefix(strings.ToLower(t), p) && !strings.HasPrefix(t, "#!") {
			return true
		}
	}
	return t == "*"
}
