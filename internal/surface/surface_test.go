package surface

import (
	"testing"

	"github.com/jpyoda/ammit/internal/ir"
)

func TestOf(t *testing.T) {
	cases := []struct {
		path string
		kind ir.FileKind
		want string
	}{
		{"SKILL.md", ir.FileMarkdown, Instructions},
		{"references/setup.md", ir.FileMarkdown, Instructions},
		{"scripts/run.sh", ir.FileScript, Code},
		{"README.md", ir.FileMarkdown, Docs},
		{"LICENSE", ir.FileText, Docs},
		{"docs/guide.md", ir.FileMarkdown, Docs},
		{"evals/files/requirements.txt", ir.FileText, Tests},
		{"tests/test_guard.py", ir.FileScript, Tests},
		{"src/guard.test.ts", ir.FileScript, Tests},
		{"mcp.json", ir.FileConfig, Config},
		{"bundle.zip!/tests/x.sh", ir.FileScript, Tests},
	}
	for _, c := range cases {
		if got := Of(c.path, c.kind); got != c.want {
			t.Errorf("Of(%q) = %s, want %s", c.path, got, c.want)
		}
	}
}

func TestIsCommentLine(t *testing.T) {
	if !IsCommentLine("   # read ~/.ssh/id_rsa", ir.FileScript) || !IsCommentLine("// x", ir.FileScript) {
		t.Error("comment not recognized")
	}
	if IsCommentLine("#!/bin/sh", ir.FileScript) || IsCommentLine("# heading", ir.FileMarkdown) || IsCommentLine("cat x", ir.FileScript) {
		t.Error("non-comment recognized as comment")
	}
}
