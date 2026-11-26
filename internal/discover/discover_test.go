package discover

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindNewLocations(t *testing.T) {
	home := t.TempDir()
	mk := func(rel string, dir bool) {
		p := filepath.Join(home, filepath.FromSlash(rel))
		if dir {
			os.MkdirAll(p, 0o755)
			return
		}
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte("{}"), 0o644)
	}
	mk(".cursor/skills/fmt", true)
	mk(".openclaw/workspace/skills/wallet", true)
	mk(".copilot/mcp-config.json", false)
	mk(".aws/amazonq/agents/default.json", false)
	mk(".kiro/settings/mcp.json", false)
	mk(".claude/skills/.hidden", true) // hidden folders are not skills

	got := map[string]bool{}
	for _, it := range Find(home, "") {
		got[it.Agent+":"+filepath.ToSlash(it.Path[len(home)+1:])] = true
	}
	for _, want := range []string{
		"cursor:.cursor/skills/fmt",
		"openclaw:.openclaw/workspace/skills/wallet",
		"copilot-cli:.copilot/mcp-config.json",
		"amazon-q:.aws/amazonq/agents/default.json",
		"kiro:.kiro/settings/mcp.json",
	} {
		if !got[want] {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if len(got) != 5 {
		t.Errorf("unexpected items: %v", got)
	}
}
