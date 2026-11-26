// Package discover finds agent add-ons installed on a machine.
//
// It only reads files at well-known locations. It never starts an MCP
// server or runs an add-on: an MCP config that launches `npx some-server`
// is reported and scanned as configuration, not executed.
//
// The location list is best effort and agents move things between
// releases. Contributions for more agents are welcome (docs/discover.md).
package discover

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Location is a place where an agent keeps add-ons.
type Location struct {
	Agent string // claude-code, claude-desktop, codex, cursor, gemini-cli, vscode, windsurf, project
	What  string // skills, plugins, agents, commands, mcp-config, settings, instructions
	// Glob relative to the base (home or project). Each match is one
	// add-on: a directory (skill, plugin) or a file (config, instructions).
	Glob string
}

// Item is one add-on found on disk.
type Item struct {
	Agent string `json:"agent"`
	What  string `json:"what"`
	Path  string `json:"path"`
	IsDir bool   `json:"is_dir"`
}

func homeLocations() []Location {
	ls := []Location{
		{"claude-code", "skills", ".claude/skills/*"},
		{"claude-code", "agents", ".claude/agents"},
		{"claude-code", "commands", ".claude/commands"},
		{"claude-code", "plugins", ".claude/plugins/cache/*/*"},
		{"claude-code", "plugins", ".claude/plugins/marketplaces/*"},
		{"claude-code", "settings", ".claude/settings.json"},
		{"claude-code", "instructions", ".claude/CLAUDE.md"},
		// ~/.claude.json also holds MCP servers but mixes them with prompt
		// history, so it needs a parser that reads only "mcpServers"
		// before it can be scanned without leaking history into reports.
		{"codex", "skills", ".codex/skills/*"},
		{"codex", "mcp-config", ".codex/config.toml"},
		{"codex", "instructions", ".codex/AGENTS.md"},
		{"cursor", "mcp-config", ".cursor/mcp.json"},
		{"gemini-cli", "mcp-config", ".gemini/settings.json"},
		{"gemini-cli", "instructions", ".gemini/GEMINI.md"},
		{"gemini-cli", "extensions", ".gemini/extensions/*"},
		{"windsurf", "mcp-config", ".codeium/windsurf/mcp_config.json"},
	}
	switch runtime.GOOS {
	case "darwin":
		ls = append(ls,
			Location{"claude-desktop", "mcp-config", "Library/Application Support/Claude/claude_desktop_config.json"},
			Location{"vscode", "mcp-config", "Library/Application Support/Code/User/mcp.json"})
	case "windows":
		ls = append(ls,
			Location{"claude-desktop", "mcp-config", "AppData/Roaming/Claude/claude_desktop_config.json"},
			Location{"vscode", "mcp-config", "AppData/Roaming/Code/User/mcp.json"})
	default:
		ls = append(ls,
			Location{"claude-desktop", "mcp-config", ".config/Claude/claude_desktop_config.json"},
			Location{"vscode", "mcp-config", ".config/Code/User/mcp.json"})
	}
	return ls
}

func projectLocations() []Location {
	return []Location{
		{"project", "skills", ".claude/skills/*"},
		{"project", "agents", ".claude/agents"},
		{"project", "commands", ".claude/commands"},
		{"project", "settings", ".claude/settings.json"},
		{"project", "mcp-config", ".mcp.json"},
		{"project", "mcp-config", ".cursor/mcp.json"},
		{"project", "mcp-config", ".vscode/mcp.json"},
		{"project", "instructions", "CLAUDE.md"},
		{"project", "instructions", "AGENTS.md"},
		{"project", "instructions", "GEMINI.md"},
		{"project", "instructions", ".cursorrules"},
		{"project", "instructions", ".cursor/rules"},
		{"project", "instructions", ".github/copilot-instructions.md"},
		{"project", "skills", ".agents/skills/*"},
	}
}

// Find returns add-ons under home (if non-empty) and project (if non-empty).
func Find(home, project string) []Item {
	var items []Item
	seen := map[string]bool{}
	scan := func(base string, ls []Location) {
		for _, l := range ls {
			matches, _ := filepath.Glob(filepath.Join(base, filepath.FromSlash(l.Glob)))
			for _, m := range matches {
				fi, err := os.Lstat(m)
				if err != nil || fi.Mode()&os.ModeSymlink != 0 || seen[m] {
					continue
				}
				if strings.HasPrefix(filepath.Base(m), ".") && strings.Contains(l.Glob, "*") && fi.IsDir() {
					continue // hidden folders inside skill dirs are not skills
				}
				seen[m] = true
				items = append(items, Item{Agent: l.Agent, What: l.What, Path: m, IsDir: fi.IsDir()})
			}
		}
	}
	if home != "" {
		scan(home, homeLocations())
	}
	if project != "" {
		scan(project, projectLocations())
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Agent != items[j].Agent {
			return items[i].Agent < items[j].Agent
		}
		return items[i].Path < items[j].Path
	})
	return items
}
