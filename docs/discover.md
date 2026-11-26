# Discovering installed add-ons

`ammit discover` looks for add-ons at well-known locations, reads them, and never
runs anything. It is meant to run on employee laptops from MDM (Jamf, Intune,
Kandji), osquery, or a scheduled job.

```sh
ammit discover                              # list
ammit discover --format json                # list, machine-readable
ammit discover --scan --format json         # scan everything found
ammit discover --project ~/code/app --scan  # include a project's files
```

Locations checked (relative to the home folder):

| Agent | Locations |
|---|---|
| Claude Code | `.claude/skills/*`, `.claude/agents`, `.claude/commands`, `.claude/plugins/cache/*/*`, `.claude/plugins/marketplaces/*`, `.claude/settings.json`, `.claude/CLAUDE.md` |
| Claude Desktop | `claude_desktop_config.json` in the platform's application-support folder |
| Codex | `.codex/skills/*`, `.codex/config.toml`, `.codex/AGENTS.md` |
| Cursor | `.cursor/mcp.json` |
| Gemini CLI | `.gemini/settings.json`, `.gemini/GEMINI.md`, `.gemini/extensions/*` |
| VS Code | `Code/User/mcp.json` in the platform's config folder |
| Windsurf | `.codeium/windsurf/mcp_config.json` |

Project locations: `.claude/skills/*`, `.claude/agents`, `.claude/commands`,
`.claude/settings.json`, `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `CLAUDE.md`,
`AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules`, `.github/copilot-instructions.md`,
`.agents/skills/*`.

Agents move these between releases. Pull requests for new agents or locations are
welcome; add a test in `cmd/ammit/main_test.go`.

**Not scanned yet:** `~/.claude.json` holds Claude Code's MCP servers but also prompt
history, so it needs a parser that reads only the `mcpServers` key first. MCP servers
configured as `npx some-server` are scanned as configuration only: seeing their tool
descriptions means running them, which belongs in the sandbox.
