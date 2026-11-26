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
| Cursor | `.cursor/mcp.json`, `.cursor/skills/*` |
| Gemini CLI | `.gemini/settings.json`, `.gemini/GEMINI.md`, `.gemini/extensions/*`, `.gemini/skills/*` |
| Antigravity | `.gemini/antigravity/mcp_config.json` |
| GitHub Copilot CLI | `.copilot/mcp-config.json`, `.copilot/skills/*` |
| VS Code | `Code/User/mcp.json` in the platform's config folder, `.vscode/mcp.json` |
| Windsurf | `.codeium/windsurf/mcp_config.json`, `.codeium/windsurf/skills/*` |
| Amazon Q | `.aws/amazonq/mcp.json`, `.aws/amazonq/agents/*.json` |
| Kiro | `.kiro/settings/mcp.json` |
| OpenClaw | `.openclaw/skills/*`, `.openclaw/workspace/skills/*`, `.clawdbot/skills/*` |
| Shared | `.config/agents/skills/*` |

The list was cross-checked against the known clients in Snyk's
[agent-scan](https://github.com/snyk/agent-scan) (November 2026). VS Code's
`settings.json` can also hold MCP servers, but it mixes them with unrelated
settings; like `~/.claude.json` it needs a key-level parser first.

Project locations: `.claude/skills/*`, `.claude/agents`, `.claude/commands`,
`.claude/settings.json`, `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `CLAUDE.md`,
`AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules`, `.github/copilot-instructions.md`,
`.agents/skills/*`, `.cursor/skills/*`, `.gemini/skills/*`, `.amp/skills/*`, `.openclaw/skills/*`.

Agents move these between releases. Pull requests for new agents or locations are
welcome; add a test in `cmd/ammit/main_test.go`.

**Not scanned yet:** `~/.claude.json` holds Claude Code's MCP servers but also prompt
history, so it needs a parser that reads only the `mcpServers` key first. MCP servers
configured as `npx some-server` are scanned as configuration only: seeing their tool
descriptions means running them, which belongs in the sandbox.
