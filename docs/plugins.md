# Analyzer plugins

A plugin is any executable that speaks one JSON-RPC 2.0 exchange over stdin and
stdout. Use it to add analysis in any language without changing ammit's Go code.

```sh
ammit scan --plugin "python3 examples/plugins/hello_plugin.py" ./my-skill
```

ammit writes one request:

```json
{"jsonrpc": "2.0", "id": 1, "method": "analyze",
 "params": {"artifact": { "schema_version": "1", "name": "...", "kind": "skill",
   "files": [{"path": "SKILL.md", "kind": "markdown", "text": "...", "derived": false, "parent": ""}],
   "references": [{"type": "url", "value": "https://...", "file": "SKILL.md", "line": 4}] }}}
```

and expects one response:

```json
{"jsonrpc": "2.0", "id": 1, "result": {"findings": [
  {"rule_id": "MY-001", "title": "...", "severity": "medium", "category": "...",
   "message": "...", "file": "SKILL.md", "line": 4, "evidence": "...", "confidence": 0.7}]}}
```

* Files arrive **normalized** (see [rules.md](rules.md)). `derived: true` marks content the
  normalizer produced, such as decoded base64; `parent` points at its source.
* Return `{"error": {"code": ..., "message": ...}}` on failure. Errors, crashes, invalid JSON and
  timeouts (`--plugin-timeout`, default 2 minutes) make the scan's verdict `review`, never clean.
* Output is capped at 16 MiB.
* A plugin runs with ammit's own permissions. Keep dependencies minimal and pinned.

## LLM plugins and prompt injection

The content you send to a model is written by a potential attacker. Keep it
separate from your instructions, tell the model it is data, never let the
model's output change the verdict without a check, and consider a second model
reviewing the first one's reasoning. A planned official LLM judge plugin will
follow these rules.
