# Writing rules

Rules live in JSON packs. The defaults are in [`rules/default.json`](../rules/default.json)
and are embedded into the binary. Load your own with `ammit scan --rules ./my-rules`;
a rule with the same `id` as a default replaces it, so you can tune or disable defaults.

```json
{
  "name": "my-org",
  "rules": [
    {
      "id": "AMT-ORG-001",
      "title": "Internal hostname in add-on",
      "severity": "medium",
      "category": "data-exposure",
      "description": "Add-ons should not reference internal hosts.",
      "remediation": "Use the public endpoint.",
      "file_kinds": ["markdown", "script", "config", "text"],
      "patterns": ["\\b[a-z0-9-]+\\.corp\\.example\\.com\\b"],
      "exclude_patterns": ["docs\\.corp\\.example\\.com"],
      "match": "any",
      "confidence": 0.6
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `id` | Unique. Defaults use `AMT-<CATEGORY>-<NNN>`. |
| `severity` | `info`, `low`, `medium`, `high`, `critical`. High and critical make the verdict `block`. |
| `file_kinds` | Limit to `markdown`, `script`, `config`, `text`. Empty means all text, including content the normalizer decoded. |
| `patterns` | Go [RE2](https://github.com/google/re2/wiki/Syntax) expressions. RE2 runs in linear time, so a hostile file cannot make a rule hang. It has no lookahead or backreferences: use `exclude_patterns` instead. |
| `exclude_patterns` | Drop a match when its line also matches one of these. |
| `match` | `any` (default): report each matching line. `all`: every pattern must match somewhere in the same file. |
| `case_sensitive` | Matching is case-insensitive unless this is `true`. |
| `confidence` | 0 to 1, how often a match is a real problem. |
| `context_sensitive` | The rule matches wording that is harmless when only mentioned. On the `docs`, `tests` and `comments` surfaces its findings drop one severity step, and the report says so. Never set it on execution, exfiltration or evasion rules. |

Rules run on **normalized** text: invisible characters are already removed, archive
members and documents are already unpacked, and base64 blobs are already decoded into
extra files. You don't need to handle those in patterns.

## Surfaces and verdicts

Every finding is labeled with the surface it sits on: `code`, `instructions` (SKILL.md,
agent and instruction files, and any other markdown an agent may load), `config`,
`docs` (README, LICENSE, a `docs/` folder), `tests` (`tests/`, `evals/`, `fixtures/`,
`test_*.py` and similar) or `comments` (a comment line in code). Labels never hide a
finding.

Verdicts: `block` (high or critical), `review` (medium, or an incomplete scan), `notes`
(only low or info findings), `no-findings`.

## Built-in structural checks

These are not pattern rules; they come from what the normalizer observed
(`internal/analyzer/structural.go`): whitespace inflation (`AMT-EVADE-001`), Unicode tag
smuggling (`-002`), bidi controls (`-003`), zero-width characters (`-004`),
encrypted archives (`-005`), bytecode without source (`-006`), encoded blobs (`-007`),
bundled executables (`AMT-EXEC-010`), hidden markdown comments (`AMT-INJECT-010`),
symlinks (`AMT-FS-001`) and incomplete analysis (`AMT-LIMIT-*`).

## Testing a rule

Every new rule needs a positive fixture (a case it must catch) and should be run
against benign add-ons to check false positives. Fixtures must be inert: use `.invalid`
domains and private addresses. Run `make fixtures` to see every fixture's verdict.
