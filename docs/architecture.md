# Architecture

ammit is a small Go core shipped as one binary, with analyzers that can run
out of process, and (planned) a sandbox that runs as its own service.

```
 entry points          core pipeline                                        outputs
 ------------          -------------                                        -------
 CLI          \
 CI action     \      collectors -> normalizer -> analyzers -> correlate  -> text, JSON, SARIF
 pre-install   ----->  (plugins)    (Skill IR)   (parallel)    & policy      webhooks (planned)
 server/API    /                        |            |
 laptop scan  /                         v            v
                                      store  <-->  sandbox service (Tartarus, planned)
                                        |
                                 watch scheduler (Muninn, planned): re-scan on change
```

## Principles

1. **One representation.** Every add-on becomes an `ir.Artifact` before analysis
   (`internal/ir`). The normalizer undoes packaging and encoding once, for every
   analyzer. Plugins receive the same IR as JSON. `ammit scan --dump-ir` shows it.
2. **Read, never run.** The scanner core never executes add-on code and never
   starts an MCP server, including during `discover`. Anything that must run
   goes to the sandbox service.
3. **Fail closed.** An analyzer error, a panic, a size limit or an unreadable
   archive makes the result `review`. A scan that did not finish never looks clean.
4. **No "safe".** Verdicts are `block`, `review` and `no-findings`.
5. **Content addressed.** The artifact hash covers every file's path and hash,
   so two copies of the same add-on hash the same and any change is visible.
   The watch loop will use this to re-scan only what changed.
6. **No third-party dependencies** in the core. A security tool's own supply
   chain is part of its attack surface.

## Packages

| Package | Role |
|---|---|
| `cmd/ammit` | CLI: `scan`, `discover`, `rules`, `version` |
| `internal/ir` | The intermediate representation |
| `internal/collect` | Reads files and archives from disk with limits; classifies files |
| `internal/normalize` | Expands archives and documents; strips invisible Unicode; decodes base64; extracts strings from bytecode and binaries; records notes |
| `internal/refs` | Extracts URLs, repositories and packages |
| `internal/analyzer` | Analyzer interface, parallel runner, structural and reference analyzers, plugin protocol |
| `internal/rules` | JSON rule engine (RE2, linear time) |
| `internal/report` | Deduplication, verdicts, text/JSON/SARIF |
| `internal/discover` | Finds installed add-ons at known locations |
| `internal/scan` | Wires the pipeline; bypass regression tests |
| `rules/` | Default rule pack, embedded into the binary |

## The sandbox (planned): layers, inside out

1. Throwaway Firecracker/Kata/gVisor microVM per run; no host mounts; non-root; resource caps.
2. No real internet: all egress through a logging proxy that returns fake responses; metadata endpoint and SMTP blocked.
3. No real secrets inside: the agent's model calls go through a proxy outside the VM that adds the API key and caps spend; only bait credentials inside.
4. Observation from outside the VM (eBPF), streamed out live.
5. Isolated infrastructure: separate cloud account, no IAM role, nothing shared with CI.
6. Results treated as hostile: logs can carry prompt injection aimed at the model that writes the report.

The open-source default will refuse to run add-ons without a microVM backend;
a plain Docker backend will exist for development only, behind an `--unsafe` flag.
