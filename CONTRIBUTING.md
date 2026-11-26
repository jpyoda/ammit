# Contributing

Thanks for helping. A few rules keep a security tool trustworthy:

1. **Every detection change has a test.** New rules need a positive fixture in
   `testdata/fixtures/` or a generated case in `internal/scan/scan_test.go`.
   Bypass fixes go in the bypass section of that file.
2. **Fixtures are inert.** Use `.invalid` domains and private IPs; never commit
   working malware or live infrastructure.
3. **Check false positives.** Run new rules against real, benign add-ons and say in
   the pull request what you scanned and what it flagged.
4. **No new dependencies in the core.** Plugins can use whatever they need.
5. **Fail closed.** Code paths that can't finish analysis must produce a finding
   or an error, never an empty result.

```sh
make lint test       # gofmt, vet, tests with the race detector
make fixtures        # see each fixture's verdict
```

Rule format: [docs/rules.md](docs/rules.md). Plugin protocol: [docs/plugins.md](docs/plugins.md).
