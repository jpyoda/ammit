# Benchmark harness

Scores ammit on pinned public datasets: recall on malicious add-ons, false-positive
rate on benign ones, each with a 95% Wilson interval. Results live in
[`docs/scores.md`](../docs/scores.md).

This is developer tooling in Python (it reads Parquet). The `ammit` binary itself
stays free of dependencies.

```sh
pip install -r bench/requirements.txt
make build                       # or: go build -o bin/ammit ./cmd/ammit
cd bench
python -m ammit_bench fetch      # download pinned datasets into .bench-cache/
python -m ammit_bench run --out results.json
python -m ammit_bench report results.json
python -m unittest discover -s tests
```

## Datasets

[`datasets.lock.json`](datasets.lock.json) pins every dataset to an exact revision
and, for downloaded files, a SHA-256. Pending or unpinned datasets are never used.

| Dataset | Role | Status |
| --- | --- | --- |
| ProtectSkills/MaliciousSkillBench | Primary: recall on the source-disjoint test split (1,384 samples), the split Cisco's scanner gates on | Revision pinned; file hashes pinned on first run |
| Seven published skill repositories | Benign corpus: false-positive rate | Pinned to commits |
| SkillTrustBench, MalSkillBench | Secondary | Pending: revision and adapter needed |

## Rules that keep the numbers honest

- **Frozen partitions.** MaliciousSkillBench's `source_disjoint/test` and the benign
  `holdout` (30% of the benign corpus, chosen by hash) are only scored with
  `--milestone`. Tune on `validation` and `dev`.
- **Population checks.** Sample counts must match the lock, and every result records a
  hash of the sample population, the ammit version and the rule-pack hash.
- **Errors count.** A sample that fails to scan fails the run unless `--allow-errors`.
- **Samples are inert.** They are written read-only (0600) outside the repo, never
  executed, and no link inside them is followed. The harness refuses to download in
  pull requests.

Dataset pins for MaliciousSkillBench follow the work in Cisco's
[skill-scanner evals](https://github.com/cisco-ai-defense/skill-scanner/tree/main/evals)
(Apache-2.0).
