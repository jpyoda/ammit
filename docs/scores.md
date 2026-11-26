# Scores

How well ammit detects malicious add-ons and how often it flags harmless ones,
measured by the [benchmark harness](../bench/README.md). Every rate carries a 95%
Wilson interval. *Flagged* means a `block` or `review` verdict; *blocked* means
`block` only. Raw results are in [`scores/`](scores/).

## 2026-11-26: false-positive tuning (static rules)

Tuned on the benign **dev** partition only, then the frozen **holdout** was scored
once to confirm. The changes: findings now carry a surface label (code, instructions,
config, docs, tests, comments); rules marked `context_sensitive` drop one severity step
when they match only in docs, tests or comments; results with only low or info findings
get the new `notes` verdict instead of `review`; and a handful of patterns were
tightened (details in the pull request). Execution, exfiltration and evasion rules are
never demoted.

| Benign partition | Samples | Blocked: before → after | Flagged: before → after |
| --- | --- | --- | --- |
| dev | 1,318 | 9.6% → **2.1%** (1.5–3.1) | 38.6% → **6.6%** (5.4–8.1) |
| holdout | 555 | 8.6% → **2.3%** (1.4–4.0) | 37.3% → **6.3%** (4.6–8.6) |

The holdout moved as much as the dev partition, so the fixes generalize rather than
fitting the samples they were tuned on.

What still blocks benign add-ons, mostly: `curl ... | sh` installers inside legitimate
skills (`AMT-EXEC-001`). That pattern is risky wherever it appears, so it stays
critical; the LLM judge and repository context are the next tools for this.

**Not yet measured: recall.** Tuning can cost detection. Every bypass and fixture test
still passes, but the MaliciousSkillBench validation run is what confirms recall held.

## 2026-11-26: baseline, milestone 1 (static rules only, before any tuning)

### Benign corpus: false-positive rate

1,873 published skills and instruction files from seven repositories, each pinned
to a commit (see [`bench/datasets.lock.json`](../bench/datasets.lock.json)). The
corpus is split 70/30 by hash; the 30% holdout is frozen and scored only at milestones.

| Partition | Samples | Blocked | Flagged |
| --- | --- | --- | --- |
| dev | 1,318 | 9.6% (8.1–11.3) | 38.6% (36.0–41.3) |
| holdout | 555 | 8.6% (6.6–11.3) | 37.3% (33.4–41.4) |

Flagged rate by repository (dev partition):

| Repository | Samples | Flagged | Blocked |
| --- | --- | --- | --- |
| NVIDIA/skills | 456 | 410 | 80 |
| github/awesome-copilot | 632 | 69 | 28 |
| microsoft/skills | 158 | 20 | 10 |
| openai/skills | 35 | 4 | 3 |
| anthropics/skills | 15 | 1 | 1 |
| huggingface/skills | 15 | 5 | 4 |
| vercel-labs/agent-skills | 7 | 0 | 0 |

Rules behind most false positives (dev): `AMT-EVADE-007` encoded text (397 samples,
mostly signature files such as `skill.oms.sig`), `AMT-INJECT-010` hidden markdown
comments (101), `AMT-INJECT-003` oversight wording (64), `AMT-CRED-001` credential
paths (30). This is far above the phase 2 target of at most 2% blocked, and the first
thing tuning addresses.

### MaliciousSkillBench: recall

Not yet scored. The dataset is fetched from Hugging Face by the
[`bench` workflow](../.github/workflows/bench.yml); its file hashes must be pinned on a
first `record_hashes` run before scores count.
