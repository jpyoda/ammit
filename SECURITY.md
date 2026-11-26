# Security policy

## Reporting

Please report vulnerabilities in ammit, and **scanner bypasses** (a malicious add-on
that ammit misses), privately through GitHub's
[private vulnerability reporting](https://github.com/jpyoda/ammit/security/advisories/new).
Don't open public issues for them.

Include a minimal, inert reproduction where possible (use `.invalid` domains).
We aim to respond within 7 days. Accepted bypasses get a regression test and
credit in the release notes unless you prefer otherwise.

## Scope

In scope: bypasses of detection, crashes or hangs caused by crafted input, path
traversal or code execution during scanning, and leaks of secrets into reports.

ammit is a detection aid, not a guarantee. A finding we don't detect yet is a bug
we want to know about, not a broken promise.
