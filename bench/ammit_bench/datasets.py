"""Dataset lock, acquisition and materialization.

Everything here only reads and writes data. Samples are malicious by design:
nothing is executed, no link inside a sample is followed, and materialized
files are written read-only for the owner (0600).

Corpus layout produced for each dataset, inside the work directory:

    <work>/<slug>/samples/...       files ammit scans (or a git checkout)
    <work>/<slug>/labels.jsonl      one record per sample, outside "samples"

A label record:
    {"id", "dataset", "label": "malicious"|"benign", "path", "categories": [...],
     "source", "provenance", "splits": {"<protocol>": "<partition>"}}
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

LOCK_PATH = Path(__file__).resolve().parent.parent / "datasets.lock.json"


class DatasetError(Exception):
    pass


# ------------------------------------------------------------------- lock


def load_lock(path: Path | None = None) -> dict:
    with open(path or LOCK_PATH, encoding="utf-8") as f:
        lock = json.load(f)
    if lock.get("lock_version") != 1:
        raise DatasetError("unsupported lock_version")
    if lock.get("safety", {}).get("execute_samples") is not False:
        raise DatasetError("lock must set safety.execute_samples to false")
    ids = [d["id"] for d in lock["datasets"]]
    if len(ids) != len(set(ids)):
        raise DatasetError("duplicate dataset id in lock")
    return lock


def usable(dataset: dict) -> bool:
    """Pending or unpinned datasets are never used."""
    return dataset.get("status") != "pending" and bool(dataset.get("revision"))


def slug(dataset_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", dataset_id).strip("_")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------- acquisition


def fetch(dataset: dict, cache: Path, record_hashes: bool = False) -> Path:
    """Download a pinned dataset into cache and verify it. Returns its root."""
    if not usable(dataset):
        raise DatasetError(f"{dataset['id']} is pending or unpinned; refusing to fetch")
    if os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
        raise DatasetError("network fetch is not allowed in pull requests (lock safety policy)")
    root = cache / slug(dataset["id"])
    if dataset["provider"] == "git":
        _fetch_git(dataset, root)
    elif dataset["provider"] == "huggingface":
        _fetch_hf(dataset, root, record_hashes)
    else:
        raise DatasetError(f"unsupported provider {dataset['provider']}")
    return root


def _fetch_git(dataset: dict, root: Path) -> None:
    rev = dataset["revision"]
    if (root / ".git").exists():
        head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        if head == rev:
            return
        shutil.rmtree(root)
    root.mkdir(parents=True)
    git = ["git", "-C", str(root), "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false"]
    for args in (["init", "-q"], ["remote", "add", "origin", dataset["url"]],
                 ["fetch", "-q", "--depth", "1", "origin", rev], ["checkout", "-q", "FETCH_HEAD"]):
        subprocess.run(git + args, check=True)
    head = subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    if head != rev:
        raise DatasetError(f"{dataset['id']}: checked out {head}, lock pins {rev}")


def _fetch_hf(dataset: dict, root: Path, record_hashes: bool) -> None:
    try:
        from huggingface_hub import hf_hub_download
    except ImportError as exc:  # pragma: no cover
        raise DatasetError("pip install -r bench/requirements.txt to fetch Hugging Face datasets") from exc
    root.mkdir(parents=True, exist_ok=True)
    pinned = dataset.get("file_sha256", {})
    for name in dataset["files"]:
        local = Path(hf_hub_download(dataset["id"], name, repo_type="dataset", revision=dataset["revision"],
                                     local_dir=root))
        digest = sha256_file(local)
        if name in pinned:
            if pinned[name] != digest:
                raise DatasetError(f"{dataset['id']}/{name}: sha256 {digest} does not match the lock")
        elif record_hashes:
            pinned[name] = digest
        else:
            raise DatasetError(
                f"{dataset['id']}/{name} has no pinned sha256 (got {digest}). Review it, then rerun "
                "with --record-hashes and commit the updated lock.")
    dataset["file_sha256"] = pinned


# --------------------------------------------------------- materialization


def _write_sample(path: Path, text: str) -> None:
    if "\x00" in text:
        raise DatasetError(f"{path}: NUL byte in sample text")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def materialize_malicious_skill_bench(dataset: dict, root: Path, out: Path) -> list[dict]:
    """Write each MaliciousSkillBench sample as samples/<id>/SKILL.md."""
    import pyarrow.parquet as pq

    primary = pq.read_table(root / "primary.parquet").to_pylist()
    expected = dataset.get("expected", {})
    if expected.get("primary_rows") and len(primary) != expected["primary_rows"]:
        raise DatasetError(f"primary.parquet has {len(primary)} rows, lock expects {expected['primary_rows']}")

    splits: dict[str, dict[str, str]] = {}
    for protocol in expected.get("splits", {}):
        rows = pq.read_table(root / "splits" / f"{protocol}.parquet").to_pylist()
        splits[protocol] = {r["benchmark_id"]: r["split"] for r in rows}

    if out.exists():
        shutil.rmtree(out)
    records = []
    for row in primary:
        bid = row["benchmark_id"]
        if not isinstance(bid, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", bid) or bid in {".", ".."}:
            raise DatasetError(f"unsafe benchmark_id {bid!r}")
        label = {"1": "malicious", "0": "benign", 1: "malicious", 0: "benign"}.get(row["label"])
        if label is None:
            raise DatasetError(f"{bid}: unsupported label {row['label']!r}")
        text = row["skill_text"] if row.get("skill_text") is not None else row.get("public_skill_text")
        if not text:
            continue  # no readable text; counted in the report as missing
        _write_sample(out / "samples" / bid / "SKILL.md", text)
        records.append({
            "id": bid,
            "dataset": dataset["id"],
            "label": label,
            "path": f"samples/{bid}",
            "categories": sorted(set(row.get("attack_category_codes") or [])) if label == "malicious" else [],
            "source": row.get("source_id"),
            "provenance": row.get("provenance"),
            "splits": {p: m[bid] for p, m in splits.items() if bid in m},
        })
    _check_split_counts(dataset, records)
    _write_labels(out, records)
    return records


def _check_split_counts(dataset: dict, records: list[dict]) -> None:
    for protocol, parts in dataset.get("expected", {}).get("splits", {}).items():
        for partition, want in parts.items():
            got = [r for r in records if r["splits"].get(protocol) == partition]
            counts = {"total": len(got), "malicious": sum(r["label"] == "malicious" for r in got)}
            counts["benign"] = counts["total"] - counts["malicious"]
            for k, v in want.items():
                if counts[k] != v:
                    raise DatasetError(
                        f"{dataset['id']} {protocol}/{partition}: {k}={counts[k]}, lock expects {v}. "
                        "The population changed; refuse to score it.")


INSTRUCTION_SUFFIXES = (".instructions.md", ".agent.md", ".prompt.md")


def materialize_benign_git(dataset: dict, root: Path, out: Path) -> list[dict]:
    """Every skill folder (with SKILL.md) and instruction file in a checkout is one benign sample."""
    records = []
    seen = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        rel_dir = Path(dirpath).relative_to(root)
        if "SKILL.md" in filenames or "skill.md" in filenames:
            seen.add(rel_dir)
            records.append(_benign_record(dataset, root, rel_dir))
        for name in filenames:
            if name.lower().endswith(INSTRUCTION_SUFFIXES):
                records.append(_benign_record(dataset, root, rel_dir / name))
    # A skill nested inside another skill's folder is scanned as part of it too;
    # keep both, the outer one is what an installer would copy.
    out.mkdir(parents=True, exist_ok=True)
    _write_labels(out, records)
    return records


BENIGN_HOLDOUT = 0.3


def benign_partition(sample_id: str) -> str:
    """Stable 70/30 dev/holdout split by hash. The holdout is frozen like a test split."""
    h = int(hashlib.sha256(f"benign-split:{sample_id}".encode()).hexdigest()[:8], 16)
    return "holdout" if h / 0xFFFFFFFF < BENIGN_HOLDOUT else "dev"


def _benign_record(dataset: dict, root: Path, rel: Path) -> dict:
    sid = f"{dataset['id'].split(':', 1)[1]}:{rel.as_posix()}"
    return {
        "id": sid,
        "dataset": dataset["id"],
        "label": "benign",
        "path": str(root / rel),
        "categories": [],
        "source": dataset["id"],
        "provenance": "published",
        "splits": {"benign": benign_partition(sid)},
    }


def _write_labels(out: Path, records: list[dict]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "labels.jsonl", "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, sort_keys=True) + "\n")


def load_labels(out: Path) -> list[dict]:
    with open(out / "labels.jsonl", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def materialize(dataset: dict, root: Path, out: Path) -> list[dict]:
    if dataset["provider"] == "git":
        return materialize_benign_git(dataset, root, out)
    if dataset["id"] == "ProtectSkills/MaliciousSkillBench":
        return materialize_malicious_skill_bench(dataset, root, out)
    raise DatasetError(f"no adapter for {dataset['id']}")


def population_digest(records: list[dict]) -> str:
    """Hash of the sorted sample ids and labels: proves which population was scored."""
    h = hashlib.sha256()
    for r in sorted(records, key=lambda r: r["id"]):
        h.update(f"{r['id']}\t{r['label']}\n".encode())
    return h.hexdigest()
