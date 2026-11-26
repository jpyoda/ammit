"""Run ammit over a population of samples and collect one verdict per sample."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

CHUNK = 100


class RunError(Exception):
    pass


def ammit_identity(ammit: str) -> dict:
    """Version and rule-pack hash, recorded with every result."""
    version = subprocess.run([ammit, "version"], capture_output=True, text=True, check=True).stdout.strip()
    rules = subprocess.run([ammit, "rules", "--json"], capture_output=True, check=True).stdout
    return {"version": version, "rules_sha256": hashlib.sha256(rules).hexdigest()}


def _scan(ammit: str, paths: list[str], extra: list[str]) -> list[dict]:
    proc = subprocess.run([ammit, "scan", "--format", "json", "--fail-on", "none", "--color", "never", *extra, *paths],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise RunError(proc.stderr.strip() or f"exit {proc.returncode}")
    data = json.loads(proc.stdout)
    return data if isinstance(data, list) else [data]


def scan_population(ammit: str, records: list[dict], base: Path, extra: list[str] | None = None,
                    progress=None) -> dict[str, dict]:
    """Return {sample id: {"verdict", "findings": [rule ids], "error"?}}.

    Paths are scanned in chunks; a chunk that fails is retried one path at a
    time so a single unreadable sample doesn't sink the run. A sample whose
    scan fails gets verdict "error".
    """
    extra = extra or []
    by_path: dict[str, dict] = {}
    for r in records:
        p = Path(r["path"])
        full = str((p if p.is_absolute() else base / p).resolve())
        by_path[full] = r
    paths = list(by_path)
    results: dict[str, dict] = {}

    def record(report: dict) -> None:
        root = str(Path(report["artifact"]["root"]).resolve())
        sample = by_path.get(root)
        if sample is None:
            raise RunError(f"ammit reported an unknown root {root}")
        results[sample["id"]] = {
            "verdict": report["verdict"],
            "findings": sorted({f["rule_id"] for f in report.get("findings", [])}),
            "analysis_errors": report.get("errors") or [],
        }

    for i in range(0, len(paths), CHUNK):
        chunk = paths[i:i + CHUNK]
        try:
            for rep in _scan(ammit, chunk, extra):
                record(rep)
        except (RunError, json.JSONDecodeError):
            for p in chunk:
                try:
                    for rep in _scan(ammit, [p], extra):
                        record(rep)
                except (RunError, json.JSONDecodeError) as exc:
                    results[by_path[p]["id"]] = {"verdict": "error", "findings": [], "error": str(exc)[:300]}
        if progress:
            progress(min(i + CHUNK, len(paths)), len(paths))
    missing = [by_path[p]["id"] for p in paths if by_path[p]["id"] not in results]
    for sid in missing:
        results[sid] = {"verdict": "error", "findings": [], "error": "no report returned"}
    return results


def find_ammit(explicit: str | None) -> str:
    if explicit:
        return explicit
    for cand in ("bin/ammit", "ammit"):
        if os.path.sep in cand and Path(cand).exists():
            return str(Path(cand).resolve())
    from shutil import which
    found = which("ammit")
    if not found:
        raise RunError("ammit not found: run `make build` or pass --ammit")
    return found
