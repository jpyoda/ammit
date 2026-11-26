"""ammit benchmark harness.

    python -m ammit_bench fetch                      # download pinned datasets
    python -m ammit_bench run --out results.json     # score the development population
    python -m ammit_bench run --milestone ...        # include frozen test partitions
    python -m ammit_bench report results.json        # markdown summary

Run from the bench/ directory (or set PYTHONPATH=bench).
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

from . import datasets as ds
from .metrics import Scorecard
from .report import markdown
from .runner import ammit_identity, find_ammit, scan_population


def _selected(lock: dict, ids: list[str] | None) -> list[dict]:
    out = []
    for d in lock["datasets"]:
        if ids and d["id"] not in ids:
            continue
        if not ds.usable(d):
            if ids:
                print(f"skip {d['id']}: {d.get('status', 'unpinned')}", file=sys.stderr)
            continue
        out.append(d)
    if not out:
        sys.exit("no usable datasets selected")
    return out


def cmd_fetch(args) -> int:
    lock = ds.load_lock()
    for d in _selected(lock, args.dataset):
        root = ds.fetch(d, Path(args.cache), record_hashes=args.record_hashes)
        print(f"{d['id']}: {root}")
    if args.record_hashes:
        with open(ds.LOCK_PATH, "w", encoding="utf-8") as f:
            json.dump(lock, f, indent=2)
            f.write("\n")
        print(f"updated {ds.LOCK_PATH}; review and commit the new hashes")
    return 0


def _in_sample(sample_id: str, fraction: float, seed: str) -> bool:
    if fraction >= 1:
        return True
    h = int(hashlib.sha256(f"{seed}:{sample_id}".encode()).hexdigest()[:8], 16)
    return h / 0xFFFFFFFF < fraction


def cmd_run(args) -> int:
    lock = ds.load_lock()
    ammit = find_ammit(args.ammit)
    identity = ammit_identity(ammit)
    cache, work = Path(args.cache), Path(args.work)
    card = Scorecard()
    meta, fp_rules, misses = [], collections.Counter(), collections.Counter()
    false_positives, errors = [], []

    for d in _selected(lock, args.dataset):
        root = cache / ds.slug(d["id"])
        if not root.exists() or args.refetch:
            root = ds.fetch(d, cache)
        out = work / ds.slug(d["id"])
        records = ds.materialize(d, root, out)

        # Split selection. Frozen partitions are only scored at milestones.
        if d["provider"] == "git":
            frozen = {"benign": "holdout"}
            protocol, partition = "benign", args.benign_partition
        else:
            frozen = d.get("frozen_partitions", {})
            protocol, partition = args.split, args.partition
        if frozen.get(protocol) == partition and not args.milestone:
            sys.exit(f"{d['id']}: {protocol}/{partition} is frozen; pass --milestone to score it")
        records = [r for r in records if r["splits"].get(protocol) == partition]
        records = [r for r in records if _in_sample(r["id"], args.sample, args.seed)]
        print(f"{d['id']}: scanning {len(records)} samples", file=sys.stderr)

        def progress(done, total, name=d["id"]):
            print(f"  {name}: {done}/{total}", file=sys.stderr)

        results = scan_population(ammit, records, out, args.extra_args.split() if args.extra_args else None, progress)
        for r in records:
            res = results[r["id"]]
            if res["verdict"] == "error":
                errors.append({"id": r["id"], "error": res.get("error")})
                card.errors.append(r["id"])
                continue
            card.add(r, res["verdict"])
            if r["label"] == "benign" and res["verdict"] != "no-findings":
                fp_rules.update(res["findings"])
                false_positives.append({"id": r["id"], "verdict": res["verdict"], "rules": res["findings"]})
            if r["label"] == "malicious" and res["verdict"] == "no-findings":
                misses.update(r["categories"] or ["uncategorized"])
        meta.append({
            "id": d["id"], "revision": d["revision"], "samples": len(records),
            "population_sha256": ds.population_digest(records),
            "selection": {"split": "benign", "partition": args.benign_partition} if d["provider"] == "git"
            else {"split": args.split, "partition": args.partition},
        })

    result = {
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "ammit": identity,
        "scan_args": args.extra_args or "",
        "sample_fraction": args.sample,
        "milestone": args.milestone,
        "datasets": meta,
        "scorecard": card.as_dict(),
        "false_positive_rules": fp_rules.most_common(),
        "false_positives": sorted(false_positives, key=lambda x: x["id"])[:200],
        "missed_categories": misses.most_common(),
        "errors": errors,
    }
    text = json.dumps(result, indent=2, sort_keys=False)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    print(markdown(result), file=sys.stderr)
    if errors and not args.allow_errors:
        print(f"{len(errors)} samples failed to scan; failing the run (use --allow-errors to report only)",
              file=sys.stderr)
        return 1
    return 0


def cmd_report(args) -> int:
    result = json.loads(Path(args.results).read_text(encoding="utf-8"))
    print(markdown(result))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ammit_bench", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch", help="download pinned datasets into the cache")
    f.add_argument("--dataset", action="append", help="dataset id (repeatable; default: all usable)")
    f.add_argument("--cache", default=".bench-cache")
    f.add_argument("--record-hashes", action="store_true", help="pin sha256 of newly downloaded files in the lock")
    f.set_defaults(fn=cmd_fetch)

    r = sub.add_parser("run", help="score ammit on the selected population")
    r.add_argument("--dataset", action="append")
    r.add_argument("--cache", default=".bench-cache")
    r.add_argument("--work", default=".bench-work")
    r.add_argument("--refetch", action="store_true")
    r.add_argument("--ammit", help="path to the ammit binary (default: bin/ammit or PATH)")
    r.add_argument("--extra-args", default="", help="extra arguments for `ammit scan`, e.g. \"--judge\"")
    r.add_argument("--split", default="source_disjoint")
    r.add_argument("--partition", default="validation", help="train, validation or test")
    r.add_argument("--benign-partition", default="dev", help="dev or holdout (frozen) for benign corpora")
    r.add_argument("--milestone", action="store_true", help="allow scoring frozen test partitions")
    r.add_argument("--sample", type=float, default=1.0, help="fraction of samples to score, chosen by hash")
    r.add_argument("--seed", default="ammit")
    r.add_argument("--out")
    r.add_argument("--allow-errors", action="store_true")
    r.set_defaults(fn=cmd_run)

    rp = sub.add_parser("report", help="markdown summary of a results file")
    rp.add_argument("results")
    rp.set_defaults(fn=cmd_report)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
