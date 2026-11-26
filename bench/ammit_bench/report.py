"""Markdown summary of a results file."""

from __future__ import annotations


def _pct(rate: dict) -> str:
    if rate["value"] is None:
        return "n/a"
    lo, hi = rate["ci95"]
    return f"{rate['value'] * 100:.1f}% ({lo * 100:.1f}–{hi * 100:.1f})"


def markdown(result: dict) -> str:
    sc = result["scorecard"]
    lines = [
        f"## ammit benchmark — {result['created_at']}",
        "",
        f"ammit `{result['ammit']['version']}`, rules `{result['ammit']['rules_sha256'][:12]}`"
        + (f", scan args `{result['scan_args']}`" if result.get("scan_args") else "")
        + (f", {result['sample_fraction'] * 100:g}% sample" if result.get("sample_fraction", 1) < 1 else ""),
        "",
        "| Dataset | Revision | Samples | Selection | Population |",
        "| --- | --- | --- | --- | --- |",
    ]
    for d in result["datasets"]:
        sel = d["selection"]
        sel_s = f"{sel['split']}/{sel['partition']}" if sel else "all"
        lines.append(f"| {d['id']} | `{d['revision'][:12]}` | {d['samples']} | {sel_s} | `{d['population_sha256'][:12]}` |")
    lines += [
        "",
        "Rates with 95% Wilson intervals. *Flagged* = block or review; *blocked* = block only.",
        "",
        "| Threshold | Recall | False-positive rate | Precision | TP / FN / FP / TN |",
        "| --- | --- | --- | --- | --- |",
    ]
    for t, c in sc["overall"].items():
        lines.append(f"| {t} | {_pct(c['recall'])} | {_pct(c['false_positive_rate'])} | {_pct(c['precision'])} "
                     f"| {c['tp']} / {c['fn']} / {c['fp']} / {c['tn']} |")

    for name, title in (("dataset", "By dataset"), ("category", "Recall by attack category"),
                        ("provenance", "By provenance")):
        groups = sc["groups"].get(name)
        if not groups:
            continue
        lines += ["", f"### {title}", "", "| Group | Recall (flagged) | FPR (flagged) | Recall (blocked) |", "| --- | --- | --- | --- |"]
        for value, by_t in groups.items():
            f, b = by_t["flagged"], by_t["blocked"]
            lines.append(f"| {value} | {_pct(f['recall'])} | {_pct(f['false_positive_rate'])} | {_pct(b['recall'])} |")

    if result.get("false_positive_rules"):
        lines += ["", "### Rules present in flagged benign samples", "", "| Rule | Benign samples flagged |", "| --- | --- |"]
        for rule, n in result["false_positive_rules"][:15]:
            lines.append(f"| {rule} | {n} |")
    if result.get("errors"):
        lines += ["", f"**{len(result['errors'])} samples failed to scan** and are excluded from the rates above."]
    return "\n".join(lines) + "\n"
