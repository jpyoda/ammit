#!/usr/bin/env python3
"""Minimal ammit analyzer plugin.

ammit sends one JSON-RPC request on stdin and reads one response on stdout.
Run it with:  ammit scan --plugin "python3 examples/plugins/hello_plugin.py" ./my-skill

This example flags skills whose description is missing, the kind of check a
plugin can add without touching ammit's Go code. Use the standard library
only, or pin dependencies: a plugin runs with the same rights as ammit.
"""
import json
import sys


def analyze(artifact):
    findings = []
    for f in artifact.get("files", []):
        if f["path"].lower().endswith("skill.md") and "description:" not in f.get("text", ""):
            findings.append({
                "rule_id": "EXAMPLE-001",
                "title": "Skill has no description",
                "severity": "low",
                "category": "quality",
                "message": "Agents choose skills by description; a missing one is unusual.",
                "file": f["path"],
                "confidence": 0.9,
            })
    return findings


def main():
    request = json.load(sys.stdin)
    if request.get("method") != "analyze":
        reply = {"jsonrpc": "2.0", "id": request.get("id"), "error": {"code": -32601, "message": "unknown method"}}
    else:
        reply = {"jsonrpc": "2.0", "id": request.get("id"),
                 "result": {"findings": analyze(request["params"]["artifact"])}}
    json.dump(reply, sys.stdout)


if __name__ == "__main__":
    main()
