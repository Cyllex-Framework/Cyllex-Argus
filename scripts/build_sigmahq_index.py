#!/usr/bin/env python3
"""Build the bundled SigmaHQ technique index that `detections/sigma.py` references.

For every MITRE ATT&CK technique, the index records how many SigmaHQ rules carry its
`attack.t<id>` tag and a capped sample of them (title + repo path), pinned to a specific SigmaHQ
commit so the links never rot. Argus references the community's vetted detections instead of
inventing its own; this is the data behind that.

Usage:
    python scripts/build_sigmahq_index.py                 # shallow-clone SigmaHQ and build
    python scripts/build_sigmahq_index.py --src <dir>     # use an existing SigmaHQ checkout
    python scripts/build_sigmahq_index.py --cap 8         # rules stored per technique (default 8)

Output: src/cyllex_argus/detections/sigmahq_index.json
"""
from __future__ import annotations

import argparse
import datetime
import glob
import json
import os
import re
import subprocess
import tempfile

REPO = "https://github.com/SigmaHQ/sigma.git"
RULE_DIRS = ["rules", "rules-threat-hunting", "rules-emerging-threats", "rules-dfir", "rules-compliance"]
_TAG = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)\b", re.I)
_TITLE = re.compile(r"^title:\s*(.+?)\s*$", re.M)
_HERE = os.path.dirname(os.path.abspath(__file__))
_OUT = os.path.join(_HERE, "..", "src", "cyllex_argus", "detections", "sigmahq_index.json")


def _git(cwd: str, *args: str) -> str:
    return subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True, encoding="utf-8").stdout


def _clone(dest: str) -> str:
    """Shallow-clone SigmaHQ and check out only the rule trees. A few rules with very long paths
    fail to materialise on Windows (MAX_PATH); that is a handful out of thousands and is ignored."""
    subprocess.run(["git", "clone", "--depth", "1", "--single-branch", REPO, dest], check=True)
    subprocess.run(["git", "-C", dest, "checkout", "HEAD", "--", *RULE_DIRS])  # tolerate long-path failures
    return _git(dest, "rev-parse", "HEAD").strip()


def build(src: str, commit: str, cap: int) -> dict:
    index: dict[str, list[dict]] = {}
    files: list[str] = []
    for d in RULE_DIRS:
        files += glob.glob(os.path.join(src, d, "**", "*.yml"), recursive=True)
    for path in files:
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        techniques = {g.upper() for g in _TAG.findall(text)}
        if not techniques:
            continue
        m = _TITLE.search(text)
        title = (m.group(1).strip().strip("'\"") if m else os.path.basename(path))[:120]
        rel = os.path.relpath(path, src).replace("\\", "/")
        for tid in techniques:
            index.setdefault(tid, []).append({"t": title, "p": rel})

    techniques = {}
    for tid, rules in sorted(index.items()):
        rules.sort(key=lambda r: r["t"])
        techniques[tid] = {"n": len(rules), "r": rules[:cap]}
    return {
        "source": "SigmaHQ/sigma",
        "commit": commit,
        "generated": datetime.date.today().isoformat(),
        "cap": cap,
        "techniques": techniques,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", help="existing SigmaHQ checkout; omit to shallow-clone a fresh one")
    ap.add_argument("--cap", type=int, default=8, help="rules stored per technique (default 8)")
    args = ap.parse_args()

    tmp = None
    try:
        if args.src:
            src = args.src
            commit = _git(src, "rev-parse", "HEAD").strip() or "unknown"
        else:
            tmp = tempfile.mkdtemp(prefix="sigmahq-")
            src = os.path.join(tmp, "sigma")
            commit = _clone(src)
        data = build(src, commit, args.cap)
    finally:
        pass  # a temp clone is left for the OS to reap; deleting a git tree on Windows is flaky

    out = os.path.abspath(_OUT)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(data, fh, separators=(",", ":"), ensure_ascii=False)
    pairs = sum(t["n"] for t in data["techniques"].values())
    print(f"commit {data['commit'][:12]} | techniques {len(data['techniques'])} | rule-technique tags {pairs}")
    print(f"wrote {out} ({round(os.path.getsize(out) / 1024, 1)} KB, cap {args.cap})")


if __name__ == "__main__":
    main()
