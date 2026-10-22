#!/usr/bin/env python3
"""Progress-metrics exporter for `cairn` (compute coordination node).

Sources:
  http://127.0.0.1:8080/{network,objectives,goals,checkpoint,progress/<id>}  the local node (launchd org.cairn.node)
  CHANGELOG.md                                                               released versions (committed)
Env: PM_CAIRN_URL overrides the node base URL. The node's log is encrypted, so there is no backfill:
history accrues from daily samples.
Run: python3 tools/progress_metrics.py
"""
# ---- progress-metrics exporter boilerplate (copied verbatim into each repo's tools/progress_metrics.py) ----
# Contract: print one JSON object per line to stdout. Fields: metric, value, date (YYYY-MM-DD),
# problem, unit, better (higher|lower|neutral), kind (gauge|event), label, source.
# Reads committed state at --ref via `git show`; never the working tree. stdlib only.
import argparse
import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(os.environ.get("PM_REPO_PATH") or Path(__file__).resolve().parents[1])
TODAY = dt.date.today().isoformat()


def _git(*args, check=True):
    p = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {p.stderr.strip()[:200]}")
    return p.stdout


def show(ref, path):
    p = subprocess.run(["git", "-C", str(REPO), "show", f"{ref}:{path}"], capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else None


def ls(ref, path=""):
    return [l for l in _git("ls-tree", "-r", "--name-only", ref, "--", path, check=False).splitlines() if l]


def file_history(ref, path, since):
    """Yield (date, commit, text) for the newest commit per day touching `path`, newest first."""
    out = _git("log", "--first-parent", ref, f"--since={since}", "--format=%H %cs", "--", path, check=False)
    seen = set()
    for line in out.splitlines():
        h, d = line.split()
        if d in seen:
            continue
        seen.add(d)
        txt = show(h, path)
        if txt is not None:
            yield d, h[:12], txt


def emit(metric, value, *, date=None, problem="misc", unit="", better="neutral", kind="gauge", label="", source=""):
    if value is None:
        return
    try:
        v = float(value)
    except (TypeError, ValueError):
        return
    if v != v:
        return
    print(json.dumps({"metric": metric, "value": v, "date": date or TODAY, "problem": problem, "unit": unit,
                      "better": better, "kind": kind, "label": label or metric, "source": source}))


def args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref", default=os.environ.get("PM_REF", "origin/main"))
    ap.add_argument("--since", default=os.environ.get("PM_SINCE") or (dt.date.today() - dt.timedelta(days=90)).isoformat())
    return ap.parse_args()
# ---- end boilerplate ----

import re
import urllib.request

P = "cairn-network"
BASE = os.environ.get("PM_CAIRN_URL", "http://127.0.0.1:8080").rstrip("/")


def get(path):
    try:
        with urllib.request.urlopen(f"{BASE}{path}", timeout=15) as r:
            return json.load(r)
    except Exception as e:  # noqa: BLE001
        print(f"cairn {path} unavailable: {e}", file=sys.stderr)
        return None


def node():
    net = get("/network")
    if net:
        c = net.get("compute") or {}
        emit("cairn.compute.live_workers", c.get("live"), problem=P, unit="count", better="higher",
             label="cairn: live workers", source=f"{BASE}/network")
        emit("cairn.compute.stale_workers", c.get("stale"), problem=P, unit="count", better="lower",
             label="cairn: stale workers", source=f"{BASE}/network")
        emit("cairn.compute.steps_per_second", c.get("steps_per_second"), problem=P, unit="steps/s", better="higher",
             label="cairn: aggregate reported steps/s", source=f"{BASE}/network")
        h = c.get("hosts") or {}
        emit("cairn.hosts.registered", h.get("registered"), problem=P, unit="count", better="higher",
             label="cairn: registered hosts", source=f"{BASE}/network")
        emit("cairn.hosts.live", h.get("live"), problem=P, unit="count", better="higher",
             label="cairn: live hosts", source=f"{BASE}/network")
        p = net.get("peers") or {}
        emit("cairn.peers.reached", p.get("reached"), problem=P, unit="count", better="higher",
             label="cairn: peers reached", source=f"{BASE}/network")
    objs = get("/objectives")
    if isinstance(objs, dict):
        objs = objs.get("objectives") or objs.get("items") or []
    if isinstance(objs, list):
        emit("cairn.objectives.total", len(objs), problem=P, unit="count", better="higher",
             label="cairn: objectives", source=f"{BASE}/objectives")
        emit("cairn.objectives.open", sum(1 for o in objs if o.get("open")), problem=P, unit="count",
             label="cairn: open objectives", source=f"{BASE}/objectives")
        emit("cairn.objectives.settled", sum(1 for o in objs if o.get("settled")), problem=P, unit="count",
             better="higher", label="cairn: settled objectives", source=f"{BASE}/objectives")
        for o in objs:
            oid = str(o.get("id", ""))
            if not oid:
                continue
            pr = get(f"/progress/{oid}")
            if not pr:
                continue
            key = re.sub(r"[^a-z0-9_-]", "", oid.split(":")[-1].lower())[:10]
            der = pr.get("derived") or {}
            fr = pr.get("frontier") or {}
            lab = (o.get("goal") or oid)[:56]
            emit(f"cairn.obj.{key}.claims_paid", der.get("claims_paid"), problem=P, unit="count", better="higher",
                 label=f"cairn {lab}: claims paid", source=f"{BASE}/progress/{oid}")
            emit(f"cairn.obj.{key}.frontier_score", fr.get("score"), problem=P, unit="score", better="higher",
                 label=f"cairn {lab}: frontier score", source=f"{BASE}/progress/{oid}")
            emit(f"cairn.obj.{key}.steps_last_day", (der.get("last_day") or {}).get("steps"), problem=P, unit="steps",
                 better="higher", label=f"cairn {lab}: steps in last day", source=f"{BASE}/progress/{oid}")
    ck = get("/checkpoint")
    if ck:
        emit("cairn.checkpoint.height", ck.get("height"), problem=P, unit="height", better="higher",
             label="cairn: checkpoint height", source=f"{BASE}/checkpoint")


def releases(ref):
    txt = show(ref, "CHANGELOG.md") or ""
    n = sum(1 for l in txt.splitlines() if l.startswith("## ["))
    emit("cairn.releases", n, problem=P, unit="count", better="higher", label="cairn: released versions in CHANGELOG",
         source="CHANGELOG.md")


def main():
    a = args()
    releases(a.ref)
    node()


if __name__ == "__main__":
    main()
