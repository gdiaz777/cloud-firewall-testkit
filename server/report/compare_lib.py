"""Shared helpers for the comparison report (Python side)."""
import json

RANK = {"FAIL": 4, "ERROR": 4, "OK": 3, "INFO": 2, "SKIP": 1}


def load_runs(paths):
    runs = [json.load(open(p, encoding="utf-8")) for p in paths]
    for r in runs:
        r.setdefault("solution", (r.get("config", {}).get("solution") or {}).get("name") or r["id"])
    return runs


def per_check(run):
    """Status per check id across every client: a failure on any client wins, then OK, INFO, N/A."""
    st = {}
    for a in run["agents"].values():
        for x in a["results"]:
            if RANK[x["status"]] > RANK.get(st.get(x["id"]), 0):
                st[x["id"]] = x["status"]
    return st
