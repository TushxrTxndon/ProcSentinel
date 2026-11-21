#!/usr/bin/env python3
"""Runs the planned test cases (synopsis Table 3.2) against a running ProcSentinel
and reports detection rate, time to detection per layer, false positives and
collector overhead. Usage: python3 scripts/evaluate.py [--reps 3] [--idle 120]"""
import argparse
import json
import statistics
import time
import urllib.request

EXPECT = {
    "cpu_hog": "cpu_hog", "cpu_hog_late": "cpu_hog", "mem_leak": "memory_leak", "fork_bomb": "fork_bomb",
    "zombie": "zombie", "thread_explosion": "thread_explosion", "ctx_switch": "context_switching",
}
TIMEOUT = {"zombie": 60, "cpu_hog_late": 75}
LAYERS = ("rule", "ewma", "iforest")


def call(base, path, body=None):
    req = urllib.request.Request(base + path, None if body is None else json.dumps(body).encode(),
                                 {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return json.load(e)


def run_case(base, wid, linger):
    start = call(base, "/api/workload/start", {"id": wid})
    if not start.get("ok"):
        raise SystemExit(start.get("message"))
    pid, t0 = start["pid"], time.time()
    found, deadline = None, t0 + TIMEOUT.get(wid, 45)
    while time.time() < deadline:
        alerts = [a for a in call(base, "/api/state")["alerts"] if a["pid"] == pid and a["type"] == EXPECT[wid]]
        if alerts and found is None:
            found = alerts[0]
            deadline = min(deadline + linger, time.time() + linger)  # give other layers time to corroborate
        elif alerts:
            found = alerts[0]
        time.sleep(0.5)
    call(base, "/api/workload/stop", {"id": wid})
    time.sleep(3)
    if not found:
        return {"detected": False}
    return {"detected": True, "ttd": found["ts"] - t0, "layers": {l: t - t0 for l, t in found["layers"].items()}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--idle", type=int, default=120, help="seconds of normal activity for the false-positive check (T6)")
    ap.add_argument("--linger", type=int, default=15)
    ap.add_argument("--only", nargs="*", default=list(EXPECT))
    ap.add_argument("--out", default="results/evaluation.md")
    args = ap.parse_args()

    st = call(args.url, "/api/state")
    print(f"Isolation Forest: {st['layers']['iforest']['status']}")
    results = {}
    for rep in range(args.reps):
        for wid in args.only:
            r = run_case(args.url, wid, args.linger)
            results.setdefault(wid, []).append(r)
            print(f"rep {rep + 1} {wid:17} " + (f"detected in {r['ttd']:5.1f}s via {', '.join(r['layers'])}" if r["detected"] else "MISSED"), flush=True)

    t_idle = time.time()
    print(f"T6: watching {args.idle}s of normal activity for false positives...", flush=True)
    time.sleep(args.idle)
    st = call(args.url, "/api/state")
    fps = [a for a in st["alerts"] if a["ts"] >= t_idle]
    overhead = st["collector"]["cpu_avg"]

    lines = ["# ProcSentinel evaluation", "",
             f"Reps per test: {args.reps}. Isolation Forest status: {st['layers']['iforest']['status']}.", "",
             "| Test | Expected | Detection rate | Mean time to detect | Rule | EWMA | Isolation Forest |",
             "|---|---|---|---|---|---|---|"]
    for wid, rs in results.items():
        hits = [r for r in rs if r["detected"]]
        cells = []
        for l in LAYERS:
            ts = [r["layers"][l] for r in hits if l in r["layers"]]
            cells.append(f"{len(ts)}/{len(rs)}, {statistics.mean(ts):.1f}s" if ts else f"0/{len(rs)}")
        mttd = f"{statistics.mean(r['ttd'] for r in hits):.1f}s" if hits else "-"
        lines.append(f"| {wid} | {EXPECT[wid]} | {len(hits)}/{len(rs)} | {mttd} | " + " | ".join(cells) + " |")
    lines += ["", f"T6 false positives in {args.idle}s of normal activity: **{len(fps)}**"]
    lines += [f"- {a['type']} on {a['name']} (pid {a['pid']}) via {', '.join(a['layers'])}" for a in fps]
    lines += ["", f"T7 collector overhead: **{overhead:.2f}% CPU** average at {st['interval_ms']} ms interval"
              if overhead is not None else "T7 collector overhead: n/a"]
    report = "\n".join(lines) + "\n"
    print("\n" + report)
    import os
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        f.write(report)


if __name__ == "__main__":
    main()
