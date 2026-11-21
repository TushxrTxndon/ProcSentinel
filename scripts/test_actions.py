#!/usr/bin/env python3
"""Smoke test of the action module through the API: renice, SIGSTOP, SIGCONT, SIGTERM
on a CPU-hog workload, plus the guards. Usage: python3 scripts/test_actions.py"""
import json
import time
import urllib.error
import urllib.request

B = "http://127.0.0.1:8080"


def call(path, body=None, ctype="application/json"):
    req = urllib.request.Request(B + path, None if body is None else json.dumps(body).encode(), {"Content-Type": ctype})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return json.load(e)


def proc(pid):
    time.sleep(1.5)
    return next((p for p in call("/api/state")["procs"] if p["pid"] == pid), None)


pid = call("/api/workload/start", {"id": "cpu_hog"})["pid"]
time.sleep(2)
assert call("/api/action", {"pid": pid, "action": "renice", "value": 19})["ok"]
assert proc(pid)["nice"] == 19
assert call("/api/action", {"pid": pid, "action": "stop"})["ok"]
time.sleep(1)  # CPU% covers the previous sample, which still includes time before SIGSTOP
p = proc(pid)
assert p["state"] == "T" and p["cpu"] < 5, p
assert call("/api/action", {"pid": pid, "action": "cont"})["ok"]
assert proc(pid)["state"] == "R"
assert call("/api/action", {"pid": pid, "action": "term"})["ok"]
q = proc(pid)
assert q is None or q["state"] == "Z", q

st = call("/api/state")
assert not call("/api/action", {"pid": 1, "action": "term"})["ok"]                      # PID 1 protected
assert not call("/api/action", {"pid": st["collector"]["pid"], "action": "stop"})["ok"]  # collector protected
assert not call("/api/action", {"pid": st["engine"]["pid"], "action": "term"})["ok"]     # engine protected
assert not call("/api/action", {"pid": "1; rm -rf /", "action": "term"})["ok"]           # type check
assert not call("/api/action", {"pid": pid, "action": "kill -9"})["ok"]                  # allowlist
assert not call("/api/action", {"pid": 99999999, "action": "stop"})["ok"]                # missing PID
assert not call("/api/action", {"pid": pid, "action": "stop"}, ctype="text/plain")["ok"]  # CSRF guard
assert not call("/api/workload/start", {"id": "../../bin/sh"})["ok"]                     # fixed binaries only
logged = call("/api/actions")
assert len([a for a in logged if a["pid"] == pid and a["ok"]]) == 4
print("action tests passed")
