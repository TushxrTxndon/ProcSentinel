"""ProcSentinel analysis engine: reads snapshots from the collector over a UNIX
domain socket, runs detection, logs to SQLite and serves the dashboard."""
import argparse
import json
import os
import pwd
import signal
import socket
import subprocess
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import actions, config as C
from .detector import Detector, is_kernel_thread
from .explainer import LLMExplainer, template
from .store import Store

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
DASHBOARD = os.path.join(ROOT, "dashboard")
WORKLOAD_BIN = os.path.join(ROOT, "workloads", "bin")

def detect_env():
    """'wsl' (WSL2 or Docker Desktop on Windows), 'vm' (other hypervisor) or 'native'."""
    try:
        if "microsoft" in open("/proc/version").read().lower():
            return "wsl"
        if " hypervisor" in open("/proc/cpuinfo").read():
            return "vm"
    except OSError:
        pass
    return "native"


ENV = detect_env()

WORKLOADS = [
    # id, test id, label, what it does, argv
    ("cpu_hog", "T1", "CPU hog", "Infinite busy loop in one process", ["cpu_hog"]),
    ("cpu_hog_late", "T1b", "CPU hog, delayed", "Idles 25 s so EWMA learns a baseline, then spins", ["cpu_hog", "25"]),
    ("mem_leak", "T2", "Memory leak", "malloc() 8 MB/s in a loop, never free()", ["mem_leak", "8", "1024"]),
    ("fork_bomb", "T3", "Fork bomb", "Controlled: forks 150 children at ~50/s (hard cap 400)", ["fork_bomb", "150"]),
    ("zombie", "T4", "Zombies", "Parent never calls wait() on 10 exited children", ["zombie", "10"]),
    ("thread_explosion", "T5", "Thread explosion", "Creates 400 pthreads", ["thread_explosion", "400"]),
    ("ctx_switch", "T8", "Context switching", "Two threads ping-pong a byte through pipes", ["ctx_switch"]),
]


class Engine:
    def __init__(self, data_dir):
        self.lock = threading.Lock()
        self.detector = Detector(data_dir)
        self.store = Store(os.path.join(data_dir, "procsentinel.db"))
        self.llm = LLMExplainer(self._ai_result)
        self.snap = None
        self.sys_hist = deque(maxlen=C.HISTORY_SAMPLES)
        self.overhead = deque(maxlen=600)
        self.connected = False
        self.ticks = 0
        self.users = {}
        self.workloads = []   # (id, Popen, started)
        # Resources reclaimed by user actions (SDG 7): CPU a stopped/terminated process would
        # have kept burning, and memory released when it exits.
        self.tracked = {}     # (pid, start) -> {"cpu", "rss_kb", "since", "freed"}
        self.impact = {"cpu_s": 0.0, "mem_kb": 0}

    # ---------------- ingest ----------------
    def ingest(self, snap):
        new, updated = self.detector.process(snap, skip={snap["collector_pid"], os.getpid()})
        s = snap["sys"]
        mem_pct = 100 * (1 - s["mem_avail_kb"] / s["mem_total_kb"]) if s["mem_total_kb"] else 0
        coll = next((p for p in snap["procs"] if p["pid"] == snap["collector_pid"]), None)
        me = next((p for p in snap["procs"] if p["pid"] == os.getpid()), None)
        with self.lock:
            self.snap = snap
            self.ticks += 1
            self.sys_hist.append([snap["ts"], s["cpu"], mem_pct, s["load"][0], s["ctxt_rate"], s["fork_rate"]])
            if coll and self.ticks > 1:
                self.overhead.append(coll["cpu"])
            self.collector = coll
            self.engine_proc = me
        for a in new:
            a.update(template(a))
            a["ai_status"] = "pending" if self.llm.enabled else None
            a["id"] = self.store.add_alert(a)
            if not self.llm.submit(a["id"], a, self.detector.history(a["pid"])):
                if self.llm.enabled:
                    self.store.set_ai(a["id"], None, "skipped")
            print(f"[alert] {a['severity']:8} {a['type']:18} pid={a['pid']} {a['name']} via {','.join(a['layers'])}", flush=True)
        for a in updated:
            self.store.update_layers(a["id"], a["layers"], a["metrics"])
        self._account(snap)
        self._reap()

    def _account(self, snap):
        live = {(p["pid"], p["start"]): p for p in snap["procs"]}
        dt = snap["interval_ms"] / 1000
        with self.lock:
            for key, t in list(self.tracked.items()):
                p = live.get(key)
                if p is not None and p["state"] in "ZX":
                    p = None                             # exited; a zombie holds no memory
                if p is not None and p["state"] not in "Tt":
                    del self.tracked[key]            # resumed: no longer reclaiming
                    continue
                if snap["ts"] - t["since"] <= C.IMPACT_MAX_S:
                    self.impact["cpu_s"] += t["cpu"] / 100 * dt
                if p is None and not t["freed"]:
                    self.impact["mem_kb"] += t["rss_kb"]
                    t["freed"] = True
                if p is None and snap["ts"] - t["since"] > C.IMPACT_MAX_S:
                    del self.tracked[key]

    def _ai_result(self, alert_id, text):
        self.store.set_ai(alert_id, text, "done" if text else "failed")

    def _reap(self):
        with self.lock:
            self.workloads = [w for w in self.workloads if w[1].poll() is None]

    def user(self, uid):
        if uid not in self.users:
            try:
                self.users[uid] = pwd.getpwuid(uid).pw_name
            except KeyError:
                self.users[uid] = str(uid)
        return self.users[uid]

    # ---------------- API views ----------------
    def state(self, pid=None):
        with self.lock:
            snap = self.snap
            sys_hist = list(self.sys_hist)
            overhead = list(self.overhead)
            coll, me = getattr(self, "collector", None), getattr(self, "engine_proc", None)
        flagged = {}
        for (apid, _, cls) in list(self.detector.recent):
            flagged.setdefault(apid, []).append(cls)
        procs = []
        if snap:
            for p in snap["procs"]:
                procs.append({
                    "pid": p["pid"], "ppid": p["ppid"], "name": p["name"], "user": self.user(p["uid"]),
                    "state": p["state"], "cpu": round(p["cpu"], 1), "rss_kb": p["rss_kb"], "threads": p["threads"],
                    "ctx_rate": round(p["ctx_rate"]), "nice": p["nice"], "children": p.get("children", 0),
                    "age_s": p["age_s"], "kthread": is_kernel_thread(p), "core": p.get("core", -1),
                    "ml": self.detector.ml_score(p["pid"], p["start"]), "alerts": flagged.get(p["pid"], []),
                })
        out = {
            "connected": self.connected, "now": time.time(), "env": ENV,
            "ts": snap["ts"] if snap else None, "ncpu": snap["ncpu"] if snap else None,
            "interval_ms": snap["interval_ms"] if snap else None,
            "sys": snap["sys"] if snap else None, "sys_hist": sys_hist, "procs": procs,
            "collector": {"pid": snap["collector_pid"] if snap else None, "cpu": coll["cpu"] if coll else None,
                          "cpu_avg": sum(overhead) / len(overhead) if overhead else None,
                          "rss_kb": coll["rss_kb"] if coll else None, "dropped": snap["dropped"] if snap else 0},
            "engine": {"pid": os.getpid(), "cpu": me["cpu"] if me else None, "rss_kb": me["rss_kb"] if me else None},
            "layers": {"rule": {"status": "ready"},
                       "ewma": {"status": "ready", "warmup": C.EWMA_WARMUP},
                       "iforest": self.detector.ml.info(), "llm": self.llm.info()},
            "alerts": self.store.alerts(40),
            "workloads": self.workload_view(),
            "actions": self.store.actions(25),
            "impact": dict(self.impact, wh=self.impact["cpu_s"] * C.WATTS_PER_CORE / 3600,
                           watts_per_core=C.WATTS_PER_CORE, tracking=len(self.tracked)),
        }
        if pid is not None:
            out["selected"] = {"pid": pid, "history": self.detector.history(pid)}
        return out

    def workload_view(self):
        with self.lock:
            running = {}
            for wid, proc, started in self.workloads:
                running.setdefault(wid, []).append({"pid": proc.pid, "started": started})
        have_bin = os.path.isdir(WORKLOAD_BIN)
        return [{"id": w[0], "test": w[1], "label": w[2], "desc": w[3], "available": have_bin and os.path.exists(os.path.join(WORKLOAD_BIN, w[4][0])),
                 "running": running.get(w[0], [])} for w in WORKLOADS]

    def start_workload(self, wid):
        w = next((w for w in WORKLOADS if w[0] == wid), None)
        if not w:
            return False, "unknown workload", None
        argv = [os.path.join(WORKLOAD_BIN, w[4][0])] + w[4][1:]
        if not os.path.exists(argv[0]):
            return False, "workload binaries not built (run make -C workloads)", None
        proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        with self.lock:
            self.workloads.append((wid, proc, time.time()))
        return True, f"Started {w[1]} {w[2]} as PID {proc.pid}", proc.pid

    def stop_workloads(self, wid=None):
        with self.lock:
            targets = [w for w in self.workloads if wid in (None, w[0])]
        for _, proc, _ in targets:
            try:
                os.killpg(proc.pid, signal.SIGKILL)   # whole session: parent + forked children
            except ProcessLookupError:
                pass
            proc.wait()
        self._reap()
        return True, f"Stopped {len(targets)} workload(s)"

    def act(self, body):
        pid, action, value = body.get("pid"), body.get("action"), body.get("value")
        with self.lock:
            snap = self.snap
        name = next((p["name"] for p in snap["procs"] if p["pid"] == pid), "?") if snap else "?"
        protected = {1, os.getpid(), os.getppid()} | ({snap["collector_pid"]} if snap else set())
        ok, msg = actions.perform(pid, action, value, protected)
        proc = next((p for p in snap["procs"] if p["pid"] == pid), None) if snap else None
        if ok and proc and action in ("stop", "term"):
            with self.lock:
                key = (proc["pid"], proc["start"])
                prev = self.tracked.get(key)
                # keep the CPU rate from before a SIGSTOP when the process is later terminated
                self.tracked[key] = {"cpu": prev["cpu"] if prev else proc["cpu"], "rss_kb": proc["rss_kb"],
                                     "since": prev["since"] if prev else time.time(), "freed": False}
        alert_id = body.get("alert_id") if isinstance(body.get("alert_id"), int) else None
        self.store.add_action(time.time(), pid if isinstance(pid, int) else None, name, str(action), value, ok, msg, alert_id)
        print(f"[action] {action} pid={pid} -> {msg}", flush=True)
        return ok, msg

    # ---------------- IPC: UNIX domain socket ----------------
    def serve_socket(self, path):
        if os.path.exists(path):
            os.unlink(path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        os.chmod(path, 0o600)
        srv.listen(1)
        print(f"[engine] waiting for collector on {path}", flush=True)
        while True:
            conn, _ = srv.accept()
            self.connected = True
            print("[engine] collector connected", flush=True)
            try:
                with conn, conn.makefile("r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        try:
                            snap = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        try:
                            self.ingest(snap)
                        except Exception as e:   # one bad snapshot must not stop monitoring
                            print(f"[engine] error processing snapshot: {e!r}", flush=True)
            finally:
                self.connected = False
                print("[engine] collector disconnected", flush=True)


def make_handler(engine):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def send_json(self, obj, code=200):
            body = json.dumps(obj, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if u.path == "/api/state":
                pid = q.get("pid", [None])[0]
                return self.send_json(engine.state(int(pid) if pid and pid.isdigit() else None))
            if u.path == "/api/alerts":
                return self.send_json(engine.store.alerts(500))
            if u.path == "/api/actions":
                return self.send_json(engine.store.actions(200))
            if u.path == "/api/llm/pending":
                return self.send_json(engine.llm.pending_list())
            rel = "index.html" if u.path in ("/", "") else u.path.lstrip("/")
            path = os.path.realpath(os.path.join(DASHBOARD, rel))
            if not path.startswith(DASHBOARD + os.sep) or not os.path.isfile(path):
                return self.send_json({"error": "not found"}, 404)
            ctype = {".html": "text/html", ".css": "text/css", ".js": "application/javascript",
                     ".svg": "image/svg+xml"}.get(os.path.splitext(path)[1], "application/octet-stream")
            with open(path, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            # Requiring a JSON content type forces a CORS preflight, so other web pages cannot POST here.
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                return self.send_json({"ok": False, "message": "expected application/json"}, 415)
            n = int(self.headers.get("Content-Length") or 0)
            if n > 10_000:
                return self.send_json({"ok": False, "message": "body too large"}, 413)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
                assert isinstance(body, dict)
            except Exception:
                return self.send_json({"ok": False, "message": "invalid JSON"}, 400)
            p = urlparse(self.path).path
            if p == "/api/action":
                ok, msg = engine.act(body)
                return self.send_json({"ok": ok, "message": msg}, 200 if ok else 400)
            if p == "/api/workload/start":
                ok, msg, pid = engine.start_workload(body.get("id"))
                return self.send_json({"ok": ok, "message": msg, "pid": pid}, 200 if ok else 400)
            if p == "/api/workload/stop":
                ok, msg = engine.stop_workloads(body.get("id"))
                return self.send_json({"ok": ok, "message": msg})
            if p == "/api/llm/answer":
                if engine.llm.mode != "external":
                    return self.send_json({"ok": False, "message": "LLM mode is not external"}, 400)
                ok, msg = engine.llm.answer(body.get("alert_id"), body.get("text"))
                return self.send_json({"ok": ok, "message": msg}, 200 if ok else 400)
            if p == "/api/ml/retrain":
                engine.detector.ml.retrain()
                return self.send_json({"ok": True, "message": "Collecting a new baseline"})
            if p == "/api/alerts/clear":
                engine.store.clear()
                return self.send_json({"ok": True, "message": "Log cleared"})
            return self.send_json({"ok": False, "message": "not found"}, 404)

    return Handler


def main():
    ap = argparse.ArgumentParser(description="ProcSentinel analysis engine + dashboard")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--socket", default=C.SOCKET_PATH)
    ap.add_argument("--data", default=C.DATA_DIR)
    args = ap.parse_args()

    engine = Engine(os.path.realpath(args.data))
    threading.Thread(target=engine.serve_socket, args=(args.socket,), daemon=True).start()
    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(engine))
    httpd.daemon_threads = True
    print(f"[engine] dashboard on http://{args.host}:{args.port}  (LLM: {engine.llm.mode})", flush=True)

    def shutdown(*_):
        engine.stop_workloads()
        threading.Thread(target=httpd.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
