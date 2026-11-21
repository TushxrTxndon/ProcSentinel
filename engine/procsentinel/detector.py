"""Module 3 - Anomaly engine: rules + EWMA z-score + Isolation Forest."""
import math
import os
import pickle
import threading
import time
from collections import deque

from . import config as C

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    ML_IMPORT_ERROR = None
except Exception as e:  # ML layer is disabled, rules + statistics still run
    np = None
    ML_IMPORT_ERROR = str(e)


def is_kernel_thread(p):
    return p["pid"] == 2 or p["ppid"] == 2


def linreg(ys):
    """Slope (per sample) and R^2 of a least-squares line through ys."""
    n = len(ys)
    mx = (n - 1) / 2
    my = sum(ys) / n
    sxx = sum((i - mx) ** 2 for i in range(n))
    sxy = sum((i - mx) * (y - my) for i, y in enumerate(ys))
    syy = sum((y - my) ** 2 for y in ys)
    slope = sxy / sxx
    r2 = (sxy * sxy) / (sxx * syy) if syy > 0 else 0.0
    return slope, r2


class Ewma:
    __slots__ = ("mu", "var", "n", "over")

    def __init__(self):
        self.mu, self.var, self.n, self.over = 0.0, 0.0, 0, 0

    def score(self, x, alpha, floor):
        """z-score of x (Eq. 2.3): deviation from the updated mean (Eq. 2.2), divided by
        the baseline standard deviation from before x was seen."""
        if self.n == 0:
            return 0.0
        mu_t = alpha * x + (1 - alpha) * self.mu                          # Eq. 2.2
        return (x - mu_t) / max(math.sqrt(self.var), floor)               # Eq. 2.3

    def commit(self, x, alpha):
        if self.n == 0:
            self.mu = x
        else:
            d = x - self.mu
            self.mu += alpha * d
            self.var = (1 - alpha) * (self.var + alpha * d * d)
        self.n += 1


class ProcState:
    def __init__(self):
        self.hist = deque(maxlen=C.HISTORY_SAMPLES)   # (ts, cpu, rss_mb, threads, ctx_rate)
        self.cpu_hi = 0
        self.ctx_hi = 0
        self.zombie_since = None
        self.forks = deque()                          # (ts, new_children)
        self.ewma = {m: Ewma() for m in C.EWMA_METRICS}
        self.ml_hits = 0
        self.ml_score = None


class MLLayer:
    def __init__(self, path):
        self.path = path
        self.rows, self.keys = [], []
        self.ticks = 0
        self.model = None
        self.threshold = None
        self.p99 = None
        self.trained_at = None
        self.status = "disabled" if ML_IMPORT_ERROR else "collecting"
        self.message = ML_IMPORT_ERROR or ""
        if not ML_IMPORT_ERROR and os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    d = pickle.load(f)
                self.model, self.threshold, self.p99, self.trained_at = d["model"], d["threshold"], d["p99"], d["trained_at"]
                self.n_train = d.get("n", 0)
                self.status = "ready"
            except Exception as e:
                self.message = f"could not load saved model: {e}"

    @staticmethod
    def transform(X):
        X = np.asarray(X, dtype=float)
        return np.sign(X) * np.log1p(np.abs(X))

    def info(self):
        d = {"status": self.status, "message": self.message}
        if self.status == "collecting":
            d["progress"] = self.ticks / C.ML_TRAIN_SAMPLES
        if self.status == "ready":
            d["trained_at"] = self.trained_at
            d["threshold"] = self.threshold
            d["samples"] = getattr(self, "n_train", 0)
        return d

    def retrain(self):
        if ML_IMPORT_ERROR:
            return
        self.rows, self.keys, self.ticks, self.status, self.message = [], [], 0, "collecting", ""

    def observe(self, feats, keys):
        if self.status != "collecting":
            return
        self.rows.extend(feats)
        self.keys.extend(keys)
        self.ticks += 1
        if self.ticks >= C.ML_TRAIN_SAMPLES:
            self.status = "training"
            threading.Thread(target=self._fit, args=(self.rows, self.keys), daemon=True).start()
            self.rows, self.keys = [], []

    def _fit(self, rows, keys):
        try:
            X = self.transform(rows)
            model = IsolationForest(n_estimators=100, random_state=0).fit(X)
            scores = model.score_samples(X)
            # Calibrate on steady normal processes: each one's normal worst case (5th percentile
            # of its scores, i.e. the 95th most unusual), the most unusual of those, minus a
            # margin, and never laxer than ML_MAX_THRESHOLD. One-off startup transients and test
            # workloads running during training cannot push the threshold out of reach.
            per_proc = {}
            for k, sc in zip(keys, scores):
                per_proc.setdefault(k, []).append(sc)
            # Short-lived processes (e.g. a test started during training) are not "steady normal".
            steady = [v for v in per_proc.values() if len(v) >= C.ML_TRAIN_SAMPLES // 2] or list(per_proc.values())
            typical = min(float(np.quantile(v, 0.05)) for v in steady)
            self.threshold = min(typical - C.ML_MARGIN, C.ML_MAX_THRESHOLD)
            self.p99 = np.quantile(np.asarray(rows, dtype=float), 0.99, axis=0).tolist()
            self.model, self.trained_at, self.n_train = model, time.time(), len(rows)
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "wb") as f:
                pickle.dump({"model": model, "threshold": self.threshold, "p99": self.p99,
                             "trained_at": self.trained_at, "n": len(rows)}, f)
            self.status, self.message = "ready", ""
        except Exception as e:
            self.status, self.message = "disabled", f"training failed: {e}"

    def score(self, feats):
        if self.status != "ready" or not feats:
            return None
        return self.model.score_samples(self.transform(feats))


class Detector:
    def __init__(self, data_dir):
        self.procs = {}          # (pid, start) -> ProcState
        self.ml = MLLayer(os.path.join(data_dir, "iforest.pkl"))
        self.recent = {}         # (pid, start, class) -> alert dict (for corroboration)

    # ------------------------------------------------------------------
    def process(self, snap, skip=()):
        """Run all three layers on one snapshot; `skip` = PIDs never flagged (ProcSentinel itself).
        Returns (new_alerts, updated_alerts)."""
        ts = snap["ts"]
        procs = snap["procs"]
        by_pid = {p["pid"]: p for p in procs}
        children = {}
        for p in procs:
            children[p["ppid"]] = children.get(p["ppid"], 0) + 1

        live = set()
        findings = []   # (proc, class, layer, metrics)
        zombies_by_parent = {}
        feats, feat_procs = [], []

        for p in procs:
            key = (p["pid"], p["start"])
            live.add(key)
            st = self.procs.get(key)
            if st is None:
                st = self.procs[key] = ProcState()
            rss_mb = p["rss_kb"] / 1024
            p["rss_rate_mb"] = p["rss_rate_kb"] / 1024
            p["children"] = children.get(p["pid"], 0)
            st.hist.append((ts, p["cpu"], rss_mb, p["threads"], p["ctx_rate"]))
            if is_kernel_thread(p) or p["pid"] in skip:
                continue

            # ---------------- Layer 1: rules ----------------
            st.cpu_hi = st.cpu_hi + 1 if p["cpu"] > C.CPU_HOG_PCT else 0
            if st.cpu_hi >= C.CPU_HOG_SAMPLES:
                findings.append((p, "cpu_hog", "rule", {"cpu": p["cpu"], "seconds": st.cpu_hi}))

            st.ctx_hi = st.ctx_hi + 1 if p["ctx_rate"] > C.CTX_RATE else 0
            if st.ctx_hi >= C.CTX_SAMPLES:
                findings.append((p, "context_switching", "rule", {"ctx_rate": p["ctx_rate"], "vctx": p["vctx"], "nvctx": p["nvctx"]}))

            if p["state"] == "Z":
                st.zombie_since = st.zombie_since or ts
                if ts - st.zombie_since > C.ZOMBIE_SECONDS:
                    zombies_by_parent.setdefault(p["ppid"], []).append(p["pid"])

            if p["new_children"]:
                st.forks.append((ts, p["new_children"]))
            while st.forks and ts - st.forks[0][0] > C.FORK_WINDOW_S:
                st.forks.popleft()
            spawned = sum(n for _, n in st.forks)
            if spawned > C.FORK_CHILDREN:
                findings.append((p, "fork_bomb", "rule", {"spawned": spawned, "window_s": C.FORK_WINDOW_S, "children": p["children"]}))

            old = next((h for h in st.hist if ts - h[0] <= C.THREAD_WINDOW_S), None)
            growth = p["threads"] - old[3] if old else 0
            if p["threads"] > C.THREAD_ABS or growth >= C.THREAD_GROWTH:
                findings.append((p, "thread_explosion", "rule", {"threads": p["threads"], "growth": growth}))

            if len(st.hist) >= C.LEAK_WINDOW:
                rss = [h[2] for h in list(st.hist)[-C.LEAK_WINDOW:]]
                slope, r2 = linreg(rss)
                interval = snap.get("interval_ms", 1000) / 1000
                slope_kb_s = slope * 1024 / interval
                if slope_kb_s > C.LEAK_MIN_SLOPE_KB_S and rss[-1] - rss[0] >= C.LEAK_MIN_GROWTH_MB and r2 >= C.LEAK_MIN_R2:
                    findings.append((p, "memory_leak", "rule", {"rss_mb": rss_mb, "slope_mb_s": slope_kb_s / 1024, "r2": r2, "window": C.LEAK_WINDOW}))

            # ---------------- Layer 2: EWMA z-score ----------------
            for m, (floor, minimum, cls) in C.EWMA_METRICS.items():
                e = st.ewma[m]
                x = p[m]
                z = e.score(x, C.EWMA_ALPHA, floor)
                anomalous = e.n > C.EWMA_WARMUP and abs(z) > C.EWMA_Z and x >= minimum
                e.over = e.over + 1 if anomalous else 0
                # Anomalous samples must not inflate the baseline (otherwise sigma grows and
                # z drops below 3 within a second); a level that persists becomes the new normal.
                if not anomalous or e.over > C.EWMA_ADAPT:
                    e.commit(x, C.EWMA_ALPHA)
                if e.over >= C.EWMA_SUSTAIN:
                    findings.append((p, cls, "ewma", {m: x, "z": z, "mean": e.mu}))

            feats.append([p[f] for f in C.ML_FEATURES])
            feat_procs.append((p, st))

        for ppid, zs in zombies_by_parent.items():
            parent = by_pid.get(ppid)
            if parent:
                findings.append((parent, "zombie", "rule", {"zombies": len(zs), "zombie_pids": zs[:20], "seconds": C.ZOMBIE_SECONDS}))

        # ---------------- Layer 3: Isolation Forest ----------------
        self.ml.observe(feats, [(p["pid"], p["start"]) for p, _ in feat_procs])
        scores = self.ml.score(feats)
        if scores is not None:
            for (p, st), s, f in zip(feat_procs, scores, feats):
                st.ml_score = float(s)
                st.ml_hits = st.ml_hits + 1 if s < self.ml.threshold else 0
                if st.ml_hits >= C.ML_SUSTAIN:
                    cls, why = self._ml_class(f)
                    findings.append((p, cls, "iforest", {"score": float(s), "threshold": self.ml.threshold, "unusual": why}))

        for key in [k for k in self.procs if k not in live]:
            del self.procs[key]
        for key in [k for k, a in self.recent.items() if ts - a["ts"] > C.ALERT_MERGE_S or (k[0], k[1]) not in live]:
            del self.recent[key]

        new, updated = [], []
        for p, cls, layer, metrics in findings:
            k = (p["pid"], p["start"], cls)
            if layer == "iforest" and k not in self.recent:
                # The forest does not classify; its guessed class must not duplicate an open alert.
                k = next((r for r in self.recent if r[:2] == k[:2]), k)
            a = self.recent.get(k)
            if a is None:
                a = {"ts": ts, "pid": p["pid"], "start": p["start"], "name": p["name"], "type": cls,
                     "layers": {layer: ts}, "metrics": {layer: metrics}, "snapshot": self._snap(p)}
                self.recent[k] = a
                new.append(a)
            elif layer not in a["layers"]:
                a["layers"][layer] = ts
                a["metrics"][layer] = metrics
                updated.append(a)
        return new, updated

    def _ml_class(self, f):
        """Name the feature(s) that are beyond the training 99th percentile."""
        names = {"cpu": "cpu_hog", "rss_rate_mb": "memory_leak", "threads": "thread_explosion",
                 "ctx_rate": "context_switching", "children": "fork_bomb"}
        over = [(f[i] / max(self.ml.p99[i], 1e-9), C.ML_FEATURES[i], f[i], self.ml.p99[i])
                for i in range(len(f)) if f[i] > self.ml.p99[i]]
        if not over:
            return "unusual_behaviour", []
        over.sort(reverse=True)
        return names[over[0][1]], [{"feature": n, "value": round(v, 2), "normal_p99": round(q, 2)} for _, n, v, q in over]

    @staticmethod
    def _snap(p):
        return {k: p[k] for k in ("pid", "ppid", "name", "state", "cpu", "rss_kb", "threads", "ctx_rate", "nice", "children")}

    def history(self, pid):
        for (p, _), st in list(self.procs.items()):   # called from HTTP threads
            if p == pid:
                return [list(h) for h in list(st.hist)]
        return []

    def ml_score(self, pid, start):
        st = self.procs.get((pid, start))
        return st.ml_score if st else None


if __name__ == "__main__":
    # Self-check: EWMA flags a jump, linreg sees a steady leak.
    e = Ewma()
    for _ in range(30):
        e.commit(1.0, 0.1)
    assert e.score(100.0, 0.1, 5.0) > 3 and abs(e.score(1.0, 0.1, 5.0)) < 1
    s, r2 = linreg([i * 2.0 for i in range(20)])
    assert abs(s - 2.0) < 1e-9 and r2 > 0.99
    print("detector self-check ok")
