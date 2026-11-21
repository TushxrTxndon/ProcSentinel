"""Module 4 - Explainer. Offline templates always; an LLM (Claude or a local Ollama
model) is opt-in via PROCSENTINEL_LLM=claude|ollama. Only redacted context is sent:
process name, metric history and the triggered rule -- never command lines or paths
(the collector does not even read them).

PROCSENTINEL_LLM=external hands the same prompt to an outside model (for example a Claude
Code session) through GET /api/llm/pending and POST /api/llm/answer."""
import json
import os
import queue
import threading
import urllib.request

TEMPLATES = {
    "cpu_hog": dict(
        title="CPU hog",
        concept="CPU scheduling",
        explain="{name} (PID {pid}) is using {cpu:.0f}% CPU and has not let go. A process that never blocks on I/O or sleeps "
                "stays runnable (state R), so the scheduler keeps handing it time slices and every other program gets less. "
                "This is the signature of an infinite loop or busy-wait.",
        suggest="Renice it to 19 so interactive programs win the CPU, or pause it with SIGSTOP to investigate. "
                "Send SIGTERM if it is not doing useful work.",
        actions=["renice", "stop", "term"]),
    "memory_leak": dict(
        title="Memory leak",
        concept="Virtual memory and RSS",
        explain="{name} (PID {pid}) keeps growing: its resident set (RSS) is {rss_mb:.0f} MB and rising steadily. "
                "Memory is allocated (malloc) and touched, so the kernel maps real page frames to it, but nothing is ever freed. "
                "Left alone it will push other pages to swap and can finally trigger the OOM killer.",
        suggest="If the program is not expected to keep growing, stop it with SIGTERM before memory runs out. "
                "Developers should look for allocations without a matching free().",
        actions=["stop", "term"]),
    "fork_bomb": dict(
        title="Fork bomb",
        concept="Process creation with fork()",
        explain="{name} (PID {pid}) is spawning children at an abnormal rate ({children} children right now). "
                "Every fork() copies the process and takes a slot in the process table; an unchecked loop of fork() calls "
                "exhausts PIDs and memory until no new program can start.",
        suggest="Send SIGSTOP to the parent first: a stopped process cannot fork, so spawning halts immediately. "
                "Then terminate it. Per-user limits (ulimit -u) prevent this in the future.",
        actions=["stop", "term"]),
    "zombie": dict(
        title="Zombie accumulation",
        concept="Process termination and wait()",
        explain="{name} (PID {pid}) has {zombies} child process(es) that exited but were never reaped. The parent never "
                "called wait()/waitpid() to collect their exit status, so the kernel keeps their entries (state Z). "
                "Zombies use no CPU or memory, but each one holds a PID.",
        suggest="A zombie cannot be killed: it is already dead. Fix the parent so it calls wait(), or terminate the parent; "
                "its zombies are then adopted by init (PID 1), which reaps them at once.",
        actions=["term"]),
    "thread_explosion": dict(
        title="Thread explosion",
        concept="Multithreading (pthreads)",
        explain="{name} (PID {pid}) now runs {threads} threads. Each pthread is a separate kernel task with its own stack "
                "and scheduling entry, so runaway thread creation wastes memory, adds scheduler overhead and can hit the "
                "system thread limit (threads-max, ulimit -u).",
        suggest="Pause it with SIGSTOP to stop further thread creation, then terminate it if the growth is unexpected. "
                "A fixed-size thread pool is the usual fix.",
        actions=["stop", "term"]),
    "context_switching": dict(
        title="Excessive context switching",
        concept="Context switching",
        explain="{name} (PID {pid}) causes about {ctx_rate:,.0f} context switches per second. Each switch saves one task's "
                "registers and loads another's, and cold caches make the next instructions slower. A high voluntary count "
                "means threads keep blocking and waking each other (lock or pipe ping-pong).",
        suggest="Lower its priority with renice, or pause it with SIGSTOP. Batching work or using fewer, longer "
                "critical sections reduces switching.",
        actions=["renice", "stop", "term"]),
    "unusual_behaviour": dict(
        title="Unusual behaviour",
        concept="Process resource usage",
        explain="{name} (PID {pid}) shows a combination of CPU, memory growth, threads, context switches and children "
                "that the Isolation Forest model has rarely seen during normal operation on this machine.",
        suggest="Inspect the process before acting. Pause it with SIGSTOP if it is hurting the system.",
        actions=["renice", "stop", "term"]),
}

LAYER_NAMES = {"rule": "Rule", "ewma": "EWMA z-score", "iforest": "Isolation Forest"}
SEVERITY = {"fork_bomb": "critical", "memory_leak": "critical", "cpu_hog": "warning", "thread_explosion": "warning",
            "zombie": "warning", "context_switching": "warning", "unusual_behaviour": "info"}


def template(alert):
    t = TEMPLATES[alert["type"]]
    s = dict(alert["snapshot"])
    s.update(cpu=s["cpu"], rss_mb=s["rss_kb"] / 1024)
    for m in alert["metrics"].values():
        s.update({k: v for k, v in m.items() if isinstance(v, (int, float))})
    s.setdefault("zombies", 0)
    return {
        "title": t["title"], "concept": t["concept"], "severity": SEVERITY[alert["type"]],
        "explanation": t["explain"].format(**s), "suggestion": t["suggest"], "actions": t["actions"],
    }


PROMPT = """You are the explainer inside ProcSentinel, a Linux process monitor used in an Operating Systems lab.
An anomaly was detected. Using only the data below, write for a student:
1. Two or three sentences explaining what the process is doing and why it is a problem, naming the OS concept involved.
2. One line starting with "Suggested action:" choosing from renice, SIGSTOP, SIGCONT or SIGTERM.
Plain text, no markdown, under 90 words. Be careful: this advice is advisory and a human decides.

Data:
{data}"""


class LLMExplainer:
    """Background worker: alerts go in a queue, AI explanations come back via callback."""

    def __init__(self, on_result):
        self.mode = os.environ.get("PROCSENTINEL_LLM", "off").lower()
        self.on_result = on_result
        self.q = queue.Queue(maxsize=20)
        self.error = None
        self.client = None
        self.pending = {}     # external mode: alert_id -> prompt, until answered
        self.lock = threading.Lock()
        if self.mode == "claude":
            try:
                import anthropic
                self.client = anthropic.Anthropic()
            except Exception as e:
                self.error, self.mode = f"Claude unavailable: {e}", "off"
        if self.mode in ("claude", "ollama"):
            threading.Thread(target=self._run, daemon=True).start()

    @property
    def enabled(self):
        return self.mode in ("claude", "ollama", "external")

    def info(self):
        return {"mode": self.mode, "error": self.error}

    def submit(self, alert_id, alert, history):
        if not self.enabled:
            return False
        ctx = {
            "process_name": alert["name"], "pid": alert["pid"], "anomaly": alert["type"],
            "detected_by": [LAYER_NAMES[l] for l in alert["layers"]], "trigger": alert["metrics"],
            "current": alert["snapshot"],
            "last_samples(cpu%,rss_mb,threads,ctx_per_s)": [[round(v, 1) for v in h[1:]] for h in history[-20:]],
        }
        if self.mode == "external":
            with self.lock:
                if len(self.pending) >= 50:
                    return False
                self.pending[alert_id] = PROMPT.format(data=json.dumps(ctx, default=str))
            return True
        try:
            self.q.put_nowait((alert_id, json.dumps(ctx, default=str)))
            return True
        except queue.Full:
            return False

    def pending_list(self):
        with self.lock:
            return [{"alert_id": k, "prompt": v} for k, v in sorted(self.pending.items())]

    def answer(self, alert_id, text):
        """External mode: store an answer for a pending alert. Returns (ok, message)."""
        if not isinstance(text, str) or not text.strip() or len(text) > 2000:
            return False, "text must be 1-2000 characters"
        with self.lock:
            if self.pending.pop(alert_id, None) is None:
                return False, "no pending explanation for that alert"
        self.on_result(alert_id, text.strip())
        return True, "Explanation saved"

    def _run(self):
        while True:
            alert_id, data = self.q.get()
            try:
                text = self._claude(data) if self.mode == "claude" else self._ollama(data)
                self.error = None
            except Exception as e:
                text, self.error = None, f"{type(e).__name__}: {e}"
            self.on_result(alert_id, text)

    def _claude(self, data):
        resp = self.client.beta.messages.create(
            model=os.environ.get("PROCSENTINEL_MODEL", "claude-opus-5-5"),
            max_tokens=1024,
            output_config={"effort": "low"},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            messages=[{"role": "user", "content": PROMPT.format(data=data)}],
        )
        if resp.stop_reason == "refusal":
            return None
        return "".join(b.text for b in resp.content if b.type == "text").strip() or None

    def _ollama(self, data):
        host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
        body = json.dumps({"model": os.environ.get("OLLAMA_MODEL", "llama3.2"), "stream": False,
                           "prompt": PROMPT.format(data=data)}).encode()
        req = urllib.request.Request(host.rstrip("/") + "/api/generate", body, {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r).get("response", "").strip() or None
