# ProcSentinel

An AI-assisted Linux process monitor and anomaly detector, built for the Operating Systems Lab (24B11CS312), JIIT Noida.

ProcSentinel samples every process from `/proc` once per second, detects six kinds of misbehaviour with three detection layers, explains each alert in plain language tied to an OS concept, and lets you respond with `renice`, `SIGSTOP`/`SIGCONT` or `SIGTERM`. Every response is confirmed by you first; nothing is ever killed automatically.

```
 /proc  ──read()──►  Collector daemon (C++17)  ──UNIX socket, JSON lines──►  Analysis engine (Python)
                                                                             ├─ Rules
                                                                             ├─ EWMA z-score
                                                                             ├─ Isolation Forest
                                                                             ├─ Explainer (templates, optional Claude / Ollama)
                                                                             ├─ SQLite log
                                                                             └─ Web dashboard ──user confirms──► setpriority() / kill()
```

## Quick start

ProcSentinel needs Linux, because it reads `/proc`. Pick one of these.

**Ubuntu / WSL2 (recommended for the demo)**

```bash
sudo apt install g++ cmake make python3 python3-venv
cd procsentinel
./run.sh                      # builds everything, then open http://127.0.0.1:8080
```

`run.sh` compiles the collector and the test workloads, creates a `.venv` with numpy and scikit-learn if they are missing, starts the engine and then the collector. Stop it with Ctrl+C.

To install WSL on Windows: `wsl --install -d Ubuntu-24.04` in an admin PowerShell, reboot, then run the commands above inside Ubuntu.

**Docker (any OS)**

```bash
docker build -t procsentinel .
docker run --rm -it --init --pid=host -p 127.0.0.1:8080:8080 procsentinel
```

`--pid=host` lets it see every process of the Docker VM, not just its own container. `--init` makes sure orphaned zombies are reaped after a test.

Run as root (`sudo ./run.sh`) to monitor and act on other users' processes. As a normal user you see everything but can only signal your own processes.

## Demo script (about 5 minutes)

1. Open the dashboard. Point out the live vital signs at the top (CPU, memory, load, context switches and forks per second, all from `/proc/stat`, `/proc/meminfo` and `/proc/loadavg`), and the collector's own overhead in the top right.
2. The detection-layer strip shows the Isolation Forest learning "normal" for the first 60 seconds. Start no workloads during this time.
3. Under **Test workloads**, start **T1 CPU hog**. It is selected automatically, so its graphs appear, and the **CPU cores** heatmap marks the core the scheduler put it on (it may hop between cores). About 10 seconds later a *CPU hog* alert arrives. Open it: the explanation, the OS concept (CPU scheduling), which layers detected it and when, and the evidence.
4. Click **Renice to 19** in the alert, confirm, and watch the Nice column change. Then **Pause**: the state turns to `T`, CPU drops to 0, and **Reclaimed by your actions** starts counting the CPU time and energy saved. Every step is listed under the **Actions** tab.
5. **T3 Fork bomb**: a critical alert in about 2 seconds, naming the parent PID. Switch the process list to **Tree** to see the parent with its 150 children, created by `fork()`. Pause the parent: spawning stops at once, because a stopped process cannot call `fork()`.
6. **T4 Zombies**: after 30 seconds the parent is flagged and its children show state `Z`. Terminate the parent: init adopts and reaps the zombies, and they disappear.
7. **T2 Memory leak**, **T5 Thread explosion** and **T8 Context switching** work the same way. **T1b** idles for 25 seconds first, so the EWMA layer learns its baseline and flags the jump before the 10-second rule does.

## Detection

| Anomaly | Rule (layer 1) | Also caught by (measured) |
|---|---|---|
| CPU hog | CPU above 90% for 10 consecutive samples | EWMA, when the process had a baseline first (T1b: 6 s before the rule) |
| Memory leak | Linear-regression slope of RSS over 20 samples stays positive (≥ 0.5 MB/s, ≥ 64 MB growth, R² ≥ 0.9) | Isolation Forest, about 14 s before the rule |
| Fork bomb | More than 50 children spawned by one parent within 5 s | |
| Zombies | A child in state `Z` for more than 30 s (alert raised on the parent) | |
| Thread explosion | More than 300 threads, or +100 threads within 10 s | |
| Context switching | More than 20,000 switches/s for 5 samples | Isolation Forest, same time as the rule |

**EWMA z-score (layer 2).** For each process and metric, μₜ = α·xₜ + (1 − α)·μₜ₋₁ and an EWMA variance are kept (α = 0.1). The z-score is zₜ = (xₜ − μₜ)/σ. A process needs 20 samples of baseline first, and |z| > 3 must hold for 5 samples. Samples that are anomalous do not update the baseline, so σ does not inflate and hide the anomaly. A level that persists for 60 samples becomes the new normal.

**Isolation Forest (layer 3).** Trained on feature vectors (CPU %, RSS growth rate, thread count, context-switch rate, child count, log-scaled) collected during the first 60 s, then saved to `data/iforest.pkl`. The alert threshold is calibrated on the processes that were present for most of the baseline: their normal worst-case score, minus a margin. One-off startup spikes, or a test left running during training, therefore cannot push the threshold out of reach. A process must stay below the threshold for 5 samples. The alert names the features that exceed the training 99th percentile. Use **Retrain** in the dashboard to learn a new baseline.

When a second layer detects the same issue on the same process, it is added to the existing alert, and the alert records when each layer detected it. That is how the layers are compared.

All thresholds are in [engine/procsentinel/config.py](engine/procsentinel/config.py).

## AI explanations (optional)

Every alert gets an offline template explanation. To add an LLM explanation:

```bash
pip install anthropic                     # inside .venv
export ANTHROPIC_API_KEY=...              # or run `ant auth login`
PROCSENTINEL_LLM=claude ./run.sh          # uses claude-opus-5-5; override with PROCSENTINEL_MODEL

PROCSENTINEL_LLM=ollama OLLAMA_MODEL=llama3.2 ./run.sh   # fully local alternative

PROCSENTINEL_LLM=external ./run.sh        # an outside agent (e.g. a Claude Code session) answers
```

In `external` mode the engine sends no requests of its own. Each alert's prompt waits at `GET /api/llm/pending`, and any agent can answer it with `POST /api/llm/answer {"alert_id": 3, "text": "..."}`. The dashboard shows "Asking Claude (external session)…" until the answer arrives. This lets you demo AI explanations without an API key, by having a Claude Code session watch the queue and answer.

Only redacted context is sent: process name, anomaly type, triggering metrics and recent metric history. The collector never reads command lines or file paths, so they cannot leak. AI text is shown as advisory, below the template explanation.

## Evaluation (test cases T1–T7)

With ProcSentinel running and no workloads active:

```bash
python3 scripts/evaluate.py --reps 3 --idle 120
```

It runs each workload several times through the API and measures detection rate, time to detection per layer, false positives during idle time (T6) and the collector's average CPU (T7). It writes the report to `results/evaluation.md`. For a realistic T6, keep using the desktop normally (browser, editor, compiler) during the idle phase.

`python3 scripts/test_actions.py` checks the action module: renice, SIGSTOP, SIGCONT and SIGTERM on a live process, and that PID 1, the engine, the collector, malformed requests and non-JSON (cross-site) requests are refused.

Latest run (Docker on Windows, `--pid=host`, 16 CPUs, 2 reps): 14/14 workloads detected, 0 alerts on any other process, 0 false positives in 120 s of idle activity, collector overhead 0.29% CPU. Full table: [results/evaluation.md](results/evaluation.md). Re-run it on the demo laptop for the final report, since that machine has far more processes.

## Project layout

| Path | What it is | OS concepts |
|---|---|---|
| [collector/src/main.cpp](collector/src/main.cpp) | Collector daemon: parses `/proc/[pid]/stat`, `status`, `statm`, `/proc/stat`, `/proc/meminfo`, `/proc/loadavg`; computes CPU % (Eq. 2.1), RSS growth, switch rate and new children; streams JSON lines over a UNIX domain socket through a producer–consumer mailbox, so a slow engine never delays sampling | PCB attributes, process states, `/proc`, CPU time accounting, IPC |
| [engine/procsentinel/detector.py](engine/procsentinel/detector.py) | Rules, EWMA z-score and Isolation Forest | Scheduling, virtual memory, `fork()`, zombies, context switching |
| [engine/procsentinel/explainer.py](engine/procsentinel/explainer.py) | Template explanations and the optional LLM worker | |
| [engine/procsentinel/actions.py](engine/procsentinel/actions.py) | `setpriority()` and `kill()` with SIGSTOP / SIGCONT / SIGTERM; protects PID 1, the engine and the collector | Signals, nice values, privileges |
| [engine/procsentinel/store.py](engine/procsentinel/store.py) | SQLite log of alerts and actions (`data/procsentinel.db`) | |
| [engine/procsentinel/server.py](engine/procsentinel/server.py) | Socket listener, HTTP API and dashboard server, workload launcher | |
| [dashboard/](dashboard/) | Web dashboard (no build step, no frameworks) | |
| [workloads/](workloads/) | C programs for each test case | pthreads, `malloc()`, `fork()`, `wait()`, pipes |
| [scripts/evaluate.py](scripts/evaluate.py) | Automated T1–T7 evaluation | |

The collector can also be run on its own: `collector/build/procsentinel-collector --once` prints one snapshot, and `--stdout` streams them.

## Safety

- Nothing is terminated automatically. Every action needs a confirmation in the dashboard and is written to the SQLite log.
- The dashboard listens on 127.0.0.1 only (Docker maps it to localhost too). POST requests must be JSON, which browsers cannot send cross-site without a CORS preflight, so other web pages cannot trigger actions.
- The fork-bomb workload is hard-capped at 400 children, and its children die with their parent. For an uncapped fork bomb, use a disposable VM with `ulimit -u`.
- The workload launcher only runs the fixed binaries in `workloads/bin`.

## Why Task Manager shows different numbers

- **CPU percentage convention.** Like `top`, ProcSentinel counts 100% as one fully busy core, so a busy loop shows about 100%. Windows Task Manager counts 100% as all cores, so the same loop on a 16-core laptop shows about 6%. The **1 core = 100% / All cores = 100%** switch above the process table shows both.
- **Scope.** On Windows, ProcSentinel runs inside the WSL2 or Docker Linux VM and sees only that VM's processes and memory; by default the VM gets half the host's RAM. Task Manager shows the entire VM as one process, VmmemWSL, next to all the Windows apps. The dashboard says so when it detects a VM.

## Limitations

- Linux only (depends on `/proc`).
- 1-second polling misses processes that live for less than a sample.
- Thresholds and the Isolation Forest baseline are tuned per machine. Retrain on the demo machine before presenting.
- An Isolation Forest cannot score values beyond its training range as *more* unusual than the most extreme training point. That is why the rules and EWMA layers catch some anomalies that the forest misses.
- LLM explanations can be wrong, so they are labelled advisory.
