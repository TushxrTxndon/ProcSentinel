# ProcSentinel evaluation

Reps per test: 2. Isolation Forest status: ready.

| Test | Expected | Detection rate | Mean time to detect | Rule | EWMA | Isolation Forest |
|---|---|---|---|---|---|---|
| cpu_hog | cpu_hog | 2/2 | 10.4s | 2/2, 10.4s | 0/2 | 0/2 |
| cpu_hog_late | cpu_hog | 2/2 | 29.8s | 2/2, 35.8s | 2/2, 29.8s | 0/2 |
| mem_leak | memory_leak | 2/2 | 5.6s | 2/2, 19.7s | 0/2 | 2/2, 5.6s |
| fork_bomb | fork_bomb | 2/2 | 1.6s | 2/2, 1.6s | 0/2 | 0/2 |
| zombie | zombie | 2/2 | 31.0s | 2/2, 31.0s | 0/2 | 0/2 |
| thread_explosion | thread_explosion | 2/2 | 2.7s | 2/2, 2.7s | 0/2 | 0/2 |
| ctx_switch | context_switching | 2/2 | 5.7s | 2/2, 5.7s | 0/2 | 2/2, 5.7s |

T6 false positives in 120s of normal activity: **0**

T7 collector overhead: **0.29% CPU** average at 1000 ms interval
