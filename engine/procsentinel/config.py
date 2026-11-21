"""Detection thresholds. Defaults follow the synopsis (Section 2.1); tune here."""
import os

SOCKET_PATH = os.environ.get("PROCSENTINEL_SOCKET", "/tmp/procsentinel.sock")
DATA_DIR = os.environ.get("PROCSENTINEL_DATA", os.path.join(os.path.dirname(__file__), "..", "..", "data"))
HISTORY_SAMPLES = 120          # per-process samples kept in memory for graphs

# --- Layer 1: rules ---
CPU_HOG_PCT = 90.0             # CPU above 90% ...
CPU_HOG_SAMPLES = 10           # ... for 10 consecutive samples
ZOMBIE_SECONDS = 30            # a process in state Z for more than 30 s
FORK_WINDOW_S = 5              # more than 50 children spawned by one parent ...
FORK_CHILDREN = 50             # ... within 5 s
THREAD_ABS = 300               # thread count above this ...
THREAD_GROWTH = 100            # ... or growing by this much ...
THREAD_WINDOW_S = 10           # ... within 10 s
CTX_RATE = 20000.0             # context switches / s ...
CTX_SAMPLES = 5                # ... sustained for 5 samples
LEAK_WINDOW = 20               # RSS samples in the regression window
LEAK_MIN_SLOPE_KB_S = 512.0    # slope must stay positive and above this
LEAK_MIN_GROWTH_MB = 64.0      # and RSS must have grown this much in the window
LEAK_MIN_R2 = 0.9              # and the growth must be steady (linear fit quality)

# --- Layer 2: EWMA z-score (Equations 2.2, 2.3) ---
EWMA_ALPHA = 0.1
EWMA_Z = 3.0
EWMA_SUSTAIN = 5               # consecutive samples with |z| > 3
EWMA_ADAPT = 60                # after this many anomalous samples the new level becomes the baseline
EWMA_WARMUP = 20               # samples before a process's baseline is trusted
# metric -> (sigma floor, minimum absolute value worth alerting on, anomaly class)
EWMA_METRICS = {
    "cpu": (5.0, 40.0, "cpu_hog"),
    "rss_rate_mb": (1.0, 5.0, "memory_leak"),
    "threads": (2.0, 64.0, "thread_explosion"),
    "ctx_rate": (500.0, 5000.0, "context_switching"),
}

# --- Layer 3: Isolation Forest ---
ML_TRAIN_SAMPLES = 60          # ticks of "normal" data collected before training
ML_SUSTAIN = 5                 # consecutive outlier ticks before alerting
ML_MARGIN = 0.03               # threshold = most unusual steady process's 5th-percentile score - margin
ML_MAX_THRESHOLD = -0.55       # IF scores near -0.5 mean "nothing special"; never alert above this
ML_FEATURES = ["cpu", "rss_rate_mb", "threads", "ctx_rate", "children"]

ALERT_MERGE_S = 120            # a second layer detecting the same issue corroborates the alert

# --- Impact estimate (SDG 7) ---
WATTS_PER_CORE = 10.0          # rough extra power of one fully busy laptop core; an estimate
IMPACT_MAX_S = 600             # count reclaimed CPU for at most 10 min per stopped/killed process
