"use strict";
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const STATES = {
  R: "Running or runnable: on a CPU or waiting in the run queue.",
  S: "Sleeping: waiting for an event such as input or a timer (interruptible).",
  D: "Uninterruptible sleep: usually waiting for disk I/O. Signals wait until it wakes.",
  Z: "Zombie: it has exited, but its parent has not called wait() to collect its status.",
  T: "Stopped by a signal (SIGSTOP). SIGCONT resumes it.",
  t: "Stopped by a debugger (traced).",
  I: "Idle kernel thread.",
  X: "Dead.",
};
const TYPES = {
  cpu_hog: "CPU hog", memory_leak: "Memory leak", fork_bomb: "Fork bomb", zombie: "Zombies",
  thread_explosion: "Thread explosion", context_switching: "Context switching", unusual_behaviour: "Unusual",
};
const SEVERITY = {
  fork_bomb: "critical", memory_leak: "critical", cpu_hog: "warning", thread_explosion: "warning",
  zombie: "warning", context_switching: "warning", unusual_behaviour: "info",
};
const LAYERS = { rule: "Rules", ewma: "EWMA z-score", iforest: "Isolation Forest" };
const MODEL_NAME = { claude: "Claude", ollama: "local model (Ollama)", external: "Claude (external session)" };
const COLS = [
  { k: "pid", t: "PID" }, { k: "name", t: "Name", l: 1 }, { k: "user", t: "User", l: 1 },
  { k: "state", t: "State" }, { k: "cpu", t: "CPU %" }, { k: "rss_kb", t: "Memory" },
  { k: "threads", t: "Threads" }, { k: "ctx_rate", t: "Switches/s" }, { k: "nice", t: "Nice" },
  { k: "ml", t: "Outlier", title: "Isolation Forest outlier score: higher is more unusual" },
];
const ACTION_TEXT = {
  renice: (n, v) => ({ title: `Renice ${n} to ${v}?`, ok: "Renice", body: "Calls setpriority(). A higher nice value gives the process a smaller share of CPU time from the scheduler. Setting a value lower than the current one needs root.", done: `Reniced ${n} to ${v}` }),
  stop: (n) => ({ title: `Pause ${n}?`, ok: "Pause process", body: "Sends SIGSTOP. The kernel stops scheduling it (state T) until it receives SIGCONT. Its memory and open files are kept.", done: `Paused ${n}` }),
  cont: (n) => ({ title: `Resume ${n}?`, ok: "Resume process", body: "Sends SIGCONT. The process becomes runnable again and continues where it stopped.", done: `Resumed ${n}` }),
  term: (n) => ({ title: `Terminate ${n}?`, ok: "Terminate process", danger: true, body: "Sends SIGTERM, asking the process to exit. Any unsaved work inside it is lost. ProcSentinel never does this on its own.", done: `Sent SIGTERM to ${n}` }),
};

let S = null;
let cpuMode = "core";   // "core": 100% = one core (Linux, top). "total": 100% = all cores (Task Manager)
const cpuOf = (v) => (cpuMode === "total" && S?.ncpu ? v / S.ncpu : v);
let sel = null;
let sort = { key: "cpu", dir: -1 };
let openAlert = null, openSig = "";
const seen = new Set();
let firstLoad = true;

// ---------------- helpers ----------------
function fmtMem(kb) {
  if (kb >= 1048576) return (kb / 1048576).toFixed(1) + " GB";
  if (kb >= 1024) return (kb / 1024).toFixed(kb >= 102400 ? 0 : 1) + " MB";
  return kb + " KB";
}
function fmtNum(n, d = 0) {
  if (n == null || Number.isNaN(n)) return "–";
  if (Math.abs(n) >= 10000) return (n / 1000).toFixed(0) + "k";
  return Number(n).toLocaleString(undefined, { maximumFractionDigits: d });
}
function ago(ts) {
  const s = Math.max(0, (S?.now ?? Date.now() / 1000) - ts);
  if (s < 60) return `${Math.round(s)} s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  return new Date(ts * 1000).toLocaleTimeString();
}
function outlier(ml) { return ml == null ? null : -ml; }   // score_samples is negative; flip so higher = stranger

function spark(values, { max, min = 0, w = 200, h = 40, fill = true } = {}) {
  if (!values.length) return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"></svg>`;
  const top = Math.max(...values);
  const hi = (max != null ? Math.max(max, top) : top * 1.25) || 1;   // headroom so flat lines don't fill the box
  const n = Math.max(values.length, 60);
  const off = n - values.length;
  const pts = values.map((v, i) => [((off + i) / (n - 1)) * w, h - 2 - ((v - min) / (hi - min || 1)) * (h - 4)]);
  const line = pts.map((p) => p[0].toFixed(1) + "," + p[1].toFixed(1)).join(" ");
  const area = fill ? `<polygon class="trace-fill" points="${pts[0][0].toFixed(1)},${h} ${line} ${w},${h}"/>` : "";
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true">${area}<polyline class="trace-line" points="${line}"/></svg>`;
}

function toast(msg, err = false) {
  const t = document.createElement("div");
  t.className = "toast" + (err ? " err" : "");
  t.textContent = msg;
  $("#toasts").append(t);
  setTimeout(() => t.remove(), 4200);
}

async function post(path, body) {
  try {
    const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
    return await r.json();
  } catch (e) {
    return { ok: false, message: "Engine unreachable. Is it still running?" };
  }
}

// ---------------- confirm + actions ----------------
function confirmBox({ title, body, ok, danger }) {
  const d = $("#confirmDlg");
  d.innerHTML = `<form method="dialog" class="inner"><h2>${esc(title)}</h2><p>${esc(body)}</p>
    <div class="row"><button class="btn" value="cancel">Cancel</button>
    <button class="btn ${danger ? "danger solid" : "primary"}" value="ok">${esc(ok)}</button></div></form>`;
  d.showModal();
  d.querySelector('[value="ok"]').focus();
  return new Promise((res) => d.addEventListener("close", () => res(d.returnValue === "ok"), { once: true }));
}

async function act(pid, name, action, value, alertId) {
  const t = ACTION_TEXT[action](name, value);
  if (!(await confirmBox(t))) return;
  const r = await post("/api/action", { pid, action, value, alert_id: alertId ?? null });
  toast(r.ok ? t.done : r.message, !r.ok);
  poll(true);
}

// ---------------- header ----------------
function renderTop() {
  const st = $("#status");
  const live = S && S.connected && S.ts && S.now - S.ts < 4;
  st.className = "status " + (live ? "live" : "down");
  st.textContent = live ? `Live, sampling every ${(S.interval_ms / 1000).toFixed(1)} s` : S ? "Waiting for the collector" : "Engine unreachable";
  const b = $("#banner");
  b.hidden = !!live;
  if (!live) b.textContent = S
    ? "The collector is not sending data. Start everything with ./run.sh, or start the collector so it can reach the engine's socket."
    : "Cannot reach the ProcSentinel engine. Start it with ./run.sh and reload this page.";

  const h = S?.sys_hist ?? [];
  const sys = S?.sys;
  const memUsed = sys ? (sys.mem_total_kb - sys.mem_avail_kb) : 0;
  const v = [
    { label: "CPU", val: sys ? sys.cpu.toFixed(0) : "–", unit: "%", data: h.map((r) => r[1]), max: 100 },
    { label: "Memory", val: sys ? (100 * memUsed / sys.mem_total_kb).toFixed(0) : "–", unit: sys ? `% of ${fmtMem(sys.mem_total_kb)}` : "%", data: h.map((r) => r[2]), max: 100 },
    { label: `Load, ${S?.ncpu ?? "?"} CPUs`, val: sys ? sys.load[0].toFixed(2) : "–", unit: "", data: h.map((r) => r[3]), max: S?.ncpu || 1 },
    { label: "Context switches", val: sys ? fmtNum(sys.ctxt_rate) : "–", unit: "/s", data: h.map((r) => r[4]) },
    { label: "Forks", val: sys ? fmtNum(sys.fork_rate, 1) : "–", unit: "/s", data: h.map((r) => r[5]), max: 5 },
  ];
  $("#vitals").innerHTML = v.map((x) => `<div class="vital"><div class="row"><span class="label">${esc(x.label)}</span>
    <span class="val">${x.val}<small>${esc(x.unit)}</small></span></div>${spark(x.data.slice(-90), { max: x.max })}</div>`).join("");

  const c = S?.collector, e = S?.engine;
  $("#overhead").innerHTML = c && c.cpu != null
    ? `Collector <b>${c.cpu.toFixed(1)}%</b> CPU, avg ${c.cpu_avg?.toFixed(2) ?? "–"}%<br>Engine <b>${e.cpu?.toFixed(1) ?? "–"}%</b> CPU, ${fmtMem(e.rss_kb ?? 0)}`
    : "";
}

function renderLayers() {
  if (!S) return ($("#layers").innerHTML = "");
  const L = S.layers;
  const ml = L.iforest;
  let mlHtml;
  if (ml.status === "collecting") mlHtml = `<span class="dot wait"></span><b>Isolation Forest</b> learning normal behaviour <span class="bar"><i style="width:${Math.round(ml.progress * 100)}%"></i></span>`;
  else if (ml.status === "training") mlHtml = `<span class="dot wait"></span><b>Isolation Forest</b> training…`;
  else if (ml.status === "ready") mlHtml = `<span class="dot"></span><b>Isolation Forest</b> trained on ${fmtNum(ml.samples)} samples <button id="retrain" title="Collect a fresh baseline of normal behaviour">Retrain</button>`;
  else mlHtml = `<span class="dot off"></span><b>Isolation Forest</b> off: ${esc(ml.message)}`;
  const llm = L.llm;
  const llmHtml = llm.mode === "off"
    ? `<span class="dot off"></span><b>AI explanations</b> off, using offline templates${llm.error ? ": " + esc(llm.error) : ""}`
    : `<span class="dot${llm.error ? " wait" : ""}"></span><b>AI explanations</b> ${MODEL_NAME[llm.mode]}${llm.error ? ": " + esc(llm.error) : ""}`;
  const envNote = S.env === "wsl"
    ? `<span class="dot off"></span><b>Inside the WSL2 Linux VM</b> Windows Task Manager shows this whole VM as one VmmemWSL process`
    : S.env === "vm" ? `<span class="dot off"></span><b>Inside a virtual machine</b> readings cover this VM only` : null;
  $("#layers").innerHTML = [
    `<span class="dot"></span><b>Rules</b> thresholds from the test plan`,
    `<span class="dot"></span><b>EWMA z-score</b> α 0.1, flags |z| above 3`,
    mlHtml, llmHtml, envNote,
  ].filter(Boolean).map((x) => `<div class="layer">${x}</div>`).join("");
  $("#retrain")?.addEventListener("click", async () => {
    if (await confirmBox({ title: "Retrain the Isolation Forest?", ok: "Retrain", body: "ProcSentinel will record about a minute of current activity as the new normal baseline. Stop any test workloads first so they are not learned as normal." })) {
      const r = await post("/api/ml/retrain");
      toast(r.message, !r.ok);
    }
  });
}

// ---------------- process table ----------------
function procSeverity(p) {
  const sev = p.alerts.map((t) => SEVERITY[t]);
  return sev.includes("critical") ? "critical" : sev.includes("warning") ? "warning" : sev.length ? "info" : "";
}

function renderHead() {
  $("#thead").innerHTML = COLS.map((c) => `<th class="${c.l ? "l" : ""}" ${sort.key === c.k ? `aria-sort="${sort.dir < 0 ? "descending" : "ascending"}"` : ""}
    ${c.title ? `title="${esc(c.title)}"` : ""}><button data-k="${c.k}">${c.t}</button></th>`).join("");
}

let view = "list";
const treeOpen = new Map();   // pid -> expanded? (user overrides; default: collapse parents of > 20 children)

function treeRows(rows) {
  // Depth-first order of the fork() hierarchy. Filtered views keep each match's ancestors.
  const all = new Map(S.procs.map((p) => [p.pid, p]));
  const keep = new Map(rows.map((p) => [p.pid, p]));
  for (const p of rows) {
    for (let a = all.get(p.ppid); a && !keep.has(a.pid); a = all.get(a.ppid)) keep.set(a.pid, a);
  }
  const kids = new Map();
  for (const p of keep.values()) {
    const parent = keep.has(p.ppid) ? p.ppid : 0;
    if (!kids.has(parent)) kids.set(parent, []);
    kids.get(parent).push(p);
  }
  for (const list of kids.values()) list.sort((a, b) => a.pid - b.pid);
  const out = [];
  const walk = (pid, depth) => {
    for (const p of kids.get(pid) || []) {
      const n = (kids.get(p.pid) || []).length;
      const open = treeOpen.has(p.pid) ? treeOpen.get(p.pid) : n <= 20;
      out.push({ p, depth, n, open });
      if (open) walk(p.pid, depth + 1);
    }
  };
  walk(0, 0);
  return out;
}

function renderTable() {
  if (!S) return;
  const q = $("#search").value.trim().toLowerCase();
  const hideK = $("#hideK").checked, flagged = $("#onlyFlagged").checked;
  let rows = S.procs.filter((p) => (!hideK || !p.kthread) && (!flagged || p.alerts.length) &&
    (!q || p.name.toLowerCase().includes(q) || String(p.pid) === q || p.user.toLowerCase().includes(q)));
  const k = sort.key;
  rows.sort((a, b) => {
    // flagged processes float to the top so a new alert is never hidden below the fold
    const fa = a.alerts.length > 0, fb = b.alerts.length > 0;
    if (fa !== fb) return fa ? -1 : 1;
    const x = k === "ml" ? outlier(a.ml) ?? -9 : a[k], y = k === "ml" ? outlier(b.ml) ?? -9 : b[k];
    return (typeof x === "string" ? x.localeCompare(y) : x - y) * sort.dir;
  });
  $("#procCount").textContent = `${rows.length} of ${S.procs.length}`;
  const items = view === "tree" ? treeRows(rows) : rows.map((p) => ({ p }));
  const thr = S.layers.iforest.threshold;
  const hot = 90;
  $("#tbody").innerHTML = items.slice(0, 500).map(({ p, depth, n, open }) => {
    const sev = procSeverity(p);
    const o = outlier(p.ml);
    const odd = thr != null && p.ml != null && p.ml < thr;
    const name = esc(p.name) + p.alerts.map((t) => `<span class="tag ${SEVERITY[t]}">${TYPES[t]}</span>`).join("");
    const nameCell = view === "tree"
      ? `<span class="tree" style="padding-left:${depth * 16}px">${n
          ? `<button class="twisty" data-twisty="${p.pid}" aria-expanded="${open}" aria-label="${open ? "Collapse" : "Expand"} children of ${esc(p.name)}">${open ? "▾" : "▸"}</button>`
          : `<span class="leaf">·</span>`}${name}${n && !open ? `<span class="kids">${n} children</span>` : ""}</span>`
      : name;
    return `<tr data-pid="${p.pid}" class="${p.pid === sel ? "sel " : ""}${sev ? "flag-" + sev : ""}">
      <td>${p.pid}</td>
      <td class="l name" title="${esc(p.name)}">${nameCell}</td>
      <td class="l muted">${esc(p.user)}</td>
      <td><span class="state ${esc(p.state)}" title="${esc(STATES[p.state] || p.state)}">${esc(p.state)}</span></td>
      <td><span class="cpu-cell">${cpuOf(p.cpu).toFixed(1)}<i><b class="${p.cpu >= hot ? "hot" : ""}" style="width:${Math.min(100, cpuOf(p.cpu))}%"></b></i></span></td>
      <td>${fmtMem(p.rss_kb)}</td>
      <td>${p.threads}</td>
      <td>${fmtNum(p.ctx_rate)}</td>
      <td class="${p.nice ? "" : "muted"}">${p.nice}</td>
      <td class="${odd ? "" : "muted"}" ${odd ? 'style="color:var(--critical);font-weight:600"' : ""}>${o == null ? "–" : o.toFixed(2)}</td></tr>`;
  }).join("") || `<tr><td colspan="${COLS.length}" class="empty">${S.procs.length ? "No process matches this filter." : "No data yet."}</td></tr>`;
}

// ---------------- cores, impact, actions ----------------
function renderCores() {
  const cores = S?.sys?.cores ?? [];
  const p = sel != null && S ? S.procs.find((x) => x.pid === sel) : null;
  const here = p && p.core >= 0 ? p.core : -1;
  $("#coreNote").textContent = p && here >= 0
    ? `${p.name} (PID ${p.pid}) last ran on CPU ${here}. The scheduler may move it between cores.`
    : "How busy each core was over the last second, from /proc/stat. Select a process to see which core it ran on.";
  $("#cores").innerHTML = cores.map((u, i) => `<div class="core${u >= 85 ? " hot" : ""}${u >= 60 ? " heavy" : ""}${i === here ? " here" : ""}" style="--u:${u.toFixed(0)}"
    title="CPU ${i}: ${u.toFixed(0)}% busy"><b>${u.toFixed(0)}%</b><span>CPU ${i}</span></div>`).join("");
}

function fmtDur(s) {
  if (s < 60) return `${s.toFixed(0)} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
  return `${(s / 3600).toFixed(1)} h`;
}

function renderImpact() {
  const m = S?.impact;
  if (!m) return ($("#impact").innerHTML = "");
  const wh = m.wh < 1 ? `${(m.wh * 1000).toFixed(0)} mWh` : `${m.wh.toFixed(2)} Wh`;
  $("#impact").innerHTML = `<h2>Reclaimed by your actions</h2>
    <div class="nums">
      <div class="num"><b>${fmtDur(m.cpu_s)}</b><span>CPU time</span></div>
      <div class="num"><b>${fmtMem(m.mem_kb)}</b><span>Memory freed</span></div>
      <div class="num"><b>${wh}</b><span>Energy, estimated</span></div>
    </div>
    <p>CPU a paused or terminated process would otherwise have used, counted for up to 10 minutes each, at about ${m.watts_per_core} W per busy core.${m.tracking ? ` Counting ${m.tracking} process${m.tracking > 1 ? "es" : ""} now.` : ""}</p>`;
}

const VERB = { renice: "Reniced", stop: "Paused", cont: "Resumed", term: "Sent SIGTERM to" };
function renderActions() {
  const list = S?.actions ?? [];
  $("#actionCount").textContent = list.length || "";
  $("#actions").innerHTML = list.map((a) => `<li class="action-row"><span class="${a.ok ? "ok" : "bad"}">${a.ok ? "✓" : "✕"}</span>
    <div><b>${VERB[a.action] || esc(a.action)} ${esc(a.name)}</b>${a.action === "renice" && a.value != null ? ` to ${esc(a.value)}` : ""}<p>${esc(a.message)}</p></div>
    <time>${ago(a.ts)}</time></li>`).join("") || `<li class="empty">No actions yet. Renice, pause or terminate a process and it is logged here.</li>`;
}

// ---------------- selected process ----------------
function renderDetail() {
  const d = $("#detail");
  if (!S || sel == null) {
    d.innerHTML = `<p class="empty">Select a process to see its live graphs and act on it.</p>`;
    return;
  }
  const p = S.procs.find((x) => x.pid === sel);
  if (!p) {
    d.innerHTML = `<p class="empty">PID ${sel} has exited.</p>`;
    return;
  }
  const h = S.selected?.pid === sel ? S.selected.history : [];
  const prot = [1, S.collector.pid, S.engine.pid].includes(p.pid);
  const charts = [
    { label: cpuMode === "total" ? "CPU, share of all cores" : "CPU, 100% = one core", val: cpuOf(p.cpu).toFixed(1) + "%", data: h.map((r) => cpuOf(r[1])), max: 100 },
    { label: "Resident memory", val: fmtMem(p.rss_kb), data: h.map((r) => r[2]) },
    { label: "Threads", val: p.threads, data: h.map((r) => r[3]) },
    { label: "Context switches", val: fmtNum(p.ctx_rate) + "/s", data: h.map((r) => r[4]) },
  ];
  const keepNice = document.activeElement?.id === "niceVal" ? document.activeElement.value : null;
  d.innerHTML = `
    <div class="detail-head">
      <div>
        <h3>${esc(p.name)}<span>PID ${p.pid}</span></h3>
        <div class="facts"><span>Parent <b>${p.ppid}</b></span><span>User <b>${esc(p.user)}</b></span>
          <span>State <span class="state ${esc(p.state)}">${esc(p.state)}</span></span><span>Nice <b>${p.nice}</b></span>
          <span>Children <b>${p.children}</b></span><span>Running for <b>${p.age_s < 120 ? Math.round(p.age_s) + " s" : Math.round(p.age_s / 60) + " min"}</b></span></div>
        <p class="state-note">${esc(STATES[p.state] || "")}${prot ? " ProcSentinel protects this process from actions." : ""}</p>
      </div>
      <div class="acts">
        <span class="renice"><input type="number" id="niceVal" min="-20" max="19" value="${keepNice ?? Math.max(p.nice, 10)}" aria-label="Nice value">
          <button class="btn" data-act="renice" ${prot ? "disabled" : ""}>Renice</button></span>
        ${p.state === "T" ? `<button class="btn" data-act="cont" ${prot ? "disabled" : ""}>Resume</button>` : `<button class="btn" data-act="stop" ${prot ? "disabled" : ""}>Pause</button>`}
        <button class="btn danger" data-act="term" ${prot ? "disabled" : ""}>Terminate</button>
      </div>
    </div>
    <div class="charts">${charts.map((c) => `<div class="chart"><div class="row"><span class="label">${c.label}</span><span class="val">${c.val}</span></div>
      ${spark(c.data, { max: c.max, w: 240, h: 70 })}<div class="axis"><span>${h.length ? Math.round(h.at(-1)[0] - h[0][0]) + " s ago" : ""}</span><span>now</span></div></div>`).join("")}</div>`;
  if (keepNice != null) $("#niceVal").focus();
  d.querySelectorAll("[data-act]").forEach((b) => b.addEventListener("click", () =>
    act(p.pid, p.name, b.dataset.act, b.dataset.act === "renice" ? Number($("#niceVal").value) : null)));
}

// ---------------- alerts ----------------
function renderAlerts() {
  if (!S) return;
  const alive = new Set(S.procs.map((p) => p.pid));
  $("#alertCount").textContent = S.alerts.length ? S.alerts.length : "";
  const active = S.alerts.filter((a) => alive.has(a.pid) && S.now - a.ts < 600).length;
  document.title = active ? `(${active}) ProcSentinel` : "ProcSentinel";
  $("#alerts").innerHTML = S.alerts.map((a) => {
    const fresh = !firstLoad && !seen.has(a.id);
    seen.add(a.id);
    return `<li class="alert ${a.severity}${fresh ? " fresh" : ""}" data-id="${a.id}" tabindex="0">
      <span class="sev"></span><div>
      <h3><span>${esc(a.title)}</span><time>${ago(a.ts)}</time></h3>
      <p>${esc(a.name)}, PID ${a.pid}${alive.has(a.pid) ? "" : ' <span class="gone">(exited)</span>'}</p>
      <div class="chips">${Object.keys(LAYERS).map((l) => `<span class="chip ${a.layers[l] != null ? "on" : ""}">${LAYERS[l]}</span>`).join("")}</div>
      </div></li>`;
  }).join("") || `<li class="empty">No anomalies so far. Start a test workload below to see detection in action.</li>`;
  firstLoad = false;
  if (openAlert != null) renderDrawer();
}

function metricList(metrics) {
  const out = [];
  const names = { cpu: "CPU %", seconds: "Sustained (s)", ctx_rate: "Switches/s", vctx: "Voluntary switches", nvctx: "Involuntary switches",
    zombies: "Zombie children", spawned: "Children spawned", window_s: "Window (s)", children: "Live children", threads: "Threads",
    growth: "Thread growth", rss_mb: "RSS (MB)", slope_mb_s: "Growth (MB/s)", r2: "Linear fit R²", window: "Samples", z: "z-score",
    mean: "EWMA mean", rss_rate_mb: "RSS growth (MB/s)", score: "IF score", threshold: "IF threshold" };
  for (const [layer, m] of Object.entries(metrics)) {
    for (const [k, v] of Object.entries(m)) {
      if (k === "unusual" && Array.isArray(v)) {
        const feat = { cpu: "CPU %", rss_rate_mb: "RSS growth MB/s", threads: "Threads", ctx_rate: "Switches/s", children: "Children" };
        v.forEach((u) => out.push([`${feat[u.feature] || u.feature}, now vs normal max`, `${fmtNum(u.value, 1)} vs ${fmtNum(u.normal_p99, 1)}`]));
      } else if (k === "zombie_pids") out.push(["Zombie PIDs", v.join(", ")]);
      else if (typeof v === "number") out.push([`${names[k] || k}${layer === "rule" ? "" : ` (${LAYERS[layer]})`}`, fmtNum(v, 2)]);
    }
  }
  return out.map(([k, v]) => `<div class="metric"><span>${esc(k)}</span><b>${esc(v)}</b></div>`).join("");
}

function renderDrawer() {
  const a = S?.alerts.find((x) => x.id === openAlert);
  const d = $("#alertDlg");
  if (!a) return;
  const alive = S.procs.some((p) => p.pid === a.pid);
  const sig = JSON.stringify([a.layers, a.ai_status, a.ai_explanation, alive]);
  if (sig === openSig && d.open) return;
  openSig = sig;
  const llm = S.layers.llm;
  let ai;
  if (a.ai_status === "pending") ai = `<p class="prose">Asking ${MODEL_NAME[llm.mode]} for an explanation…</p>`;
  else if (a.ai_status === "done") ai = `<p class="prose">${esc(a.ai_explanation)}</p>`;
  else if (a.ai_status) ai = `<p class="prose">No AI explanation is available for this alert. The explanation above is complete on its own.</p>`;
  else ai = `<p class="prose">AI explanations are off. Start the engine with PROCSENTINEL_LLM=claude (or ollama) to add one to each alert.</p>`;
  const actions = (a.actions || []).map((x) => x === "renice"
    ? `<button class="btn" data-act="renice" data-v="19" ${alive ? "" : "disabled"}>Renice to 19</button>`
    : x === "stop" ? `<button class="btn" data-act="stop" ${alive ? "" : "disabled"}>Pause</button>`
    : `<button class="btn danger" data-act="term" ${alive ? "" : "disabled"}>Terminate</button>`).join("");
  d.innerHTML = `<div class="inner">
    <header><div><h2>${esc(a.title)} <span class="tag ${a.severity}">${a.severity}</span></h2>
      <p class="sub">${esc(a.name)}, PID ${a.pid}, detected ${new Date(a.ts * 1000).toLocaleTimeString()}${alive ? "" : ". The process has exited."}</p></div>
      <button class="icon-btn" id="closeDrawer" aria-label="Close"><svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" stroke-width="2" fill="none"/></svg></button></header>
    <div><span class="concept">OS concept: ${esc(a.concept)}</span></div>
    <section><h3>What is happening</h3><p class="prose">${esc(a.explanation)}</p></section>
    <section><h3>Suggested action</h3><p class="prose">${esc(a.suggestion)}</p></section>
    <section class="ai"><h3>AI explanation (advisory)</h3>${ai}</section>
    <section><h3>Detected by</h3><ol class="timeline">${Object.entries(LAYERS).map(([k, n]) => a.layers[k] != null
      ? `<li><b>${n}</b><span>${a.layers[k] - a.ts < 0.05 ? "first to detect" : `+${(a.layers[k] - a.ts).toFixed(1)} s later`}</span></li>`
      : `<li class="miss"><b>${n}</b><span>not triggered</span></li>`).join("")}</ol></section>
    <section><h3>Evidence</h3><div class="metrics">${metricList(a.metrics)}</div></section>
    <div class="acts">${actions}<button class="btn" id="showProc" ${alive ? "" : "disabled"}>Show in process table</button></div>
  </div>`;
  if (!d.open) d.showModal();
  $("#closeDrawer").addEventListener("click", () => d.close());
  $("#showProc").addEventListener("click", () => { sel = a.pid; d.close(); poll(true); });
  d.querySelectorAll("[data-act]").forEach((b) => b.addEventListener("click", () =>
    act(a.pid, a.name, b.dataset.act, b.dataset.v ? Number(b.dataset.v) : null, a.id)));
}

// ---------------- workloads ----------------
function renderWorkloads() {
  if (!S) return;
  $("#workloads").innerHTML = S.workloads.map((w) => `<li class="wl"><span class="id">${w.test}</span>
    <div><b>${esc(w.label)}</b><p>${esc(w.desc)}</p>${w.running.length ? `<span class="running">Running as PID ${w.running.map((r) => r.pid).join(", ")}</span>` : ""}</div>
    ${w.running.length ? `<button class="btn" data-stop="${w.id}">Stop</button>`
      : `<button class="btn primary" data-start="${w.id}" ${w.available ? "" : 'disabled title="Build the workloads first: make -C workloads"'}>Start</button>`}</li>`).join("");
}

// ---------------- polling ----------------
let timer = null, inflight = false;
async function poll(now = false) {
  clearTimeout(timer);
  if (inflight && !now) return;
  inflight = true;
  try {
    const r = await fetch("/api/state" + (sel != null ? `?pid=${sel}` : ""), { cache: "no-store" });
    S = await r.json();
  } catch (e) {
    S = null;
  }
  inflight = false;
  renderTop(); renderLayers(); renderCores(); renderImpact(); renderTable(); renderDetail(); renderAlerts(); renderActions(); renderWorkloads();
  timer = setTimeout(poll, 1000);
}

// ---------------- events ----------------
$("#thead").addEventListener("click", (e) => {
  const k = e.target.closest("button")?.dataset.k;
  if (!k) return;
  sort = sort.key === k ? { key: k, dir: -sort.dir } : { key: k, dir: ["name", "user", "state"].includes(k) ? 1 : -1 };
  renderHead(); renderTable();
});
function setCpuMode(m) {
  cpuMode = m;
  document.querySelectorAll("[data-cpu]").forEach((x) => x.setAttribute("aria-pressed", String(x.dataset.cpu === m)));
  try { localStorage.setItem("ps-cpu", m); } catch (e) { /* storage unavailable */ }
  renderTable(); renderDetail();
}
document.querySelectorAll("[data-cpu]").forEach((b) => b.addEventListener("click", () => setCpuMode(b.dataset.cpu)));
try { if (localStorage.getItem("ps-cpu") === "total") setCpuMode("total"); } catch (e) { /* storage unavailable */ }
document.querySelectorAll("[data-view]").forEach((b) => b.addEventListener("click", () => {
  view = b.dataset.view;
  document.querySelectorAll("[data-view]").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
  renderTable();
}));
document.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll("[data-tab]").forEach((x) => x.setAttribute("aria-selected", String(x === b)));
  $("#alerts").hidden = b.dataset.tab !== "alerts";
  $("#actions").hidden = b.dataset.tab !== "actions";
}));
$("#tbody").addEventListener("click", (e) => {
  const tw = e.target.closest("[data-twisty]");
  if (tw) {
    treeOpen.set(Number(tw.dataset.twisty), tw.getAttribute("aria-expanded") !== "true");
    return renderTable();
  }
  const tr = e.target.closest("tr[data-pid]");
  if (!tr) return;
  sel = Number(tr.dataset.pid);
  renderTable(); poll(true);
});
["#search", "#hideK", "#onlyFlagged"].forEach((s) => $(s).addEventListener("input", renderTable));
$("#alerts").addEventListener("click", (e) => {
  const li = e.target.closest("[data-id]");
  if (li) { openAlert = Number(li.dataset.id); openSig = ""; renderDrawer(); }
});
$("#alerts").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && e.target.dataset.id) { openAlert = Number(e.target.dataset.id); openSig = ""; renderDrawer(); }
});
$("#alertDlg").addEventListener("close", () => { openAlert = null; });
$("#alertDlg").addEventListener("click", (e) => { if (e.target === $("#alertDlg")) $("#alertDlg").close(); });
$("#workloads").addEventListener("click", async (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  if (b.dataset.start) {
    b.disabled = true;
    const r = await post("/api/workload/start", { id: b.dataset.start });
    toast(r.message, !r.ok);
    if (r.ok) sel = r.pid;
  } else if (b.dataset.stop) {
    const r = await post("/api/workload/stop", { id: b.dataset.stop });
    toast(r.message, !r.ok);
  }
  poll(true);
});
$("#stopAll").addEventListener("click", async () => { const r = await post("/api/workload/stop", {}); toast(r.message, !r.ok); poll(true); });
$("#clearAlerts").addEventListener("click", async () => {
  if (await confirmBox({ title: "Clear the alert log?", ok: "Clear log", danger: true, body: "This deletes every stored alert and action from the SQLite log. Detection keeps running." })) {
    const r = await post("/api/alerts/clear");
    toast(r.ok ? "Log cleared" : r.message, !r.ok);
    poll(true);
  }
});
$("#themeBtn").addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("ps-theme", document.documentElement.dataset.theme); } catch (e) { /* storage unavailable */ }
});
try { const t = localStorage.getItem("ps-theme"); if (t) document.documentElement.dataset.theme = t; } catch (e) { /* storage unavailable */ }

// ?pid=123 preselects a process, ?alert=7 opens an alert (handy for bookmarks and screenshots)
const qs = new URLSearchParams(location.search);
if (qs.get("pid")) sel = Number(qs.get("pid"));
if (qs.get("alert")) openAlert = Number(qs.get("alert"));
if (qs.get("view") === "tree") document.querySelector('[data-view="tree"]').click();
renderHead();
poll();
