// ProcSentinel collector daemon (Module 1 + Module 2).
// Samples /proc every interval, computes per-process deltas and streams one JSON
// line per snapshot to the analysis engine over a UNIX domain socket.
//
// Producer-consumer: the sampler thread never blocks on the socket. It drops the
// newest snapshot into a single-slot mailbox; a sender thread writes it out. If the
// engine is slow, older snapshots are overwritten instead of delaying sampling.

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

static std::atomic<bool> g_running{true};

struct ProcSample {
    int pid = 0, ppid = 0, threads = 0, nice = 0, uid = -1, core = -1;
    char state = '?';
    std::string name;
    unsigned long long cpu_ticks = 0, start_time = 0;
    long rss_kb = 0;
    unsigned long long vctx = 0, nvctx = 0;
};

struct Prev {
    unsigned long long cpu_ticks, start_time, ctx;
    long rss_kb;
};

static bool read_file(const std::string &path, std::string &out) {
    std::ifstream f(path);
    if (!f) return false;
    std::stringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

// /proc/[pid]/stat: "pid (comm) state ppid ..." -- comm may contain spaces and ')'.
static bool parse_stat(int pid, ProcSample &p) {
    std::string s;
    if (!read_file("/proc/" + std::to_string(pid) + "/stat", s)) return false;
    size_t l = s.find('('), r = s.rfind(')');
    if (l == std::string::npos || r == std::string::npos || r + 2 >= s.size()) return false;
    p.pid = pid;
    p.name = s.substr(l + 1, r - l - 1);
    std::istringstream in(s.substr(r + 2));
    std::vector<std::string> f;
    std::string tok;
    while (in >> tok) f.push_back(tok);
    // f[0]=state(3) f[1]=ppid(4) f[11]=utime(14) f[12]=stime(15) f[16]=nice(19)
    // f[17]=num_threads(20) f[19]=starttime(22)
    if (f.size() < 20) return false;
    p.state = f[0][0];
    p.ppid = std::atoi(f[1].c_str());
    p.cpu_ticks = std::strtoull(f[11].c_str(), nullptr, 10) + std::strtoull(f[12].c_str(), nullptr, 10);
    p.nice = std::atoi(f[16].c_str());
    p.threads = std::atoi(f[17].c_str());
    p.start_time = std::strtoull(f[19].c_str(), nullptr, 10);
    if (f.size() > 36) p.core = std::atoi(f[36].c_str());  // field 39: CPU it last ran on
    return true;
}

static void parse_status(int pid, ProcSample &p) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("Uid:", 0) == 0) p.uid = std::atoi(line.c_str() + 4);
        else if (line.rfind("voluntary_ctxt_switches:", 0) == 0) p.vctx = std::strtoull(line.c_str() + 24, nullptr, 10);
        else if (line.rfind("nonvoluntary_ctxt_switches:", 0) == 0) p.nvctx = std::strtoull(line.c_str() + 27, nullptr, 10);
    }
}

static void parse_statm(int pid, ProcSample &p, long page_kb) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/statm");
    long size = 0, resident = 0;
    if (f >> size >> resident) p.rss_kb = resident * page_kb;
}

struct CpuTimes {
    unsigned long long total = 0, idle = 0, ctxt = 0, forks = 0;
    std::vector<std::pair<unsigned long long, unsigned long long>> cores;  // per-core (total, idle)
};

static CpuTimes read_proc_stat() {
    CpuTimes c;
    std::ifstream f("/proc/stat");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("cpu", 0) == 0) {
            // "cpu " is the aggregate, "cpuN " one core. Fields: user nice system idle iowait
            // irq softirq steal (guest time is already included in user).
            size_t sp = line.find(' ');
            std::istringstream in(line.substr(sp));
            unsigned long long v[8] = {0}, total = 0;
            for (int i = 0; i < 8 && in >> v[i]; i++) {}
            for (int i = 0; i < 8; i++) total += v[i];
            if (sp == 3) { c.total = total; c.idle = v[3] + v[4]; }
            else c.cores.emplace_back(total, v[3] + v[4]);
        } else if (line.rfind("ctxt ", 0) == 0) c.ctxt = std::strtoull(line.c_str() + 5, nullptr, 10);
        else if (line.rfind("processes ", 0) == 0) c.forks = std::strtoull(line.c_str() + 10, nullptr, 10);
    }
    return c;
}

static void read_meminfo(long &total_kb, long &avail_kb) {
    std::ifstream f("/proc/meminfo");
    std::string key;
    long val;
    std::string unit;
    total_kb = avail_kb = 0;
    while (f >> key >> val) {
        std::getline(f, unit);
        if (key == "MemTotal:") total_kb = val;
        else if (key == "MemAvailable:") avail_kb = val;
    }
}

static void json_str(std::string &out, const std::string &s) {
    out += '"';
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += (char)c; }
        else if (c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); out += b; }
        else out += (char)c;
    }
    out += '"';
}

// ---- single-slot mailbox between sampler (producer) and sender (consumer) ----
static std::mutex g_mu;
static std::condition_variable g_cv;
static std::string g_slot;
static bool g_has = false;
static std::atomic<unsigned long> g_dropped{0};

static void publish(std::string &&line) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_has) g_dropped++;
    g_slot = std::move(line);
    g_has = true;
    g_cv.notify_one();
}

static int connect_socket(const std::string &path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    if (connect(fd, (sockaddr *)&addr, sizeof addr) < 0) { close(fd); return -1; }
    return fd;
}

static void sender(const std::string &path, bool to_stdout) {
    int fd = -1;
    for (;;) {
        std::string line;
        {
            std::unique_lock<std::mutex> lk(g_mu);
            g_cv.wait_for(lk, std::chrono::milliseconds(500), [] { return g_has || !g_running; });
            if (!g_has) {
                if (!g_running) break;
                continue;
            }
            line.swap(g_slot);
            g_has = false;
        }
        if (to_stdout) { std::fwrite(line.data(), 1, line.size(), stdout); std::fflush(stdout); continue; }
        if (fd < 0) {
            fd = connect_socket(path);
            if (fd < 0) continue;  // engine not up yet; this snapshot is dropped
            std::fprintf(stderr, "[collector] connected to %s\n", path.c_str());
        }
        size_t off = 0;
        while (off < line.size()) {
            ssize_t n = send(fd, line.data() + off, line.size() - off, MSG_NOSIGNAL);
            if (n <= 0) { close(fd); fd = -1; std::fprintf(stderr, "[collector] engine disconnected\n"); break; }
            off += (size_t)n;
        }
    }
    if (fd >= 0) close(fd);
}

int main(int argc, char **argv) {
    int interval_ms = 1000;
    std::string sock = "/tmp/procsentinel.sock";
    bool to_stdout = false, once = false;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--interval" && i + 1 < argc) interval_ms = std::max(100, std::atoi(argv[++i]));
        else if (a == "--socket" && i + 1 < argc) sock = argv[++i];
        else if (a == "--stdout") to_stdout = true;
        else if (a == "--once") { to_stdout = true; once = true; }
        else { std::fprintf(stderr, "usage: %s [--interval ms] [--socket path] [--stdout] [--once]\n", argv[0]); return 2; }
    }
    signal(SIGINT, [](int) { g_running = false; g_cv.notify_all(); });
    signal(SIGTERM, [](int) { g_running = false; g_cv.notify_all(); });
    signal(SIGPIPE, SIG_IGN);

    const long page_kb = sysconf(_SC_PAGESIZE) / 1024;
    const long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    const long hz = sysconf(_SC_CLK_TCK);
    std::thread tx(sender, sock, to_stdout);

    std::unordered_map<int, Prev> prev;
    CpuTimes prev_cpu = read_proc_stat();
    auto prev_t = std::chrono::steady_clock::now();
    bool first = true;

    while (g_running) {
        auto tick_start = std::chrono::steady_clock::now();
        CpuTimes cpu = read_proc_stat();
        double dt = std::chrono::duration<double>(tick_start - prev_t).count();
        if (dt <= 0) dt = interval_ms / 1000.0;
        double dtotal = (double)(cpu.total - prev_cpu.total);

        std::vector<ProcSample> procs;
        DIR *d = opendir("/proc");
        if (!d) { std::perror("opendir /proc"); return 1; }
        while (dirent *e = readdir(d)) {
            if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
            ProcSample p;
            // A process may exit between readdir() and our reads: just skip it.
            if (!parse_stat(std::atoi(e->d_name), p)) continue;
            parse_status(p.pid, p);
            parse_statm(p.pid, p, page_kb);
            procs.push_back(std::move(p));
        }
        closedir(d);

        // New children per parent since the previous sample (fork-rate signal).
        std::unordered_map<int, int> new_children;
        if (!first)
            for (auto &p : procs) {
                auto it = prev.find(p.pid);
                if (it == prev.end() || it->second.start_time != p.start_time) new_children[p.ppid]++;
            }

        long mem_total, mem_avail;
        read_meminfo(mem_total, mem_avail);
        double load[3] = {0, 0, 0};
        if (FILE *lf = std::fopen("/proc/loadavg", "r")) {
            if (std::fscanf(lf, "%lf %lf %lf", &load[0], &load[1], &load[2]) != 3) load[0] = load[1] = load[2] = 0;
            std::fclose(lf);
        }
        double uptime = 0;
        if (FILE *uf = std::fopen("/proc/uptime", "r")) {
            if (std::fscanf(uf, "%lf", &uptime) != 1) uptime = 0;
            std::fclose(uf);
        }
        double sys_cpu = dtotal > 0 ? 100.0 * (dtotal - (double)(cpu.idle - prev_cpu.idle)) / dtotal : 0;

        std::string out;
        out.reserve(procs.size() * 200 + 512);
        char buf[512];
        std::snprintf(buf, sizeof buf,
                      "{\"ts\":%.3f,\"interval_ms\":%d,\"ncpu\":%ld,\"collector_pid\":%d,\"dropped\":%lu,"
                      "\"sys\":{\"cpu\":%.2f,\"mem_total_kb\":%ld,\"mem_avail_kb\":%ld,\"load\":[%.2f,%.2f,%.2f],"
                      "\"ctxt_rate\":%.1f,\"fork_rate\":%.1f,\"nprocs\":%zu,\"cores\":[",
                      std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count(),
                      interval_ms, ncpu, (int)getpid(), g_dropped.load(), first ? 0.0 : sys_cpu, mem_total, mem_avail,
                      load[0], load[1], load[2], first ? 0.0 : (cpu.ctxt - prev_cpu.ctxt) / dt,
                      first ? 0.0 : (cpu.forks - prev_cpu.forks) / dt, procs.size());
        out += buf;
        for (size_t i = 0; i < cpu.cores.size(); i++) {
            double pct = 0;
            if (!first && i < prev_cpu.cores.size()) {
                double dt_c = (double)(cpu.cores[i].first - prev_cpu.cores[i].first);
                double di_c = (double)(cpu.cores[i].second - prev_cpu.cores[i].second);
                if (dt_c > 0) pct = 100.0 * (dt_c - di_c) / dt_c;
            }
            std::snprintf(buf, sizeof buf, "%s%.1f", i ? "," : "", pct);
            out += buf;
        }
        out += "]},\"procs\":[";

        std::unordered_map<int, Prev> next;
        next.reserve(procs.size());
        bool comma = false;
        for (auto &p : procs) {
            unsigned long long ctx = p.vctx + p.nvctx;
            double cpu_pct = 0, ctx_rate = 0, rss_rate = 0;
            auto it = prev.find(p.pid);
            if (it != prev.end() && it->second.start_time == p.start_time) {
                // Equation 2.1: CPU% = d(utime+stime) / dJtotal * Ncpu * 100
                if (dtotal > 0) cpu_pct = (double)(p.cpu_ticks - it->second.cpu_ticks) / dtotal * ncpu * 100.0;
                ctx_rate = (double)(ctx - it->second.ctx) / dt;
                rss_rate = (double)(p.rss_kb - it->second.rss_kb) / dt;
            }
            next[p.pid] = {p.cpu_ticks, p.start_time, ctx, p.rss_kb};
            if (comma) out += ',';
            comma = true;
            out += "{\"pid\":" + std::to_string(p.pid) + ",\"ppid\":" + std::to_string(p.ppid) + ",\"name\":";
            json_str(out, p.name);
            auto nc = new_children.find(p.pid);
            std::snprintf(buf, sizeof buf,
                          ",\"state\":\"%c\",\"uid\":%d,\"nice\":%d,\"threads\":%d,\"cpu\":%.2f,\"rss_kb\":%ld,"
                          "\"rss_rate_kb\":%.1f,\"vctx\":%llu,\"nvctx\":%llu,\"ctx_rate\":%.1f,\"new_children\":%d,"
                          "\"start\":%llu,\"age_s\":%.1f,\"core\":%d}",
                          p.state, p.uid, p.nice, p.threads, cpu_pct, p.rss_kb, rss_rate, p.vctx, p.nvctx, ctx_rate,
                          nc == new_children.end() ? 0 : nc->second, p.start_time,
                          uptime - (double)p.start_time / hz, p.core);
            out += buf;
        }
        out += "]}\n";
        if (!(once && first)) publish(std::move(out));  // --once: skip the delta-less first sample

        prev.swap(next);
        prev_cpu = cpu;
        prev_t = tick_start;
        if (once && !first) break;
        first = false;

        auto wake = tick_start + std::chrono::milliseconds(interval_ms);
        while (g_running && std::chrono::steady_clock::now() < wake)
            std::this_thread::sleep_for(std::chrono::milliseconds(std::min(50, interval_ms)));
    }
    g_running = false;
    g_cv.notify_all();
    tx.join();
    return 0;
}
