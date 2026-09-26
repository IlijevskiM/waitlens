// waitlens - where does a process's time go when it's not running?
//
//   sudo waitlens -p <pid> [-d seconds] [--func /path/bin:symbol] [--folded out.txt]
//   sudo waitlens [options] -- ./program args...
//
// loads the BPF programs (they're embedded in the binary), points them at one
// process, waits until -d runs out / ctrl-c / the process exits, then prints:
// time breakdown, histograms, the stacks it spent the most time blocked in,
// and where it page faulted.
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "waitlens/common.h"
#include "waitlens/histogram.hpp"
#include "waitlens/symbolizer.hpp"

// the compiled BPF object, pulled in by embed_bpf.S with .incbin
extern "C" const char waitlens_bpf_obj[];
extern "C" const char waitlens_bpf_obj_end[];

namespace {

using namespace waitlens;

std::atomic<bool> g_stop{false};
bool g_verbose = false;

int libbpf_log(enum libbpf_print_level level, const char* fmt, va_list args) {
    if (level == LIBBPF_DEBUG || (level == LIBBPF_INFO && !g_verbose)) return 0;
    return std::vfprintf(stderr, fmt, args);
}

[[noreturn]] void die(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    std::fprintf(stderr, "waitlens: ");
    std::vfprintf(stderr, fmt, ap);
    std::fprintf(stderr, "\n");
    va_end(ap);
    std::exit(1);
}

struct Options {
    uint32_t pid = 0;
    double duration_s = 0;  // 0 = until Ctrl-C or exit
    std::string func;       // "/path/to/binary:symbol"
    std::string folded_path;
    int top = 8;
    uint32_t min_offcpu_us = 1;
    bool faults = true;
    std::vector<char*> command;
};

void usage(const char* argv0) {
    std::fprintf(stderr,
                 "usage: sudo %s -p PID [options]\n"
                 "       sudo %s [options] -- COMMAND [ARGS...]\n\n"
                 "options:\n"
                 "  -p PID            profile an existing process\n"
                 "  -d SECONDS        stop after this long (default: until Ctrl-C / exit)\n"
                 "  --func BIN:SYM    also measure latency of function SYM in binary BIN\n"
                 "                    (SYM may be a substring of the demangled C++ name)\n"
                 "  --folded FILE     write off-CPU stacks in folded format (flame graphs)\n"
                 "  --top N           stacks to show per section (default 8)\n"
                 "  --min-us N        ignore off-CPU blocks shorter than N us (default 1)\n"
                 "  --no-faults       skip page-fault tracking\n"
                 "  -v                verbose libbpf output\n",
                 argv0, argv0);
}

Options parse_args(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) { usage(argv[0]); std::exit(1); }
            return argv[++i];
        };
        if (a == "--") {
            for (int j = i + 1; j < argc; ++j) o.command.push_back(argv[j]);
            break;
        }
        if (a == "-p") o.pid = uint32_t(std::stoul(next()));
        else if (a == "-d") o.duration_s = std::stod(next());
        else if (a == "--func") o.func = next();
        else if (a == "--folded") o.folded_path = next();
        else if (a == "--top") o.top = std::stoi(next());
        else if (a == "--min-us") o.min_offcpu_us = uint32_t(std::stoul(next()));
        else if (a == "--no-faults") o.faults = false;
        else if (a == "-v") g_verbose = true;
        else { usage(argv[0]); std::exit(a == "-h" || a == "--help" ? 0 : 1); }
    }
    if (!o.pid && o.command.empty()) { usage(argv[0]); std::exit(1); }
    o.command.push_back(nullptr);
    return o;
}

// --- small RAII wrappers so libbpf objects get cleaned up ---

struct ObjectDeleter {
    void operator()(bpf_object* o) const { bpf_object__close(o); }
};
struct LinkDeleter {
    void operator()(bpf_link* l) const { bpf_link__destroy(l); }
};
using ObjectPtr = std::unique_ptr<bpf_object, ObjectDeleter>;
using LinkPtr = std::unique_ptr<bpf_link, LinkDeleter>;

bpf_program* find_prog(bpf_object* obj, const char* name) {
    bpf_program* p = bpf_object__find_program_by_name(obj, name);
    if (!p) die("BPF program %s not found", name);
    return p;
}

int map_fd(bpf_object* obj, const char* name) {
    bpf_map* m = bpf_object__find_map_by_name(obj, name);
    if (!m) die("BPF map %s not found", name);
    return bpf_map__fd(m);
}

// --- process stuff ---

// fork the child but make it block on a pipe until we've attached everything,
// otherwise we'd miss whatever it does at startup
struct Spawned {
    pid_t pid = 0;
    int go_fd = -1;
};

Spawned spawn_paused(std::vector<char*>& cmd) {
    int fds[2];
    if (pipe(fds) != 0) die("pipe: %s", std::strerror(errno));
    pid_t pid = fork();
    if (pid < 0) die("fork: %s", std::strerror(errno));
    if (pid == 0) {
        close(fds[1]);
        char c;
        if (read(fds[0], &c, 1) != 1) _exit(127);
        close(fds[0]);
        execvp(cmd[0], cmd.data());
        std::fprintf(stderr, "waitlens: exec %s: %s\n", cmd[0], std::strerror(errno));
        _exit(127);
    }
    close(fds[0]);
    return {pid, fds[1]};
}

std::string read_small_file(const std::string& path) {
    std::ifstream f(path);
    std::string s;
    std::getline(f, s);
    return s;
}

// utime + stime from /proc/<pid>/stat, in seconds
std::optional<double> cpu_seconds(uint32_t pid) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/stat");
    std::string s;
    if (!std::getline(f, s)) return std::nullopt;
    const size_t rp = s.rfind(')');  // comm can have spaces in it, so split after the ')'
    if (rp == std::string::npos) return std::nullopt;
    std::vector<std::string> fields;
    size_t pos = rp + 2;
    while (pos < s.size()) {
        size_t sp = s.find(' ', pos);
        fields.push_back(s.substr(pos, sp - pos));
        if (sp == std::string::npos) break;
        pos = sp + 1;
    }
    if (fields.size() < 13) return std::nullopt;
    const double hz = double(sysconf(_SC_CLK_TCK));
    return (std::stod(fields[11]) + std::stod(fields[12])) / hz;  // utime, stime
}

// can only read thread names while the process is alive, so grab them as we go
void refresh_thread_names(uint32_t pid, std::map<uint32_t, std::string>& names) {
    const std::string dir = "/proc/" + std::to_string(pid) + "/task/";
    DIR* d = opendir(dir.c_str());
    if (!d) return;
    while (dirent* e = readdir(d)) {
        const uint32_t tid = uint32_t(std::strtoul(e->d_name, nullptr, 10));
        if (tid) names[tid] = read_small_file(dir + e->d_name + "/comm");
    }
    closedir(d);
}

// --- report ---

struct Frames {
    std::vector<std::string> kernel;  // innermost first
    std::vector<std::string> user;    // innermost first
};

std::vector<uint64_t> read_stack(int stacks_fd, int32_t id) {
    std::vector<uint64_t> ips;
    if (id < 0) return ips;
    uint64_t buf[WL_MAX_STACK_DEPTH] = {};
    uint32_t key = uint32_t(id);
    if (bpf_map_lookup_elem(stacks_fd, &key, buf) != 0) return ips;
    for (uint64_t ip : buf) {
        if (!ip) break;
        ips.push_back(ip);
    }
    return ips;
}

// "f(std::vector<int, std::allocator<int> >&)" -> "f(std::vector<...>&)"
// full template args make C++ stacks basically unreadable
std::string simplify(const std::string& name) {
    std::string out;
    int depth = 0;
    for (size_t i = 0; i < name.size(); ++i) {
        const char c = name[i];
        // careful: operator< / operator<< aren't template brackets
        if (c == '<' && i >= 8 && name.compare(i - 8, 8, "operator") == 0) { out += c; continue; }
        if (c == '<') { if (depth++ == 0) out += "<...>"; continue; }
        if (c == '>' && depth > 0) { --depth; continue; }
        if (depth == 0) out += c;
    }
    return out;
}

bool is_bpf_frame(const std::string& s) {
    return s.rfind("bpf_prog_", 0) == 0 || s.rfind("bpf_trace_run", 0) == 0 ||
           s.rfind("__bpf_trace_", 0) == 0 || s.rfind("__traceiter_", 0) == 0;
}

Frames symbolize(int stacks_fd, const wl_stack_key& k, const KernelSymbols& ksyms,
                 ProcessSymbols& usyms) {
    Frames f;
    for (uint64_t ip : read_stack(stacks_fd, k.kern_stack_id)) {
        std::string s = ksyms.resolve(ip);
        if (!is_bpf_frame(s)) f.kernel.push_back(std::move(s));
    }
    for (uint64_t ip : read_stack(stacks_fd, k.user_stack_id)) f.user.push_back(simplify(usyms.resolve(ip)));
    if (k.user_stack_id < 0) f.user.push_back("[user stack unavailable]");
    return f;
}

void print_frames(const Frames& f, size_t max_frames = 12) {
    size_t shown = 0;
    for (const auto& s : f.kernel) {
        if (shown++ >= max_frames) break;
        std::printf("      %s [k]\n", s.c_str());
    }
    if (!f.kernel.empty()) std::printf("      --\n");
    for (const auto& s : f.user) {
        if (shown++ >= max_frames + 6) { std::printf("      ...\n"); break; }
        std::printf("      %s\n", s.c_str());
    }
}

template <typename V>
std::vector<std::pair<wl_stack_key, V>> dump_hash(int fd) {
    std::vector<std::pair<wl_stack_key, V>> out;
    wl_stack_key key{}, next{};
    wl_stack_key* prev = nullptr;
    while (bpf_map_get_next_key(fd, prev, &next) == 0) {
        V v{};
        if (bpf_map_lookup_elem(fd, &next, &v) == 0) out.emplace_back(next, v);
        key = next;
        prev = &key;
    }
    return out;
}

}  // namespace

int main(int argc, char** argv) {
    Options opt = parse_args(argc, argv);
    if (geteuid() != 0) die("needs root (or CAP_BPF + CAP_PERFMON): run with sudo");
    libbpf_set_print(libbpf_log);

    // ---- load BPF --------------------------------------------------------
    const size_t obj_size = size_t(waitlens_bpf_obj_end - waitlens_bpf_obj);
    ObjectPtr obj(bpf_object__open_mem(waitlens_bpf_obj, obj_size, nullptr));
    if (!obj) die("failed to open embedded BPF object");
    if (int err = bpf_object__load(obj.get())) die("failed to load BPF programs (%d); try -v", err);

    // ---- target ----------------------------------------------------------
    Spawned child;
    uint32_t target = opt.pid;
    if (!opt.command.empty() && opt.command[0]) {
        child = spawn_paused(opt.command);
        target = uint32_t(child.pid);
    }
    if (kill(pid_t(target), 0) != 0) die("no such process: %u", target);

    const uint32_t zero = 0;
    wl_config cfg{target, opt.min_offcpu_us * 1000};
    bpf_map_update_elem(map_fd(obj.get(), "cfg_map"), &zero, &cfg, BPF_ANY);

    // ---- attach ----------------------------------------------------------
    std::vector<LinkPtr> links;
    for (const char* name : {"on_sched_switch", "on_sched_wakeup", "on_sched_wakeup_new"}) {
        bpf_link* l = bpf_program__attach(find_prog(obj.get(), name));
        if (!l) die("attach %s failed", name);
        links.emplace_back(l);
    }

    if (opt.faults) {
        // one page fault perf event per cpu, every fault sampled. the BPF
        // side throws away faults from other processes
        const long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        for (long cpu = 0; cpu < ncpu; ++cpu) {
            perf_event_attr attr{};
            attr.type = PERF_TYPE_SOFTWARE;
            attr.size = sizeof attr;
            attr.config = PERF_COUNT_SW_PAGE_FAULTS;
            attr.sample_period = 1;
            const int fd = int(syscall(SYS_perf_event_open, &attr, -1, int(cpu), -1, PERF_FLAG_FD_CLOEXEC));
            if (fd < 0) {
                std::fprintf(stderr, "waitlens: page faults disabled (perf_event_open: %s)\n",
                             std::strerror(errno));
                break;
            }
            bpf_link* l = bpf_program__attach_perf_event(find_prog(obj.get(), "on_page_fault"), fd);
            if (!l) { close(fd); die("attach page-fault program failed"); }
            links.emplace_back(l);  // link owns the fd now, closes it on destroy
        }
    }

    std::string func_label;
    if (!opt.func.empty()) {
        const size_t colon = opt.func.find(':');  // first ':' since C++ names have '::' in them
        if (colon == std::string::npos) die("--func expects BINARY:SYMBOL");
        const std::string bin = opt.func.substr(0, colon), sym = opt.func.substr(colon + 1);
        auto elf = ElfFile::open(bin);
        if (!elf) die("cannot read ELF %s", bin.c_str());
        auto matches = elf->find_functions(sym);
        if (matches.empty()) die("no function matching '%s' in %s", sym.c_str(), bin.c_str());
        if (matches.size() > 1) {
            std::fprintf(stderr, "waitlens: '%s' matches %zu functions, using %s\n", sym.c_str(),
                         matches.size(), simplify(demangle(matches[0].name)).c_str());
        }
        auto off = elf->vaddr_to_file_offset(matches[0].addr);
        if (!off) die("cannot map %s to a file offset", sym.c_str());
        for (bool ret : {false, true}) {
            bpf_link* l = bpf_program__attach_uprobe(
                find_prog(obj.get(), ret ? "on_func_exit" : "on_func_entry"), ret, int(target),
                bin.c_str(), size_t(*off));
            if (!l) die("uprobe attach failed for %s", sym.c_str());
            links.emplace_back(l);
        }
        func_label = simplify(demangle(matches[0].name));
    }

    // ---- run -------------------------------------------------------------
    signal(SIGINT, [](int) { g_stop = true; });
    signal(SIGTERM, [](int) { g_stop = true; });

    ProcessSymbols usyms(target);
    std::map<uint32_t, std::string> thread_names;
    usyms.refresh();
    refresh_thread_names(target, thread_names);
    const std::optional<double> cpu0 = child.pid ? std::optional<double>(0.0) : cpu_seconds(target);
    std::optional<double> cpu1;

    const auto t0 = std::chrono::steady_clock::now();
    if (child.pid) {
        if (write(child.go_fd, "g", 1) != 1) die("failed to start child");
        close(child.go_fd);
    }
    std::fprintf(stderr, "waitlens: profiling pid %u%s%s... Ctrl-C to stop\n", target,
                 func_label.empty() ? "" : ", function ", func_label.c_str());

    int child_status = 0;
    bool child_done = false;
    while (!g_stop) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const double elapsed =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        if (opt.duration_s > 0 && elapsed >= opt.duration_s) break;
        if (child.pid) {
            rusage ru{};
            if (wait4(child.pid, &child_status, WNOHANG, &ru) == child.pid) {
                child_done = true;
                cpu1 = double(ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) +
                       double(ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) / 1e6;
                break;
            }
        } else if (kill(pid_t(target), 0) != 0) {
            break;
        }
        usyms.refresh();  // in case it loaded new libraries
        refresh_thread_names(target, thread_names);
    }
    const double wall_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    if (!cpu1) cpu1 = cpu_seconds(target);
    links.clear();  // detach first so the numbers stop changing while we read them

    // ---- report ----------------------------------------------------------
    KernelSymbols ksyms = KernelSymbols::load();
    const int stacks_fd = map_fd(obj.get(), "stack_traces");

    uint64_t cnt[WL_CNT_COUNT] = {};
    for (uint32_t i = 0; i < WL_CNT_COUNT; ++i) bpf_map_lookup_elem(map_fd(obj.get(), "counter_map"), &i, &cnt[i]);
    wl_hist hist[WL_HIST_COUNT] = {};
    for (uint32_t i = 0; i < WL_HIST_COUNT; ++i) bpf_map_lookup_elem(map_fd(obj.get(), "hist_map"), &i, &hist[i]);

    auto offcpu = dump_hash<wl_offcpu_val>(map_fd(obj.get(), "offcpu_time"));
    auto faults = dump_hash<uint64_t>(map_fd(obj.get(), "fault_counts"));
    std::sort(offcpu.begin(), offcpu.end(),
              [](const auto& a, const auto& b) { return a.second.total_ns > b.second.total_ns; });
    std::sort(faults.begin(), faults.end(), [](const auto& a, const auto& b) { return a.second > b.second; });

    std::map<uint32_t, uint64_t> per_thread_off;
    for (const auto& [k, v] : offcpu) per_thread_off[k.pid] += v.total_ns;

    std::printf("\n=== waitlens report: pid %u", target);
    if (!opt.command.empty() && opt.command[0]) std::printf(" (%s)", opt.command[0]);
    std::printf(" ===\n\n");
    std::printf("wall time           %s\n", format_ns(uint64_t(wall_s * 1e9)).c_str());
    if (cpu0 && cpu1) std::printf("on-CPU time         %s (all threads)\n", format_ns(uint64_t((*cpu1 - *cpu0) * 1e9)).c_str());
    std::printf("off-CPU time        %s (all threads)\n", format_ns(cnt[WL_CNT_OFFCPU_NS]).c_str());
    std::printf("  waiting for CPU   %s (runnable, in run queue)\n", format_ns(cnt[WL_CNT_RUNQ_NS]).c_str());
    std::printf("context switches    %llu out, %llu of them preemptions\n",
                (unsigned long long)cnt[WL_CNT_SWITCHES_OUT], (unsigned long long)cnt[WL_CNT_PREEMPTIONS]);
    if (opt.faults) std::printf("page faults         %llu\n", (unsigned long long)cnt[WL_CNT_PAGE_FAULTS]);
    std::printf("threads observed    %zu\n\n", per_thread_off.size());

    if (!per_thread_off.empty()) {
        std::vector<std::pair<uint32_t, uint64_t>> th(per_thread_off.begin(), per_thread_off.end());
        std::sort(th.begin(), th.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        std::printf("off-CPU time by thread\n");
        for (size_t i = 0; i < th.size() && i < 10; ++i) {
            auto it = thread_names.find(th[i].first);
            std::printf("  %-8u %-16s %12s\n", th[i].first,
                        it == thread_names.end() ? "?" : it->second.c_str(), format_ns(th[i].second).c_str());
        }
        std::printf("\n");
    }

    std::printf("%s\n", render_hist(hist[WL_HIST_OFFCPU], "off-CPU block duration").c_str());
    std::printf("%s\n", render_hist(hist[WL_HIST_RUNQ], "run-queue latency (wakeup -> running)").c_str());
    if (!func_label.empty()) {
        const std::string t = "latency of " + func_label + " (" + std::to_string(cnt[WL_CNT_FUNC_CALLS]) + " calls)";
        std::printf("%s\n", render_hist(hist[WL_HIST_FUNC], t.c_str()).c_str());
    }

    std::printf("top off-CPU stacks (where threads blocked, by total time)\n");
    for (int i = 0; i < opt.top && i < int(offcpu.size()); ++i) {
        const auto& [k, v] = offcpu[size_t(i)];
        auto it = thread_names.find(k.pid);
        std::printf("  #%d  %s total, %llu blocks, avg %s   [tid %u %s]\n", i + 1,
                    format_ns(v.total_ns).c_str(), (unsigned long long)v.count,
                    format_ns(v.total_ns / (v.count ? v.count : 1)).c_str(), k.pid,
                    it == thread_names.end() ? "" : it->second.c_str());
        print_frames(symbolize(stacks_fd, k, ksyms, usyms));
    }
    if (opt.faults) {
        std::map<uint32_t, uint64_t> per_thread_faults;
        for (const auto& [k, v] : faults) per_thread_faults[k.pid] += v;
        std::printf("\npage faults by thread\n");
        for (const auto& [tid, n] : per_thread_faults) {
            auto it = thread_names.find(tid);
            std::printf("  %-8u %-16s %12llu\n", tid, it == thread_names.end() ? "?" : it->second.c_str(),
                        (unsigned long long)n);
        }
        std::printf("\ntop page-fault stacks\n");
        for (int i = 0; i < opt.top && i < int(faults.size()); ++i) {
            const auto& [k, v] = faults[size_t(i)];
            std::printf("  #%d  %llu faults   [tid %u]\n", i + 1, (unsigned long long)v, k.pid);
            print_frames(symbolize(stacks_fd, k, ksyms, usyms), 0);
        }
    }

    if (!opt.folded_path.empty()) {
        // folded format for flame graphs: root;...;leaf <value>, value = us off-cpu
        std::ofstream out(opt.folded_path);
        for (const auto& [k, v] : offcpu) {
            Frames f = symbolize(stacks_fd, k, ksyms, usyms);
            auto it = thread_names.find(k.pid);
            std::string line = it == thread_names.end() ? "?" : it->second;
            for (auto u = f.user.rbegin(); u != f.user.rend(); ++u) line += ";" + *u;
            for (auto kf = f.kernel.rbegin(); kf != f.kernel.rend(); ++kf) line += ";" + *kf + "_[k]";
            out << line << " " << (v.total_ns / 1000) << "\n";
        }
        std::fprintf(stderr, "waitlens: wrote folded stacks to %s (render with flamegraph.pl or speedscope.app)\n",
                     opt.folded_path.c_str());
    }

    if (child.pid && !child_done) {
        kill(child.pid, SIGTERM);  // we started it so we clean it up
        waitpid(child.pid, &child_status, 0);
    }
    return 0;
}
