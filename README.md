# waitlens

A Linux latency profiler built on eBPF. Point it at a running process (or launch one through
it) and it tells you where the process's time goes when it is **not** running on a CPU:
blocked on locks, sleeping on I/O, waiting in the scheduler's run queue, or stalled on page
faults. It shows the exact kernel and C++ call stacks responsible.

CPU profilers like `perf record` only see time spent *running*. Tail latency usually comes
from time spent *waiting*, which on-CPU sampling cannot see. waitlens measures that waiting
directly in the kernel with near-zero overhead.

```
            kernel (eBPF, verified + JIT-compiled)                        user space (C++20)
 sched_switch ──► off-CPU start/stop per thread + stack ids ─┐
 sched_wakeup ──► run-queue wait start                        ├─► BPF maps ──► waitlens: symbolize
 page-fault perf event ──► fault count per user stack          │   (hash,        (/proc/kallsyms,
 uprobe/uretprobe ──► latency of one C++ function ─────────────┘    stack,       /proc/pid/maps,
                                                                    histograms)  ELF .symtab) ─► report
                                                                                              └► folded stacks
```

## What the report shows

* **Time breakdown:** wall time, on-CPU time, off-CPU time, and how much of the off-CPU time was
  spent runnable but waiting for a CPU (preemption / overloaded cores).
* **Histograms:** off-CPU block durations, run-queue latency, and optionally the latency of any
  function you name (via uprobes), with p50/p99 bounds.
* **Top off-CPU stacks:** the kernel + user stacks where threads blocked the longest in total.
* **Page faults by thread and by stack:** where first-touch memory faults happen.
* **Folded stacks** (`--folded`) for flame graphs (`flamegraph.pl` or https://speedscope.app).

## Real example: what it found in my order book feed handler

Profiling [itch-orderbook](https://github.com/IlijevskiM/itch-orderbook) replaying 5M messages
in pipeline mode (decode thread → lock-free ring → book thread):

1. **Hot-path page faults.** The book thread, which must never stall, took **9,268 page faults**:
   first-touch faults from the order pool growing and from `std::map` allocating price-level
   nodes. Pre-growing the pool and moving the level maps onto a `std::pmr` pool over a
   pre-faulted arena cut book-thread faults to **28** (99.7% fewer) and raised pipeline
   throughput about 9%.
2. **The p99 tail is preemption, not code.** The worker threads spin rather than block, yet
   nearly every context switch in the process was a preemption (128 of 134), with run-queue waits up to
   ~2 ms. On a machine with few cores the tail latency comes from the scheduler, so the fix is
   CPU pinning / isolated cores, not micro-optimizing the book.

(Measured on a 2-vCPU Linux VM with a synthetic stream.)

## Quick start

### On macOS: use a Linux VM

eBPF is a Linux kernel feature. On a Mac, run it in a lightweight VM with
[Lima](https://lima-vm.io) (works on Apple Silicon; the VM is arm64 and waitlens supports it):

```bash
brew install lima
limactl start --name=bpf --cpus=4 --memory=8 template://ubuntu-lts
limactl shell bpf
```

### Inside Linux (Ubuntu 22.04+ / kernel 5.8+ with BTF)

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config cmake g++ \
    libgtest-dev linux-tools-common linux-tools-generic
git clone https://github.com/<you>/waitlens && cd waitlens
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
ctest --test-dir build                  # unit tests (no root needed)
bash tests/integration.sh build         # end-to-end with BPF (uses sudo)
```

### Usage

```bash
# launch a program under the profiler
sudo ./build/waitlens -- ./build/workload 5 4

# attach to a running process for 10 seconds
sudo ./build/waitlens -p 12345 -d 10

# also measure one C++ function's latency (name may be a substring of the demangled name)
sudo ./build/waitlens --func ./build/workload:demo::handle_request -- ./build/workload 5 4

# flame graph of off-CPU time
sudo ./build/waitlens --folded offcpu.folded -- ./build/workload 5 4
# then drag offcpu.folded into https://speedscope.app
```

### Try the demo

`demo/workload.cpp` is a small service with three planted latency problems: a mutex held during
slow work, an occasional blocking "backend call", and memory that page-faults on first touch.
waitlens's top stacks point straight at `demo::update_shared_stats` (futex waits) and
`demo::fetch_from_backend` (nanosleep). Run `./build/workload 3 4 --fixed` to see the throughput
after moving the slow work out of the lock (about 1.8x on a 2-vCPU VM).

## Benchmarking

How each number is measured (results go in `RESULTS.md` with the machine and exact command):

| Metric | How to measure |
|---|---|
| overhead | run `workload 5 4 --fixed` alone vs. under waitlens (with and without `--no-faults`), compare req/s over 5 runs |
| hot-path faults before/after | profile itch-orderbook before and after the pool/arena change; read "page faults by thread" |
| throughput change | `replay <file> --mode pipeline`, best of 5, before and after |
| preemption finding | "context switches ... of them preemptions" and the run-queue histogram |

Measured here on a 2-vCPU VM: scheduler tracing alone was within run-to-run noise (about 1%);
adding every-fault page-fault sampling cost about 8% on a fault-heavy workload.

## Design decisions

| Decision | Why | Alternative |
|---|---|---|
| Aggregate in kernel maps, read once at the end | per-event cost is a few map updates; nothing is streamed to user space | perf buffer / ring buffer per event (flexible, far more overhead) |
| `tp_btf` tracepoints + CO-RE | typed access to `task_struct`; one binary loads across kernel versions because field offsets are relocated at load time | kprobes (unstable), or compiling against each kernel's headers (BCC style) |
| Capture stacks at switch-out | the thread being descheduled is still `current`, so its stack explains why it blocked | capture at wake-up (you would get the waker's stack instead) |
| `task->__state == TASK_RUNNING` at switch-out means preemption | a preempted thread is still runnable, so its run-queue wait starts immediately | only counting explicit wakeups (misses preemption) |
| Branch-free `log2` for histogram slots | the verifier needs bounded code; shifts instead of loops | `bpf_loop` or unrolled loops |
| Page faults through a software perf event per CPU | works on x86 and arm64 (the `exceptions:page_fault_user` tracepoint is x86-only) | sampling every Nth fault to cut overhead |
| Own ELF symbolizer (`<elf.h>`), `/proc/pid/maps`, `/proc/kallsyms` | no heavy dependencies; handles PIE executables and shared libs via PT_LOAD mapping; reads through `/proc/pid/root` for containers | libdw / blazesym |
| Uprobes resolved to file offsets by our ELF code | works with C++ names by demangled substring | libbpf's name-based attach (needs exact mangled names) |
| BPF object embedded with `.incbin` | one self-contained binary | shipping a separate `.bpf.o` file |

## Limitations

* **User stacks need frame pointers.** Build the target with `-fno-omit-frame-pointer`.
  Hand-written leaf functions (like libc `memset`) skip their caller's frame.
* **Uprobes are trap-based** (a few microseconds per hit), so probing a function called millions
  of times per second distorts it. You will even see the probe's own trap in off-CPU stacks.
* **Page-fault sampling is system-wide** and filtered in BPF, so its cost scales with the whole
  machine's fault rate. Use `--no-faults` on busy hosts.
* Thread names and memory maps are read from `/proc` while the target runs; a process that
  `dlopen`s and `dlclose`s libraries very quickly can leave frames unresolved.

## Ideas to extend

* Lock contention view: uprobe `pthread_mutex_lock` and attribute wait time to lock addresses.
* Wakeup chains: record who woke each thread to see the full blocking chain.
* Stream per-event data through a BPF ring buffer for a live, top-like view.
* Export Prometheus / OpenTelemetry metrics.
