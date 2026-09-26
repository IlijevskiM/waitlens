// SPDX-License-Identifier: GPL-2.0
/*
 * waitlens - the kernel side.
 *
 * basically answers "where is my process spending time when it's NOT running":
 *   - off-CPU time per (thread, user stack, kernel stack)  <- sched_switch
 *   - run queue latency (runnable, but waiting for a cpu)  <- sched_wakeup + sched_switch
 *   - page faults per user stack                           <- software perf event
 *   - latency of one function you pick                     <- uprobe + uretprobe
 *
 * everything gets summed up in maps inside the kernel, so each event is just
 * a couple map updates. nothing goes to user space until the report at the end.
 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "waitlens/common.h"

char LICENSE[] SEC("license") = "GPL";

#define TASK_RUNNING 0

struct start_val {
    __u64 ts;
    __s32 user_stack_id;
    __s32 kern_stack_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct wl_config);
} cfg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32); /* thread id */
    __type(value, struct start_val);
} offcpu_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32); /* thread id */
    __type(value, __u64);
} runq_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64); /* pid_tgid */
    __type(value, __u64);
} func_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 16384);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, WL_MAX_STACK_DEPTH * sizeof(__u64));
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct wl_stack_key);
    __type(value, struct wl_offcpu_val);
} offcpu_time SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct wl_stack_key);
    __type(value, __u64);
} fault_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, WL_HIST_COUNT);
    __type(key, __u32);
    __type(value, struct wl_hist);
} hist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, WL_CNT_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} counter_map SEC(".maps");

/* older kernels (< 5.14) call it `state` not `__state`. CO-RE figures out
 * which one exists when the program loads */
struct task_struct___old {
    long state;
} __attribute__((preserve_access_index));

static __always_inline long task_state(struct task_struct *t) {
    if (bpf_core_field_exists(t->__state)) return BPF_CORE_READ(t, __state);
    return BPF_CORE_READ((struct task_struct___old *)t, state);
}

static __always_inline __u32 target_tgid(void) {
    __u32 zero = 0;
    struct wl_config *c = bpf_map_lookup_elem(&cfg_map, &zero);
    return c ? c->target_tgid : 0;
}

static __always_inline __u32 min_offcpu_ns(void) {
    __u32 zero = 0;
    struct wl_config *c = bpf_map_lookup_elem(&cfg_map, &zero);
    return c ? c->min_offcpu_ns : 0;
}

/* floor(log2(v)) with shifts instead of a loop, the verifier likes this better */
static __always_inline __u32 log2_u64(__u64 v) {
    __u32 r = 0, shift;
    shift = (v > 0xFFFFFFFFULL) << 5; v >>= shift; r |= shift;
    shift = (v > 0xFFFF) << 4;        v >>= shift; r |= shift;
    shift = (v > 0xFF) << 3;          v >>= shift; r |= shift;
    shift = (v > 0xF) << 2;           v >>= shift; r |= shift;
    shift = (v > 0x3) << 1;           v >>= shift; r |= shift;
    r |= (v >> 1);
    return r;
}

static __always_inline void hist_add(__u32 which, __u64 ns) {
    struct wl_hist *h = bpf_map_lookup_elem(&hist_map, &which);
    if (!h) return;
    __u32 slot = log2_u64(ns);
    if (slot >= WL_HIST_SLOTS) slot = WL_HIST_SLOTS - 1;
    __sync_fetch_and_add(&h->slots[slot], 1);
}

static __always_inline void counter_add(__u32 which, __u64 v) {
    __u64 *c = bpf_map_lookup_elem(&counter_map, &which);
    if (c) __sync_fetch_and_add(c, v);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(on_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next) {
    const __u32 tgid = target_tgid();
    if (!tgid) return 0;
    const __u64 now = bpf_ktime_get_ns();

    /* prev is getting switched out. we're still in prev's context here, so
     * grabbing the stack now tells us *why* it's leaving (lock, sleep, io...) */
    if (BPF_CORE_READ(prev, tgid) == tgid) {
        __u32 pid = BPF_CORE_READ(prev, pid);
        struct start_val sv = {
            .ts = now,
            .user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK),
            .kern_stack_id = bpf_get_stackid(ctx, &stack_traces, 0),
        };
        bpf_map_update_elem(&offcpu_start, &pid, &sv, BPF_ANY);
        counter_add(WL_CNT_SWITCHES_OUT, 1);
        /* still TASK_RUNNING = it got preempted, didn't block. so it's
         * straight back in the run queue waiting */
        if (task_state(prev) == TASK_RUNNING) {
            bpf_map_update_elem(&runq_start, &pid, &now, BPF_ANY);
            counter_add(WL_CNT_PREEMPTIONS, 1);
        }
    }

    /* next is getting the cpu back -> close out its off-cpu + runq timers */
    if (BPF_CORE_READ(next, tgid) == tgid) {
        __u32 pid = BPF_CORE_READ(next, pid);
        struct start_val *sv = bpf_map_lookup_elem(&offcpu_start, &pid);
        if (sv) {
            __u64 delta = now - sv->ts;
            if (delta >= min_offcpu_ns()) {
                struct wl_stack_key key = {
                    .pid = pid,
                    .user_stack_id = sv->user_stack_id,
                    .kern_stack_id = sv->kern_stack_id,
                };
                struct wl_offcpu_val zero = {}, *v;
                v = bpf_map_lookup_elem(&offcpu_time, &key);
                if (!v) {
                    bpf_map_update_elem(&offcpu_time, &key, &zero, BPF_NOEXIST);
                    v = bpf_map_lookup_elem(&offcpu_time, &key);
                }
                if (v) {
                    __sync_fetch_and_add(&v->total_ns, delta);
                    __sync_fetch_and_add(&v->count, 1);
                }
                hist_add(WL_HIST_OFFCPU, delta);
                counter_add(WL_CNT_OFFCPU_NS, delta);
            }
            bpf_map_delete_elem(&offcpu_start, &pid);
        }
        __u64 *rq = bpf_map_lookup_elem(&runq_start, &pid);
        if (rq) {
            __u64 delta = now - *rq;
            hist_add(WL_HIST_RUNQ, delta);
            counter_add(WL_CNT_RUNQ_NS, delta);
            bpf_map_delete_elem(&runq_start, &pid);
        }
    }
    return 0;
}

/* thread woke up (runnable now) but still has to wait for a cpu */
static __always_inline int on_wakeup(struct task_struct *p) {
    const __u32 tgid = target_tgid();
    if (!tgid || BPF_CORE_READ(p, tgid) != tgid) return 0;
    __u32 pid = BPF_CORE_READ(p, pid);
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&runq_start, &pid, &now, BPF_ANY);
    return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(on_sched_wakeup, struct task_struct *p) { return on_wakeup(p); }

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(on_sched_wakeup_new, struct task_struct *p) { return on_wakeup(p); }

/* hooked to a PERF_COUNT_SW_PAGE_FAULTS event on each cpu, sample_period = 1,
 * so this runs for every fault, in the context of whoever faulted */
SEC("perf_event")
int on_page_fault(struct bpf_perf_event_data *ctx) {
    const __u32 tgid = target_tgid();
    __u64 id = bpf_get_current_pid_tgid();
    if (!tgid || (id >> 32) != tgid) return 0;
    struct wl_stack_key key = {
        .pid = (__u32)id,
        .user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK),
        .kern_stack_id = -1,
    };
    __u64 one = 1, *v = bpf_map_lookup_elem(&fault_counts, &key);
    if (v) __sync_fetch_and_add(v, 1);
    else bpf_map_update_elem(&fault_counts, &key, &one, BPF_NOEXIST);
    counter_add(WL_CNT_PAGE_FAULTS, 1);
    return 0;
}

/* function latency. main.cpp finds the symbol's offset itself and attaches these */
SEC("uprobe")
int BPF_UPROBE(on_func_entry) {
    __u64 id = bpf_get_current_pid_tgid();
    if ((id >> 32) != target_tgid()) return 0;
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&func_start, &id, &now, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(on_func_exit) {
    __u64 id = bpf_get_current_pid_tgid();
    __u64 *start = bpf_map_lookup_elem(&func_start, &id);
    if (!start) return 0;
    hist_add(WL_HIST_FUNC, bpf_ktime_get_ns() - *start);
    counter_add(WL_CNT_FUNC_CALLS, 1);
    bpf_map_delete_elem(&func_start, &id);
    return 0;
}
