/* shared between the BPF side (plain C, clang -target bpf) and the C++ side.
 * so: C only, fixed width types only, nothing fancy */
#ifndef WAITLENS_COMMON_H
#define WAITLENS_COMMON_H

#ifdef __cplusplus
#include <cstdint>
typedef uint32_t wl_u32;
typedef int32_t wl_s32;
typedef uint64_t wl_u64;
#else
typedef __u32 wl_u32;
typedef __s32 wl_s32;
typedef __u64 wl_u64;
#endif

/* log2 histogram. slot i = samples in [2^i, 2^(i+1)) ns.
 * 40 slots gets you from 1ns up to ~18 min which is plenty */
#define WL_HIST_SLOTS 40
#define WL_MAX_STACK_DEPTH 127

enum wl_hist_id {
    WL_HIST_OFFCPU = 0,  /* how long a thread stayed off-CPU per switch */
    WL_HIST_RUNQ = 1,    /* woke up -> actually running */
    WL_HIST_FUNC = 2,    /* uprobe'd function latency */
    WL_HIST_COUNT = 3,
};

struct wl_hist {
    wl_u64 slots[WL_HIST_SLOTS];
};

struct wl_config {
    wl_u32 target_tgid;   /* process to profile */
    wl_u32 min_offcpu_ns; /* ignore off-CPU blocks shorter than this */
};

/* key for summing by (thread, stack). stack id < 0 = couldn't get the stack
 * (usually -EFAULT, the program wasn't built with frame pointers) */
struct wl_stack_key {
    wl_u32 pid; /* thread id */
    wl_s32 user_stack_id;
    wl_s32 kern_stack_id;
    wl_u32 pad;
};

struct wl_offcpu_val {
    wl_u64 total_ns;
    wl_u64 count;
};

/* running totals for the summary at the top of the report */
enum wl_counter_id {
    WL_CNT_OFFCPU_NS = 0,
    WL_CNT_RUNQ_NS = 1,
    WL_CNT_SWITCHES_OUT = 2,
    WL_CNT_PREEMPTIONS = 3, /* switched out while still runnable */
    WL_CNT_PAGE_FAULTS = 4,
    WL_CNT_FUNC_CALLS = 5,
    WL_CNT_COUNT = 6,
};

#endif /* WAITLENS_COMMON_H */
