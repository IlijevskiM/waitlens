#pragma once
// printing + percentiles for the log2 histograms the BPF side fills in
#include <cstdint>
#include <cstdio>
#include <string>

#include "waitlens/common.h"

namespace waitlens {

inline uint64_t hist_total(const wl_hist& h) {
    uint64_t t = 0;
    for (uint64_t v : h.slots) t += v;
    return t;
}

// returns the upper edge of the bucket the p-th percentile falls in.
// with log2 buckets that's only accurate to within 2x, hence "p99 <= X" in the output
inline uint64_t hist_percentile_upper_ns(const wl_hist& h, double p) {
    const uint64_t total = hist_total(h);
    if (total == 0) return 0;
    const double target = double(total) * p / 100.0;
    uint64_t seen = 0;
    for (int i = 0; i < WL_HIST_SLOTS; ++i) {
        seen += h.slots[i];
        if (double(seen) >= target) return uint64_t(1) << (i + 1);
    }
    return uint64_t(1) << WL_HIST_SLOTS;
}

inline std::string format_ns(uint64_t ns) {
    char buf[32];
    if (ns < 1'000) std::snprintf(buf, sizeof buf, "%llu ns", (unsigned long long)ns);
    else if (ns < 1'000'000) std::snprintf(buf, sizeof buf, "%.1f us", double(ns) / 1e3);
    else if (ns < 1'000'000'000) std::snprintf(buf, sizeof buf, "%.1f ms", double(ns) / 1e6);
    else std::snprintf(buf, sizeof buf, "%.2f s", double(ns) / 1e9);
    return buf;
}

// ascii histogram like bcc's tools, skips empty buckets at both ends
inline std::string render_hist(const wl_hist& h, const char* title, int width = 40) {
    std::string out;
    int lo = -1, hi = -1;
    uint64_t mx = 0;
    for (int i = 0; i < WL_HIST_SLOTS; ++i) {
        if (!h.slots[i]) continue;
        if (lo < 0) lo = i;
        hi = i;
        if (h.slots[i] > mx) mx = h.slots[i];
    }
    char line[256];
    std::snprintf(line, sizeof line, "%s  (n=%llu, p50 <= %s, p99 <= %s)\n", title,
                  (unsigned long long)hist_total(h), format_ns(hist_percentile_upper_ns(h, 50)).c_str(),
                  format_ns(hist_percentile_upper_ns(h, 99)).c_str());
    out += line;
    if (lo < 0) return out + "    (no samples)\n";
    for (int i = lo; i <= hi; ++i) {
        const int stars = int(double(h.slots[i]) / double(mx) * width + 0.5);
        std::snprintf(line, sizeof line, "  %10s - %-10s : %10llu |%-*s|\n",
                      format_ns(uint64_t(1) << i).c_str(), format_ns(uint64_t(1) << (i + 1)).c_str(),
                      (unsigned long long)h.slots[i], width, std::string(size_t(stars), '*').c_str());
        out += line;
    }
    return out;
}

}  // namespace waitlens
