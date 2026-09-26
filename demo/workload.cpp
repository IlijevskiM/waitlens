// a purposely bad "service" to test waitlens on.
//
// worker threads handle fake requests. most requests are a bit of cpu work,
// but there are 3 problems hidden in there:
//   1. lock contention - the lock holder sometimes does slow work while holding it
//   2. blocking calls - occasionally sleeps like it's waiting on a backend
//   3. page faults - some requests touch brand new mmap'd memory
//
// waitlens should blame futex waits under demo::update_shared_stats, nanosleep
// under demo::fetch_from_backend, and the faults on demo::build_response.
//
//   ./workload [seconds=5] [threads=4] [--fixed]
//
// --fixed moves the slow part out of the lock so you can see the before/after
#include <sys/mman.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

namespace demo {

std::mutex g_stats_mu;
uint64_t g_stats[64];
std::atomic<uint64_t> g_requests{0};

__attribute__((noinline)) uint64_t spin(uint64_t n) {
    uint64_t x = n;
    for (uint64_t i = 0; i < n; ++i) x = x * 6364136223846793005ULL + 1442695040888963407ULL;
    return x;
}

bool g_fixed = false;  // set by --fixed

__attribute__((noinline)) void update_shared_stats(uint64_t v, bool slow) {
    if (g_fixed) {
        const uint64_t extra = slow ? spin(400'000) : 0;  // do the slow part first
        std::lock_guard<std::mutex> lk(g_stats_mu);        // then only lock for the update
        g_stats[v % 64] += v;
        g_stats[0] += extra;
        return;
    }
    std::lock_guard<std::mutex> lk(g_stats_mu);
    g_stats[v % 64] += v;
    if (slow) g_stats[0] += spin(400'000);  // the bug: slow work while holding the lock
}

__attribute__((noinline)) void fetch_from_backend() {
    std::this_thread::sleep_for(std::chrono::microseconds(500));
}

__attribute__((noinline)) uint64_t build_response(size_t bytes) {
    // brand new anonymous memory, so every page we touch faults
    void* p = mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;
    std::memset(p, 1, bytes);
    uint64_t sum = static_cast<unsigned char*>(p)[bytes - 1];
    munmap(p, bytes);
    return sum;
}

__attribute__((noinline)) uint64_t handle_request(uint64_t id, std::mt19937_64& rng) {
    uint64_t r = spin(2'000 + rng() % 2'000);
    update_shared_stats(r, rng() % 8 == 0);
    if (rng() % 50 == 0) fetch_from_backend();
    if (rng() % 10 == 0) r += build_response(256 * 1024);
    g_requests.fetch_add(1, std::memory_order_relaxed);
    return r + id;
}

}  // namespace demo

int main(int argc, char** argv) {
    const double seconds = argc > 1 ? std::atof(argv[1]) : 5.0;
    const int nthreads = argc > 2 ? std::atoi(argv[2]) : 4;
    demo::g_fixed = argc > 3 && std::strcmp(argv[3], "--fixed") == 0;
    std::atomic<bool> stop{false};
    std::vector<std::thread> workers;
    for (int t = 0; t < nthreads; ++t) {
        workers.emplace_back([&, t] {
            std::mt19937_64 rng(uint64_t(t) + 1);
            uint64_t id = 0, sink = 0;
            while (!stop.load(std::memory_order_relaxed)) sink += demo::handle_request(id++, rng);
            if (sink == 42) std::puts("");  // just so the compiler can't optimize the work away
        });
    }
    const auto t0 = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(std::chrono::duration<double>(seconds));
    stop = true;
    for (auto& w : workers) w.join();
    const double el = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    std::printf("workload: %llu requests in %.2f s (%.0f req/s)\n",
                (unsigned long long)demo::g_requests.load(), el, double(demo::g_requests.load()) / el);
    return 0;
}
