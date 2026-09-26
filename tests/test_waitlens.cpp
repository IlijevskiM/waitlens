// tests for everything that doesn't need root/BPF: symbol lookup, ELF parsing
// (on the test binary itself), /proc/pid/maps + kallsyms parsing, histograms
#include <gtest/gtest.h>

#include <fstream>
#include <sstream>

#include "waitlens/histogram.hpp"
#include "waitlens/symbolizer.hpp"

using namespace waitlens;

namespace test_ns {
__attribute__((noinline)) int marker_function(int x) { return x * 3 + 1; }
}  // namespace test_ns

TEST(SymbolTable, LookupWithinAndBetweenSymbols) {
    SymbolTable t;
    t.add({0x1000, 0x10, "a"});
    t.add({0x2000, 0, "b"});  // unknown size: extends to next symbol
    t.add({0x3000, 0x10, "c"});
    t.finalize();
    ASSERT_NE(t.lookup(0x1005), nullptr);
    EXPECT_EQ(t.lookup(0x1005)->name, "a");
    EXPECT_EQ(t.lookup(0x1010), nullptr);  // past a's size
    EXPECT_EQ(t.lookup(0x2fff)->name, "b");
    EXPECT_EQ(t.lookup(0x0fff), nullptr);
}

TEST(KernelSymbols, ParsesKallsymsText) {
    auto ks = KernelSymbols::parse(
        "ffffffff81000000 T _stext\n"
        "ffffffff81001000 t schedule\n"
        "ffffffff81002000 D some_data\n"           // data: ignored
        "ffffffffc0000000 t mod_func\t[my_mod]\n"
        "0000000000000000 T hidden_without_root\n");  // zeroed: ignored
    EXPECT_EQ(ks.size(), 3u);
    EXPECT_EQ(ks.resolve(0xffffffff81001234ULL), "schedule");
    EXPECT_EQ(ks.resolve(0xffffffffc0000010ULL), "mod_func");
}

TEST(ProcMaps, ParsesMappingsAndPaths) {
    auto maps = parse_proc_maps(
        "55d0c0a00000-55d0c0a21000 r--p 00000000 fd:01 1234   /usr/bin/app\n"
        "55d0c0a21000-55d0c0b00000 r-xp 00021000 fd:01 1234   /usr/bin/app\n"
        "7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0      [stack]\n"
        "7f0000000000-7f0000001000 rw-p 00000000 00:00 0\n");
    ASSERT_EQ(maps.size(), 4u);
    EXPECT_FALSE(maps[0].executable);
    EXPECT_TRUE(maps[1].executable);
    EXPECT_EQ(maps[1].offset, 0x21000u);
    EXPECT_EQ(maps[1].path, "/usr/bin/app");
    EXPECT_EQ(maps[2].path, "[stack]");
    EXPECT_EQ(maps[3].path, "");
}

TEST(Demangle, CppNames) {
    EXPECT_EQ(demangle("_ZN7test_ns15marker_functionEi"), "test_ns::marker_function(int)");
    EXPECT_EQ(demangle("main"), "main");
}

// real ELF end to end: find our own function by name, then resolve a live
// address inside it through /proc/self/maps and check we get the name back
TEST(ElfFile, ResolvesOwnFunctionFromLiveAddress) {
    auto elf = ElfFile::open("/proc/self/exe");
    ASSERT_NE(elf, nullptr);
    auto found = elf->find_functions("test_ns::marker_function");
    ASSERT_EQ(found.size(), 1u);
    auto off = elf->vaddr_to_file_offset(found[0].addr);
    ASSERT_TRUE(off.has_value());
    EXPECT_EQ(elf->file_offset_to_vaddr(*off), found[0].addr);

    ProcessSymbols self{static_cast<uint32_t>(getpid())};
    ASSERT_TRUE(self.refresh());
    const auto live = reinterpret_cast<uint64_t>(&test_ns::marker_function);
    EXPECT_EQ(self.resolve(live + 1), "test_ns::marker_function(int)");
    EXPECT_EQ(test_ns::marker_function(1), 4);
}

TEST(ElfFile, RejectsNonElf) {
    const char* path = "/tmp/waitlens_not_elf.txt";
    std::ofstream(path) << "hello";
    EXPECT_EQ(ElfFile::open(path), nullptr);
    EXPECT_EQ(ElfFile::open("/definitely/not/here"), nullptr);
}

TEST(Histogram, PercentilesAreBucketUpperBounds) {
    wl_hist h{};
    h.slots[10] = 90;  // [1024, 2048) ns
    h.slots[20] = 10;  // [~1 ms, ~2 ms)
    EXPECT_EQ(hist_total(h), 100u);
    EXPECT_EQ(hist_percentile_upper_ns(h, 50), 2048u);
    EXPECT_EQ(hist_percentile_upper_ns(h, 90), 2048u);
    EXPECT_EQ(hist_percentile_upper_ns(h, 99), uint64_t(1) << 21);
    wl_hist empty{};
    EXPECT_EQ(hist_percentile_upper_ns(empty, 99), 0u);
}

TEST(Histogram, RenderShowsPopulatedRangeOnly) {
    wl_hist h{};
    h.slots[3] = 5;
    h.slots[5] = 10;
    std::string s = render_hist(h, "test");
    EXPECT_NE(s.find("n=15"), std::string::npos);
    EXPECT_NE(s.find("8 ns"), std::string::npos);    // first populated bucket
    EXPECT_EQ(s.find("4 ns -"), std::string::npos);  // empty bucket before it
}

TEST(Histogram, FormatsUnits) {
    EXPECT_EQ(format_ns(512), "512 ns");
    EXPECT_EQ(format_ns(1500), "1.5 us");
    EXPECT_EQ(format_ns(2'500'000), "2.5 ms");
    EXPECT_EQ(format_ns(3'000'000'000ULL), "3.00 s");
}
