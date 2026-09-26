#include "waitlens/symbolizer.hpp"

#include <cxxabi.h>
#include <elf.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

namespace waitlens {

std::string demangle(const std::string& name) {
    int status = 0;
    char* out = abi::__cxa_demangle(name.c_str(), nullptr, nullptr, &status);
    if (status != 0 || !out) return name;
    std::string s(out);
    std::free(out);
    return s;
}

// ---------------------------------------------------------------- SymbolTable

void SymbolTable::finalize() {
    std::sort(syms_.begin(), syms_.end(),
              [](const Symbol& a, const Symbol& b) { return a.addr < b.addr; });
    syms_.erase(std::unique(syms_.begin(), syms_.end(),
                            [](const Symbol& a, const Symbol& b) { return a.addr == b.addr; }),
                syms_.end());
}

const Symbol* SymbolTable::lookup(uint64_t addr) const {
    // last symbol that starts at or before addr
    auto it = std::upper_bound(syms_.begin(), syms_.end(), addr,
                               [](uint64_t a, const Symbol& s) { return a < s.addr; });
    if (it == syms_.begin()) return nullptr;
    --it;
    if (it->size != 0 && addr >= it->addr + it->size) return nullptr;
    return &*it;
}

// -------------------------------------------------------------- KernelSymbols

KernelSymbols KernelSymbols::parse(const std::string& text) {
    KernelSymbols ks;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        // "ffffffff81000000 T _stext"   (optionally followed by "[module]")
        std::istringstream ls(line);
        std::string addr_s, type, name;
        if (!(ls >> addr_s >> type >> name)) continue;
        if (type != "t" && type != "T" && type != "w" && type != "W") continue;
        const uint64_t addr = std::strtoull(addr_s.c_str(), nullptr, 16);
        if (addr == 0) continue;  // not root -> kernel hides addresses
        ks.table_.add({addr, 0, name});
    }
    ks.table_.finalize();
    return ks;
}

KernelSymbols KernelSymbols::load(const std::string& path) {
    std::ifstream f(path);
    std::stringstream ss;
    ss << f.rdbuf();
    return parse(ss.str());
}

std::string KernelSymbols::resolve(uint64_t addr) const {
    const Symbol* s = table_.lookup(addr);
    if (!s) {
        char buf[32];
        std::snprintf(buf, sizeof buf, "0x%llx", (unsigned long long)addr);
        return buf;
    }
    return s->name;
}

// -------------------------------------------------------------------- ElfFile

namespace {
std::vector<char> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return std::vector<char>(std::istreambuf_iterator<char>(f), {});
}

template <typename T>
bool in_bounds(const std::vector<char>& d, uint64_t off, uint64_t count = 1) {
    return off <= d.size() && count <= (d.size() - off) / sizeof(T);
}
}  // namespace

std::unique_ptr<ElfFile> ElfFile::open(const std::string& path) {
    std::vector<char> d = read_file(path);
    if (d.size() < sizeof(Elf64_Ehdr) || std::memcmp(d.data(), ELFMAG, SELFMAG) != 0 ||
        d[EI_CLASS] != ELFCLASS64)
        return nullptr;

    auto elf = std::unique_ptr<ElfFile>(new ElfFile());
    Elf64_Ehdr eh;
    std::memcpy(&eh, d.data(), sizeof eh);

    // program headers = which parts of the file get mapped to which vaddrs
    if (in_bounds<Elf64_Phdr>(d, eh.e_phoff, eh.e_phnum)) {
        for (int i = 0; i < eh.e_phnum; ++i) {
            Elf64_Phdr ph;
            std::memcpy(&ph, d.data() + eh.e_phoff + size_t(i) * sizeof ph, sizeof ph);
            if (ph.p_type == PT_LOAD) elf->segments_.push_back({ph.p_vaddr, ph.p_offset, ph.p_filesz});
        }
    }

    // section headers -> find .symtab and .dynsym (stripped libs only have dynsym)
    if (!in_bounds<Elf64_Shdr>(d, eh.e_shoff, eh.e_shnum)) return elf;
    std::vector<Elf64_Shdr> sh(eh.e_shnum);
    std::memcpy(sh.data(), d.data() + eh.e_shoff, sh.size() * sizeof(Elf64_Shdr));

    for (const Elf64_Shdr& s : sh) {
        if (s.sh_type != SHT_SYMTAB && s.sh_type != SHT_DYNSYM) continue;
        if (s.sh_link >= sh.size() || s.sh_entsize != sizeof(Elf64_Sym)) continue;
        const Elf64_Shdr& strtab = sh[s.sh_link];
        const uint64_t n = s.sh_size / sizeof(Elf64_Sym);
        if (!in_bounds<Elf64_Sym>(d, s.sh_offset, n)) continue;
        for (uint64_t i = 0; i < n; ++i) {
            Elf64_Sym sym;
            std::memcpy(&sym, d.data() + s.sh_offset + i * sizeof sym, sizeof sym);
            if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC || sym.st_value == 0) continue;
            if (sym.st_name >= strtab.sh_size || strtab.sh_offset + sym.st_name >= d.size()) continue;
            const char* nm = d.data() + strtab.sh_offset + sym.st_name;
            const size_t maxlen = d.size() - (strtab.sh_offset + sym.st_name);
            Symbol out{sym.st_value, sym.st_size, std::string(nm, strnlen(nm, maxlen))};
            elf->all_funcs_.push_back(out);
            elf->symbols_.add(std::move(out));
        }
    }
    elf->symbols_.finalize();
    return elf;
}

std::optional<uint64_t> ElfFile::file_offset_to_vaddr(uint64_t off) const {
    for (const Segment& s : segments_)
        if (off >= s.offset && off < s.offset + s.filesz) return off - s.offset + s.vaddr;
    return std::nullopt;
}

std::optional<uint64_t> ElfFile::vaddr_to_file_offset(uint64_t vaddr) const {
    for (const Segment& s : segments_)
        if (vaddr >= s.vaddr && vaddr < s.vaddr + s.filesz) return vaddr - s.vaddr + s.offset;
    return std::nullopt;
}

std::vector<Symbol> ElfFile::find_functions(const std::string& needle) const {
    std::vector<Symbol> out;
    for (const Symbol& s : all_funcs_)
        if (s.name == needle || demangle(s.name).find(needle) != std::string::npos)
            out.push_back(s);
    std::sort(out.begin(), out.end(), [](const Symbol& a, const Symbol& b) { return a.addr < b.addr; });
    out.erase(std::unique(out.begin(), out.end(),
                          [](const Symbol& a, const Symbol& b) { return a.addr == b.addr; }),
              out.end());
    return out;
}

// ------------------------------------------------------------- /proc/pid/maps

std::vector<Mapping> parse_proc_maps(const std::string& text) {
    // 55d0c0a00000-55d0c0a21000 r-xp 00001000 fd:01 1234  /usr/bin/app
    std::vector<Mapping> out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        char perms[8] = {};
        unsigned long long start = 0, end = 0, off = 0;
        int path_pos = -1;
        if (std::sscanf(line.c_str(), "%llx-%llx %7s %llx %*s %*s %n", &start, &end, perms, &off,
                        &path_pos) < 4)
            continue;
        Mapping m;
        m.start = start;
        m.end = end;
        m.offset = off;
        m.executable = perms[2] == 'x';
        if (path_pos > 0 && size_t(path_pos) < line.size()) m.path = line.substr(size_t(path_pos));
        out.push_back(std::move(m));
    }
    return out;
}

// ------------------------------------------------------------ ProcessSymbols

bool ProcessSymbols::refresh() {
    std::ifstream f("/proc/" + std::to_string(pid_) + "/maps");
    if (!f) return false;
    std::stringstream ss;
    ss << f.rdbuf();
    auto maps = parse_proc_maps(ss.str());
    if (maps.empty()) return false;
    maps_ = std::move(maps);
    return true;
}

std::string ProcessSymbols::resolve(uint64_t addr) {
    for (const Mapping& m : maps_) {
        if (addr < m.start || addr >= m.end) continue;
        if (!m.executable || m.path.empty() || m.path[0] != '/') break;
        auto it = elf_cache_.find(m.path);
        if (it == elf_cache_.end()) {
            // go through /proc/<pid>/root so this still works for containers
            auto elf = ElfFile::open("/proc/" + std::to_string(pid_) + "/root" + m.path);
            if (!elf) elf = ElfFile::open(m.path);
            it = elf_cache_.emplace(m.path, std::move(elf)).first;
        }
        std::string base = m.path.substr(m.path.find_last_of('/') + 1);
        if (!it->second) return "[" + base + "]";
        auto vaddr = it->second->file_offset_to_vaddr(addr - m.start + m.offset);
        if (!vaddr) return "[" + base + "]";
        const Symbol* s = it->second->symbols().lookup(*vaddr);
        return s ? demangle(s->name) : "[" + base + "]";
    }
    char buf[32];
    std::snprintf(buf, sizeof buf, "0x%llx", (unsigned long long)addr);
    return buf;
}

}  // namespace waitlens
