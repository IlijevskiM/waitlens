#pragma once
// turns the raw addresses in BPF stack traces into function names.
//
//   kernel addr -> /proc/kallsyms
//   user addr   -> /proc/<pid>/maps (which file + offset)
//               -> that ELF's symbol table (.symtab / .dynsym)
//               -> demangle
//
// did it by hand with <elf.h> instead of pulling in libdw or blazesym,
// mostly to actually understand how this works
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace waitlens {

struct Symbol {
    uint64_t addr = 0;  // virtual address (ELF) or kernel address
    uint64_t size = 0;  // 0 = don't know, assume it runs until the next symbol
    std::string name;
};

// sorted list of symbols so we can binary search "which function is this addr in"
class SymbolTable {
public:
    void add(Symbol s) { syms_.push_back(std::move(s)); }
    void finalize();  // sort + dedupe, call after you're done adding
    const Symbol* lookup(uint64_t addr) const;
    size_t size() const { return syms_.size(); }

private:
    std::vector<Symbol> syms_;
};

// kernel symbols from /proc/kallsyms (addresses are all 0 unless you're root)
class KernelSymbols {
public:
    static KernelSymbols load(const std::string& path = "/proc/kallsyms");
    static KernelSymbols parse(const std::string& text);
    std::string resolve(uint64_t addr) const;
    size_t size() const { return table_.size(); }

private:
    SymbolTable table_;
};

// function symbols + loadable segments from one ELF file
class ElfFile {
public:
    // nullptr if it doesn't exist or isn't a 64-bit ELF
    static std::unique_ptr<ElfFile> open(const std::string& path);

    // maps gives us a file offset but symbols are in virtual addresses, so
    // convert using the PT_LOAD segments
    std::optional<uint64_t> file_offset_to_vaddr(uint64_t off) const;
    std::optional<uint64_t> vaddr_to_file_offset(uint64_t vaddr) const;

    const SymbolTable& symbols() const { return symbols_; }
    // every function whose demangled name contains `needle` (for --func)
    std::vector<Symbol> find_functions(const std::string& needle) const;

private:
    struct Segment {
        uint64_t vaddr, offset, filesz;
    };
    std::vector<Segment> segments_;
    SymbolTable symbols_;
    std::vector<Symbol> all_funcs_;
};

struct Mapping {
    uint64_t start = 0, end = 0, offset = 0;
    bool executable = false;
    std::string path;
};

std::vector<Mapping> parse_proc_maps(const std::string& text);

// user-space symbols for one process. refresh() while it's still running;
// after it exits we just keep using the last snapshot of its maps
class ProcessSymbols {
public:
    explicit ProcessSymbols(uint32_t pid) : pid_(pid) {}
    bool refresh();  // re-read /proc/<pid>/maps, false if the process is gone
    std::string resolve(uint64_t addr);

private:
    uint32_t pid_;
    std::vector<Mapping> maps_;
    std::map<std::string, std::unique_ptr<ElfFile>> elf_cache_;
};

std::string demangle(const std::string& name);

}  // namespace waitlens
