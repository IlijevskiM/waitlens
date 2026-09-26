cmake_minimum_required(VERSION 3.20)
project(waitlens LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-Wall> $<$<COMPILE_LANGUAGE:CXX>:-Wextra>)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "waitlens uses eBPF and only builds on Linux (use a Linux VM on macOS; see README)")
endif()

# ---- dependencies ----------------------------------------------------------
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf>=0.8)
find_program(CLANG clang REQUIRED)
# Ubuntu's /usr/sbin/bpftool is a wrapper that refuses to run when the tools
# package does not match `uname -r` exactly (common in VMs), so prefer the real
# binary under /usr/lib/linux-tools*/ when one exists.
file(GLOB _bpftool_candidates /usr/lib/linux-tools/*/bpftool /usr/lib/linux-tools-*/bpftool)
if(_bpftool_candidates AND NOT BPFTOOL)
  list(GET _bpftool_candidates 0 _first)
  set(BPFTOOL ${_first} CACHE FILEPATH "bpftool binary")
endif()
find_program(BPFTOOL bpftool PATHS /usr/sbin /usr/local/sbin)
if(NOT BPFTOOL)
  message(FATAL_ERROR "bpftool not found (apt install linux-tools-common linux-tools-generic)")
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
  set(BPF_ARCH x86)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
  set(BPF_ARCH arm64)
else()
  message(FATAL_ERROR "unsupported architecture ${CMAKE_SYSTEM_PROCESSOR}")
endif()

# ---- BPF object ------------------------------------------------------------
# vmlinux.h: every kernel type, generated from the running kernel's BTF. With
# CO-RE the compiled object still loads on other kernel versions.
set(VMLINUX_H ${CMAKE_BINARY_DIR}/vmlinux.h)
add_custom_command(
  OUTPUT ${VMLINUX_H}
  COMMAND ${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_H}
  COMMENT "Generating vmlinux.h from kernel BTF")

set(BPF_OBJ ${CMAKE_BINARY_DIR}/waitlens.bpf.o)
add_custom_command(
  OUTPUT ${BPF_OBJ}
  COMMAND ${CLANG} -g -O2 -target bpf -D__TARGET_ARCH_${BPF_ARCH}
          -I${CMAKE_BINARY_DIR} -I${CMAKE_SOURCE_DIR}/include ${LIBBPF_CFLAGS}
          -c ${CMAKE_SOURCE_DIR}/bpf/waitlens.bpf.c -o ${BPF_OBJ}
  DEPENDS ${CMAKE_SOURCE_DIR}/bpf/waitlens.bpf.c ${CMAKE_SOURCE_DIR}/include/waitlens/common.h ${VMLINUX_H}
  COMMENT "Compiling BPF programs")

configure_file(src/embed_bpf.S.in ${CMAKE_BINARY_DIR}/embed_bpf.S @ONLY)
set_source_files_properties(${CMAKE_BINARY_DIR}/embed_bpf.S PROPERTIES OBJECT_DEPENDS ${BPF_OBJ})

# ---- user space ------------------------------------------------------------
add_library(waitlens_core STATIC src/symbolizer.cpp)
target_include_directories(waitlens_core PUBLIC include)

add_executable(waitlens src/main.cpp ${CMAKE_BINARY_DIR}/embed_bpf.S)
target_link_libraries(waitlens PRIVATE waitlens_core PkgConfig::LIBBPF)

# Demo target: frame pointers so user stacks unwind (see README).
add_executable(workload demo/workload.cpp)
target_compile_options(workload PRIVATE -O2 -g -fno-omit-frame-pointer)
find_package(Threads REQUIRED)
target_link_libraries(workload PRIVATE Threads::Threads)

# ---- tests -----------------------------------------------------------------
include(CTest)
if(BUILD_TESTING)
  find_package(GTest QUIET)
  if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(googletest
      URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
      DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    FetchContent_MakeAvailable(googletest)
  endif()
  add_executable(waitlens_tests tests/test_waitlens.cpp)
  target_compile_options(waitlens_tests PRIVATE -O1 -fno-omit-frame-pointer)
  target_link_libraries(waitlens_tests PRIVATE waitlens_core GTest::gtest_main)
  include(GoogleTest)
  gtest_discover_tests(waitlens_tests)
endif()
