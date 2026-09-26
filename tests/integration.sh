#!/usr/bin/env bash
# End-to-end check: profile the demo workload and assert the report found the
# three latency sources it contains. Needs root (BPF). Used by CI.
set -euo pipefail
BUILD=${1:-build}
out=$(${SUDO:-sudo} "$BUILD/waitlens" --top 20 --folded /tmp/waitlens.folded \
        --func "$BUILD/workload:demo::handle_request" -- "$BUILD/workload" 2 4 2>&1)
echo "$out" | head -40

fail() { echo "FAIL: $1"; exit 1; }
echo "$out" | grep -q "=== waitlens report"                || fail "no report"
echo "$out" | grep -q "demo::update_shared_stats"           || fail "lock contention stack not found"
echo "$out" | grep -q "demo::fetch_from_backend"            || fail "sleep stack not found"
echo "$out" | grep -qE "latency of demo::handle_request.*[1-9][0-9]* calls" || fail "no uprobe samples"
echo "$out" | grep -qE "page faults +[1-9]"                 || fail "no page faults counted"
[ -s /tmp/waitlens.folded ]                                 || fail "folded output empty"
echo "PASS"
