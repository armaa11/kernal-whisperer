#!/usr/bin/env bash
set -u

LOG_DIR="/tmp/kw_e2e_logs"
TEST_DIR="/tmp/kw_test"
SCRIPT_NAME="$(basename "$0")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$LOG_DIR/e2e_${TIMESTAMP}.log"
SUMMARY_FILE="$LOG_DIR/summary_${TIMESTAMP}.txt"

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0

mkdir -p "$LOG_DIR" "$TEST_DIR"
: > "$LOG_FILE"
: > "$SUMMARY_FILE"

log() {
  printf '%s\n' "$*" | tee -a "$LOG_FILE"
}

record() {
  local status="$1"
  local id="$2"
  local msg="$3"
  case "$status" in
    PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
    FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
    WARN) WARN_COUNT=$((WARN_COUNT + 1)) ;;
    SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
  esac
  printf '[%s] %s: %s\n' "$status" "$id" "$msg" | tee -a "$SUMMARY_FILE" "$LOG_FILE"
}

run_capture() {
  local id="$1"
  shift
  local out_file="$LOG_DIR/${id}.out"
  local rc_file="$LOG_DIR/${id}.rc"

  log ""
  log "=== $id ==="
  log "CMD: $*"

  bash -lc "$*" >"$out_file" 2>&1
  local rc=$?
  printf '%s\n' "$rc" > "$rc_file"

  log "Exit: $rc"
  log "--- BEGIN OUTPUT ($id) ---"
  cat "$out_file" | tee -a "$LOG_FILE"
  log "--- END OUTPUT ($id) ---"

  return 0
}

contains() {
  local file="$1"
  local pat="$2"
  grep -Fq -- "$pat" "$file"
}

contains_re() {
  local file="$1"
  local pat="$2"
  grep -Eq -- "$pat" "$file"
}

prepare_fixtures() {
  log "Preparing fixtures under $TEST_DIR"
  rm -f /tmp/kw_trace_* 2>/dev/null || true

  cat > "$TEST_DIR/crash_test.py" <<'PYEOF'
#!/usr/bin/env python3
import os, sys
try:
    open("/tmp/kw_test/ghost_config.json", "r")
except FileNotFoundError:
    pass
try:
    open("/tmp/kw_test/permission_test.txt", "r")
except PermissionError:
    pass
sys.exit(2)
PYEOF

  cat > "$TEST_DIR/network_fail.py" <<'PYEOF'
#!/usr/bin/env python3
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect(("127.0.0.1", 19999))
except ConnectionRefusedError:
    pass
finally:
    s.close()
sys.exit(1)
PYEOF

  cat > "$TEST_DIR/port_bind.py" <<'PYEOF'
#!/usr/bin/env python3
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("0.0.0.0", 80))
    s.listen(1)
except PermissionError:
    pass
finally:
    s.close()
sys.exit(1)
PYEOF

  cat > "$TEST_DIR/sigsegv_test.c" <<'CEOF'
#include <stdlib.h>
int main() {
    int *ptr = NULL;
    *ptr = 42;
    return 0;
}
CEOF

  cat > "$TEST_DIR/silent_exit.sh" <<'BEOF'
#!/usr/bin/env bash
cat /tmp/kw_test/ghost_config.json 2>/dev/null
exit 127
BEOF

  cat > "$TEST_DIR/repeat_fail.sh" <<'BEOF'
#!/usr/bin/env bash
for i in $(seq 1 10); do
  cat /tmp/kw_test/ghost_config.json 2>/dev/null
  : "$i"
done
exit 1
BEOF

  cat > "$TEST_DIR/docker_simulate.sh" <<'BEOF'
#!/usr/bin/env bash
python3 -c "
import json, sys
try:
    with open('/tmp/kw_test/app_config.json') as f:
        json.load(f)
except Exception:
    sys.exit(1)
" 2>/dev/null
BEOF

  cat > "$TEST_DIR/misleading.py" <<'PYEOF'
#!/usr/bin/env python3
import sys
try:
    open('/etc/ssl/certs/fake_db_cert.pem', 'r')
except FileNotFoundError:
    print('ERROR: Database connection failed', file=sys.stderr)
    sys.exit(1)
PYEOF

  cat > "$TEST_DIR/env_mismatch.py" <<'PYEOF'
#!/usr/bin/env python3
import sys
required_files = [
    '/opt/myapp/config/production.toml',
    '/opt/myapp/secrets/api_key.txt',
    '/opt/myapp/certs/server.crt',
]
for f in required_files:
    try:
        open(f, 'r')
    except FileNotFoundError:
        pass
sys.exit(3)
PYEOF

  cat > "$TEST_DIR/permission_test.txt" <<'TEOF'
This file exists but is unreadable
TEOF

  chmod 000 "$TEST_DIR/permission_test.txt"
  chmod +x "$TEST_DIR/crash_test.py" "$TEST_DIR/network_fail.py" "$TEST_DIR/port_bind.py" \
    "$TEST_DIR/silent_exit.sh" "$TEST_DIR/repeat_fail.sh" "$TEST_DIR/docker_simulate.sh" \
    "$TEST_DIR/misleading.py" "$TEST_DIR/env_mismatch.py"

  if ! gcc "$TEST_DIR/sigsegv_test.c" -o "$TEST_DIR/sigsegv_test" >/dev/null 2>&1; then
    record FAIL "PREP-GCC" "Failed to compile sigsegv_test.c"
  else
    record PASS "PREP-GCC" "Compiled sigsegv_test"
  fi

  local count
  count="$(ls -1 "$TEST_DIR" 2>/dev/null | wc -l | tr -d ' ')"
  if [ "$count" -ge 8 ]; then
    record PASS "PREP-FIXTURES" "Fixtures created ($count items)"
  else
    record FAIL "PREP-FIXTURES" "Expected >=8 fixtures, got $count"
  fi
}

check_prereqs() {
  if [ ! -x ./target/release/kernel-whisperer ]; then
    record FAIL "PREP-BIN" "./target/release/kernel-whisperer not found; run cargo build --release"
    exit 1
  fi

  if ! command -v strace >/dev/null 2>&1; then
    record FAIL "PREP-STRACE" "strace missing"
    exit 1
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    record FAIL "PREP-PY" "python3 missing"
    exit 1
  fi

  record PASS "PREP-REQ" "Prerequisites present"
}

layer7() {
  run_capture "L7_T1" "./target/release/kernel-whisperer --mode strace --no-llm run -- /tmp/kw_test/docker_simulate.sh"
  if contains "$LOG_DIR/L7_T1.out" "app_config.json" && contains "$LOG_DIR/L7_T1.out" "ENOENT"; then
    record PASS "L7-T1" "Silent docker-like failure reveals missing file"
  else
    record FAIL "L7-T1" "Missing ENOENT/app_config.json evidence"
  fi

  run_capture "L7_T2" "./target/release/kernel-whisperer --mode strace --no-llm run -- python3 /tmp/kw_test/misleading.py"
  if contains "$LOG_DIR/L7_T2.out" "fake_db_cert.pem" && contains "$LOG_DIR/L7_T2.out" "ENOENT"; then
    record PASS "L7-T2" "Misleading app message traced to real missing cert"
  else
    record FAIL "L7-T2" "Did not surface fake_db_cert.pem ENOENT"
  fi

  run_capture "L7_T3" "./target/release/kernel-whisperer --mode strace --no-llm run -- python3 /tmp/kw_test/env_mismatch.py"
  if contains "$LOG_DIR/L7_T3.out" "/opt/myapp/config/production.toml" && \
     contains "$LOG_DIR/L7_T3.out" "/opt/myapp/secrets/api_key.txt" && \
     contains "$LOG_DIR/L7_T3.out" "/opt/myapp/certs/server.crt"; then
    record PASS "L7-T3" "Environment mismatch paths surfaced"
  else
    record FAIL "L7-T3" "One or more expected prod-mismatch paths missing"
  fi

  run_capture "L7_T5" "time ./target/release/kernel-whisperer --mode strace --no-llm run -- python3 /tmp/kw_test/crash_test.py"
  if contains "$LOG_DIR/L7_T5.out" "real"; then
    local seconds
    seconds="$(awk '/^real/{print $2}' "$LOG_DIR/L7_T5.out" | tail -1)"
    record PASS "L7-T5" "Timing captured (real=$seconds)"
  else
    record WARN "L7-T5" "time output format unavailable"
  fi
}

layer8() {
  run_capture "L8_T1" "./target/release/kernel-whisperer --mode strace --no-llm run -- true"
  if contains "$LOG_DIR/L8_T1.out" "0 errors" || contains "$LOG_DIR/L8_T1.out" "?"; then
    record PASS "L8-T1" "Short-lived process handled"
  else
    record FAIL "L8-T1" "Unexpected short-lived process output"
  fi

  run_capture "L8_T2" "time ./target/release/kernel-whisperer --mode strace --no-llm run -- find /usr -name '*.so' 2>/dev/null"
  if contains_re "$LOG_DIR/L8_T2.out" "[0-9]+ syscalls analyzed|total"; then
    record PASS "L8-T2" "Stress trace completed"
  else
    record WARN "L8-T2" "Stress trace output missing syscall count marker"
  fi

  run_capture "L8_T3" "./target/release/kernel-whisperer --mode strace --no-llm run --"
  if contains_re "$LOG_DIR/L8_T3.out" "error|required|USAGE|usage"; then
    record PASS "L8-T3" "Empty command rejected gracefully"
  else
    record FAIL "L8-T3" "Empty command rejection unclear"
  fi

  run_capture "L8_T4" "mkdir -p '/tmp/kw_test/path with spaces' && touch '/tmp/kw_test/path with spaces/file.txt' && ./target/release/kernel-whisperer --mode strace --no-llm run -- cat '/tmp/kw_test/path with spaces/nonexistent'"
  if contains "$LOG_DIR/L8_T4.out" "ENOENT" && contains "$LOG_DIR/L8_T4.out" "path with spaces/nonexistent"; then
    record PASS "L8-T4" "Space-containing path handled"
  else
    record FAIL "L8-T4" "Path with spaces not surfaced correctly"
  fi

  run_capture "L8_T6" "./target/release/kernel-whisperer --mode strace --no-llm run -- sleep 2 >'$LOG_DIR/L8_T6_a.out' 2>&1 & pid1=\$!; ./target/release/kernel-whisperer --mode strace --no-llm run -- cat /nonexistent >'$LOG_DIR/L8_T6_b.out' 2>&1 & pid2=\$!; wait \$pid1; wait \$pid2"
  if contains "$LOG_DIR/L8_T6_b.out" "ENOENT"; then
    record PASS "L8-T6" "Concurrent runs completed with expected error capture"
  else
    record FAIL "L8-T6" "Concurrent run missing ENOENT in second instance"
  fi

  run_capture "L8_T7" "LONG_PATH=\$(python3 -c 'print(\"/tmp/\" + \"a\"*200)'); ./target/release/kernel-whisperer --mode strace --no-llm run -- cat \"\$LONG_PATH\""
  if contains "$LOG_DIR/L8_T7.out" "ENOENT"; then
    record PASS "L8-T7" "Long path handled"
  else
    record FAIL "L8-T7" "Long path ENOENT not captured"
  fi

  run_capture "L8_T8" "./target/release/kernel-whisperer --mode strace --no-llm run -- bash -c 'cat /nonexistent; cat /also_nonexistent'"
  if contains "$LOG_DIR/L8_T8.out" "/nonexistent" && contains "$LOG_DIR/L8_T8.out" "/also_nonexistent"; then
    record PASS "L8-T8" "Fork/exec chain errors captured"
  else
    record FAIL "L8-T8" "Did not capture both missing files"
  fi
}

layer9() {
  run_capture "L9_T1" "./target/release/kernel-whisperer --no-llm run -- cat /nonexistent"
  if contains_re "$LOG_DIR/L9_T1.out" "strace fallback|ENOENT|Root Cause|Raw Errors"; then
    record PASS "L9-T1" "Auto mode made visible decision/output"
  else
    record FAIL "L9-T1" "Auto mode output ambiguous"
  fi

  run_capture "L9_T2" "./target/release/kernel-whisperer --mode ebpf --no-llm run -- cat /nonexistent"
  if contains_re "$LOG_DIR/L9_T2.out" "unavailable|strace|ENOENT|not implemented"; then
    record PASS "L9-T2" "eBPF mode fails/works gracefully"
  else
    record FAIL "L9-T2" "eBPF mode behavior unclear"
  fi

  run_capture "L9_T3" "./target/release/kernel-whisperer --mode strace --no-llm run -- cat /nonexistent"
  if contains "$LOG_DIR/L9_T3.out" "ENOENT"; then
    record PASS "L9-T3" "Explicit strace works"
  else
    record FAIL "L9-T3" "Explicit strace missing ENOENT"
  fi

  run_capture "L9_T4" "cat /proc/version"
  if contains_re "$LOG_DIR/L9_T4.out" "Linux version [0-9]+\.[0-9]+"; then
    record PASS "L9-T4" "/proc/version parseable"
  else
    record WARN "L9-T4" "Unusual /proc/version format"
  fi
}

layer10() {
  run_capture "L10_T1" "for cmd in 'cat /nonexistent' 'cat /tmp/kw_test/permission_test.txt' 'python3 /tmp/kw_test/crash_test.py' 'python3 /tmp/kw_test/network_fail.py' '/tmp/kw_test/sigsegv_test' '/tmp/kw_test/silent_exit.sh' 'ls /tmp'; do ./target/release/kernel-whisperer --mode strace --no-llm run -- \$cmd 2>&1 | grep -i 'panic\\|thread.*panicked\\|RUST_BACKTRACE' && echo \"PANIC in: \$cmd\" || echo \"CLEAN: \$cmd\"; done"
  if ! contains "$LOG_DIR/L10_T1.out" "PANIC in:"; then
    record PASS "L10-T1" "No rust panics across scenarios"
  else
    record FAIL "L10-T1" "Panic signature detected"
  fi

  run_capture "L10_T2" "ls /tmp/kw_trace_* 2>/dev/null | wc -l"
  if contains_re "$LOG_DIR/L10_T2.out" "^0$"; then
    record PASS "L10-T2" "No kw_trace tmpfile leaks"
  else
    record FAIL "L10-T2" "kw_trace tempfiles remain"
  fi

  run_capture "L10_T3" "ps aux | grep strace | grep -v grep | wc -l"
  if contains_re "$LOG_DIR/L10_T3.out" "^0$"; then
    record PASS "L10-T3" "No strace zombies"
  else
    record WARN "L10-T3" "Active strace processes detected"
  fi

  run_capture "L10_T4" "cargo build >/dev/null 2>&1 && ./target/debug/kernel-whisperer --mode strace --no-llm run -- cat /nonexistent > /tmp/kw_debug_out.txt 2>&1 && ./target/release/kernel-whisperer --mode strace --no-llm run -- cat /nonexistent > /tmp/kw_release_out.txt 2>&1 && diff /tmp/kw_debug_out.txt /tmp/kw_release_out.txt"
  local l10_t4_rc
  l10_t4_rc="$(cat "$LOG_DIR/L10_T4.rc")"
  if [ "$l10_t4_rc" != "0" ] && [ "$l10_t4_rc" != "1" ]; then
    record FAIL "L10-T4" "Debug/release comparison command failed"
  elif [ -s "$LOG_DIR/L10_T4.out" ]; then
    if contains_re "$LOG_DIR/L10_T4.out" "after [0-9]+ms|0x[0-9a-f]+"; then
      record WARN "L10-T4" "Debug/release differ in non-structural timing/address fields"
    else
      record FAIL "L10-T4" "Debug/release structural diff detected"
    fi
  else
    record PASS "L10-T4" "Debug/release output identical"
  fi

  run_capture "L10_T5" "./target/release/kernel-whisperer --help"
  if contains_re "$LOG_DIR/L10_T5.out" "kernel-whisperer|USAGE|Usage"; then
    record PASS "L10-T5" "Help always available"
  else
    record FAIL "L10-T5" "Help output missing"
  fi

  run_capture "L10_T6" "cargo test"
  if contains_re "$LOG_DIR/L10_T6.out" "test result: ok\\..*0 failed"; then
    record PASS "L10-T6" "Cargo tests green at end"
  else
    record FAIL "L10-T6" "Final cargo test not green"
  fi

  run_capture "L10_T7" "./target/release/kernel-whisperer --mode strace run -- python3 -c \"import pathlib; pathlib.Path('/etc/nginx/conf.d/ghost_site.conf').read_text()\""
  if contains "$LOG_DIR/L10_T7.out" "ghost_site.conf" && contains "$LOG_DIR/L10_T7.out" "ENOENT" && contains_re "$LOG_DIR/L10_T7.out" "Root cause:|Raw Errors"; then
    record PASS "L10-T7" "Flagship demo output captured"
  else
    record FAIL "L10-T7" "Flagship demo missing expected structure/path"
  fi
}

print_summary() {
  log ""
  log "========================================"
  log "E2E SUMMARY ($SCRIPT_NAME)"
  log "PASS=$PASS_COUNT FAIL=$FAIL_COUNT WARN=$WARN_COUNT SKIP=$SKIP_COUNT"
  log "Summary file: $SUMMARY_FILE"
  log "Main log: $LOG_FILE"
  log "========================================"

  cat "$SUMMARY_FILE"

  if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
  fi
}

main() {
  check_prereqs
  prepare_fixtures
  layer7
  layer8
  layer9
  layer10
  print_summary
}

main "$@"
