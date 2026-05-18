#!/bin/bash
source ~/.cargo/env 2>/dev/null || true
export PATH="$HOME/.cargo/bin:$PATH"
cd ~/kernel-whisperer-run
KW="./target/release/kernel-whisperer"

echo "=== ENVIRONMENT ==="
uname -a
rustc --version
which strace
cat /proc/sys/kernel/yama/ptrace_scope
ls /sys/kernel/btf/vmlinux 2>&1
curl -s --max-time 2 http://localhost:8080/v1/models 2>&1 | head -1
echo ""

echo "=== L1: BUILD ==="
echo "-- L1-T1: Debug build"
cargo build 2>&1 | tail -3; echo "exit:$?"
echo "-- L1-T2: Release build"
cargo build --release 2>&1 | tail -3; echo "exit:$?"
echo "-- L1-T3: Binary type"
file $KW
echo "-- L1-T4: Size"
ls -lh $KW | awk '{print $5}'
echo "-- L1-T5: Strip"
nm $KW 2>&1 | head -2
echo "-- L1-T6: Unit tests"
cargo test 2>&1 | tail -8
echo "-- L1-T7: Clippy"
cargo clippy 2>&1 | grep -cE "^warning" ; echo ""
echo "-- L1-T8: Linux guard"
grep -n compile_error src/main.rs

echo ""
echo "=== L2: CLI ==="
echo "-- L2-T1: help"
$KW --help 2>&1
echo "-- L2-T2: version"
$KW --version 2>&1
echo "-- L2-T3: run help"
$KW run --help 2>&1
echo "-- L2-T4: attach help"
$KW attach --help 2>&1
echo "-- L2-T5: bad mode"
$KW --mode badvalue --no-llm run -- ls 2>&1; echo "exit:$?"
echo "-- L2-T6: run no cmd"
$KW run 2>&1; echo "exit:$?"
echo "-- L2-T7: last-n flag"
$KW --no-llm --last-n 5 --mode strace run -- ls /tmp 2>&1 | head -5; echo "exit:$?"
echo "-- L2-T8: attach pid 1"
$KW attach 1 2>&1; echo "exit:$?"
echo "-- L2-T9: attach abc"
$KW attach abc 2>&1; echo "exit:$?"

echo ""
echo "=== L3: STRACE ==="
echo "-- L3-T1: ENOENT"
$KW --mode strace --no-llm run -- cat /nonexistent 2>&1
echo "-- L3-T2: EACCES"
$KW --mode strace --no-llm run -- cat /tmp/kw_test/permission_test.txt 2>&1
echo "-- L3-T3: Multi error"
$KW --mode strace --no-llm run -- python3 /tmp/kw_test/crash_test.py 2>&1
echo "-- L3-T4: ECONNREFUSED"
$KW --mode strace --no-llm run -- python3 /tmp/kw_test/network_fail.py 2>&1
echo "-- L3-T5: bind EACCES"
$KW --mode strace --no-llm run -- python3 /tmp/kw_test/port_bind.py 2>&1
echo "-- L3-T6: SIGSEGV"
$KW --mode strace --no-llm run -- /tmp/kw_test/sigsegv_test 2>&1
echo "-- L3-T7: Silent exit"
$KW --mode strace --no-llm run -- /tmp/kw_test/silent_exit.sh 2>&1
echo "-- L3-T8: Clean exit"
$KW --mode strace --no-llm run -- ls /tmp 2>&1
echo "-- L3-T9: Verbose vs non-verbose"
NORMAL=$($KW --mode strace --no-llm run -- cat /nonexistent 2>&1 | wc -l)
VERBOSE=$($KW --mode strace --no-llm --verbose run -- cat /nonexistent 2>&1 | wc -l)
echo "normal=$NORMAL verbose=$VERBOSE"
echo "-- L3-T10: strace missing"
PATH="" $KW --mode strace --no-llm run -- cat /nonexistent 2>&1; echo "exit:$?"
echo "-- L3-T11: nonexistent binary"
$KW --mode strace --no-llm run -- /nonexistent_binary_xyz 2>&1; echo "exit:$?"
echo "-- L3-T12: Dedup"
cat > /tmp/kw_test/repeat_fail.sh << 'EOF'
#!/bin/bash
for i in $(seq 1 10); do cat /tmp/kw_test/ghost_config.json 2>/dev/null; done
exit 1
EOF
chmod +x /tmp/kw_test/repeat_fail.sh
$KW --mode strace --no-llm run -- /tmp/kw_test/repeat_fail.sh 2>&1
echo "-- L3-T13: Deterministic explanation/fix visible"
$KW --mode strace --no-llm run -- cat /nonexistent 2>&1 | grep -E "Explanation|Suggested Fix|Root cause:" -n

echo ""
echo "=== L5: LLM GRACEFUL ==="
echo "-- L5-T1: LLM down graceful"
$KW --mode strace run -- cat /nonexistent 2>&1; echo "exit:$?"
echo "-- L5-T3: no-llm fast"
time $KW --mode strace --no-llm run -- cat /nonexistent 2>&1 | tail -3
echo "-- L5-T4: wrong URL"
$KW --mode strace --llm-url http://localhost:19876 run -- cat /nonexistent 2>&1; echo "exit:$?"

echo ""
echo "=== L6: OUTPUT ==="
echo "-- L6-T1: error exit symbol"
$KW --mode strace --no-llm run -- cat /nonexistent 2>&1 | head -1
echo "-- L6-T2: clean exit symbol"
$KW --mode strace --no-llm run -- ls /tmp 2>&1 | head -1
echo "-- L6-T5: footer"
$KW --mode strace --no-llm run -- cat /nonexistent 2>&1 | tail -3
echo "-- L6-T7: JSON"
$KW --mode strace --no-llm --json run -- cat /nonexistent 2>&1 > /tmp/kw_test/result.json
python3 -m json.tool /tmp/kw_test/result.json > /dev/null 2>&1; echo "json_valid:$?"
python3 -c "import json; d=json.load(open('/tmp/kw_test/result.json')); print('keys:', sorted(d.keys()))"

echo ""
echo "=== L7: SCENARIOS ==="
echo "-- L7-T1: Silent Docker Exit"
cat > /tmp/kw_test/docker_simulate.sh << 'EOF'
#!/bin/bash
python3 -c "
import json, sys
try:
    with open('/tmp/kw_test/app_config.json') as f:
        config = json.load(f)
except:
    sys.exit(1)
" 2>/dev/null
EOF
chmod +x /tmp/kw_test/docker_simulate.sh
$KW --mode strace --no-llm run -- /tmp/kw_test/docker_simulate.sh 2>&1

echo "-- L7-T2: Misleading error"
cat > /tmp/kw_test/misleading.py << 'PYEOF'
#!/usr/bin/env python3
import sys
try:
    open("/etc/ssl/certs/fake_db_cert.pem", "r")
except FileNotFoundError:
    print("ERROR: Database connection failed", file=sys.stderr)
    sys.exit(1)
PYEOF
$KW --mode strace --no-llm run -- python3 /tmp/kw_test/misleading.py 2>&1

echo ""
echo "=== L8: EDGE CASES ==="
echo "-- L8-T1: short-lived"
$KW --mode strace --no-llm run -- true 2>&1; echo "exit:$?"
echo "-- L8-T3: empty cmd"
$KW --mode strace --no-llm run -- 2>&1; echo "exit:$?"
echo "-- L8-T8: fork children"
$KW --mode strace --no-llm run -- bash -c "cat /nonexistent; cat /also_nonexistent" 2>&1

echo ""
echo "=== L9: AUTO-DETECT ==="
echo "-- L9-T1: auto mode"
$KW --no-llm run -- cat /nonexistent 2>&1 | head -5
echo "-- L9-T2: ebpf mode"
$KW --mode ebpf --no-llm run -- cat /nonexistent 2>&1; echo "exit:$?"

echo ""
echo "=== L10: REGRESSION ==="
echo "-- L10-T1: No panics"
for cmd in "cat /nonexistent" "python3 /tmp/kw_test/crash_test.py" "/tmp/kw_test/sigsegv_test" "ls /tmp"; do
  PANIC=$($KW --mode strace --no-llm run -- $cmd 2>&1 | grep -ci "panic\|thread.*panicked\|RUST_BACKTRACE")
  if [ "$PANIC" -gt 0 ]; then echo "PANIC: $cmd"; else echo "CLEAN: $cmd"; fi
done
echo "-- L10-T2: tmpfile leak"
ls /tmp/kw_trace_* 2>/dev/null | wc -l
echo "-- L10-T3: zombie strace"
ps aux 2>/dev/null | grep strace | grep -v grep | wc -l
echo "-- L10-T5: help always works"
$KW --help > /dev/null 2>&1; echo "help_exit:$?"
echo "-- L10-T6: tests still green"
cargo test 2>&1 | tail -10
echo "-- L10-T7: Flagship demo"
$KW --mode strace --no-llm run -- python3 -c "
import sys
try:
    open('/etc/nginx/conf.d/ghost_site.conf','r')
except FileNotFoundError:
    sys.exit(1)
" 2>&1

echo ""
echo "=== DONE ==="
