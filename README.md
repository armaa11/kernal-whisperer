# Kernel Whisperer

**A deterministic-first Linux debugging CLI.** Kernel Whisperer traces application syscalls, cuts through the noise, correlates runtime failures, and outputs actionable root-cause analysis in plain English. 

Stop guessing why a process crashed. Let the kernel tell you exactly which file was missing, which port was blocked, or which connection was refused.

## Why this exists

Standard `strace` output is a firehose of thousands of lines of noise. Most "AI debugging tools" blindly feed logs into an LLM and return hallucinations. 

Kernel Whisperer fixes both problems:
1. **Deterministic Filtering:** It uses hardcoded heuristics to strip out memory management, startup probes, and expected failures, isolating the actual fatal syscall.
2. **Evidence-Bounded AI (Optional):** It generates plain-English explanations and concrete fix commands, but the AI is strictly forbidden from hallucinating outside the bounds of the deterministic syscall evidence.

## Installation

You need a Linux environment with `cargo` and `strace` (or `clang`/`libbpf-dev` for eBPF).

```bash
git clone [https://github.com/armano11/kernel-whisperer.git](https://github.com/armano11/kernel-whisperer.git)
cd kernel-whisperer
cargo build --release


Let’s get one thing straight immediately: a README is a static Markdown file. It cannot be "perfectly interactive" on GitHub, GitLab, or any standard repository host. If you want interactivity, you build a web dashboard or a CLI playground. I will give you a highly scannable, deeply understandable static README, and I will build an interactive widget *here* so you can visualize the engine’s logic.

First, let's look at the actual codebase.

### Codebase Analysis

You have built a very pragmatic, well-architected Rust CLI. The separation of concerns between `tracer`, `filter`, `llm`, and `output` is clean. Your core philosophy—"Deterministic-First"—is exactly how diagnostic tools should be built. Relying entirely on LLMs for root cause analysis is a trap, and bounding the LLM’s output using hard syscall evidence (`filter.rs` and `sanitize_with_evidence`) is a robust safeguard against hallucinations.

**The Strengths:**

* **Graceful Degradation:** Falling back from eBPF to `strace` when the kernel lacks BTF, and falling back from the LLM to deterministic text when the server is down, makes this tool highly resilient.
* **Noise Filtering:** `src/filter.rs` is the most valuable part of this codebase. Stripping out the memory management (`mmap`, `brk`) and startup probes (`/etc/ld.so.preload`) is what makes the output actually readable.
* **Safety Constraints:** Forcing the LLM to only explain paths and error codes that actually appear in the trace prevents it from giving generic, useless advice.

**The Flaws & Vulnerabilities:**

* **`strace` Parsing is Brittle:** Your `strace.rs` parser relies on string splitting and character matching. `strace` output is not a stable API. Different versions format arguments differently, and string arguments containing unescaped characters could break your parser.
* **LLM Hardcoding:** In `cli.rs`, the LLM URL defaults to a local `llama.cpp` instance. You should allow parsing a generic base URL and an API key via environment variables so users can plug in OpenAI, Anthropic, or vLLM easily.
* **eBPF Clock Sync:** In `tracer.bpf.c`, you use `bpf_ktime_get_ns()`. This gives kernel boot time, which does not map 1:1 with userspace wall-clock time (`CLOCK_REALTIME`). If you ever need to correlate these trace logs with external application logs, your timestamps will be out of sync.

---

### The README

Here is the revised, highly readable documentation. It focuses strictly on what it does, why it's better than standard tools, and how to use it immediately.

```markdown
# Kernel Whisperer

**A deterministic-first Linux debugging CLI.** Kernel Whisperer traces application syscalls, cuts through the noise, correlates runtime failures, and outputs actionable root-cause analysis in plain English. 

Stop guessing why a process crashed. Let the kernel tell you exactly which file was missing, which port was blocked, or which connection was refused.

## Why this exists

Standard `strace` output is a firehose of thousands of lines of noise. Most "AI debugging tools" blindly feed logs into an LLM and return hallucinations. 

Kernel Whisperer fixes both problems:
1. **Deterministic Filtering:** It uses hardcoded heuristics to strip out memory management, startup probes, and expected failures, isolating the actual fatal syscall.
2. **Evidence-Bounded AI (Optional):** It generates plain-English explanations and concrete fix commands, but the AI is strictly forbidden from hallucinating outside the bounds of the deterministic syscall evidence.

## Installation

You need a Linux environment with `cargo` and `strace` (or `clang`/`libbpf-dev` for eBPF).

```bash
git clone [https://github.com/armano11/kernel-whisperer.git](https://github.com/armano11/kernel-whisperer.git)
cd kernel-whisperer
cargo build --release

```

*The binary will be located at `./target/release/kernel-whisperer*`

## Usage

Kernel Whisperer runs your command, monitors its interaction with the Linux kernel, and catches exactly where it fails.

### 1. Deterministic Mode (Default & Recommended)

Fast, offline, and relies entirely on raw kernel evidence.

```bash
./kernel-whisperer --no-llm run -- cat /nonexistent/file.txt

```

### 2. AI-Enhanced Mode

Connects to a local LLM to translate the raw `errno` into a contextual, beginner-friendly explanation.
*(Requires a local `llama-server` running on port 8080).*

```bash
./kernel-whisperer run -- python3 failing_app.py

```

### Options

```text
  --mode <auto|strace|ebpf>    Force a specific tracer backend.
  --verbose                    Show the full filtered timeline, not just the crash.
  --json                       Output structured JSON for CI/CD pipelines.

```

## How It Works Under the Hood

1. **Trace:** Hooks into `sys_enter` and `sys_exit` via `strace` or eBPF.
2. **Filter:** Discards known background noise (e.g., `ENOENT` on `/etc/selinux/config` during glibc startup).
3. **Analyze:** Identifies fatal errors (like `EACCES`, `ECONNREFUSED`) immediately preceding the process exit signal.
4. **Explain:** Outputs the exact root cause and a suggested shell command to fix it.

```

***

### The Interactive Diagnostic Simulator

To provide the interactivity you asked for, I have built a simulator based on the logic in your `filter.rs` and `llm.rs` files. You can explore how the engine translates raw, noisy syscall traces into clean, deterministic diagnoses.

```json?chameleon
{"component":"LlmGeneratedComponent","props":{"height":"700px","prompt":"Create an interactive 'Syscall Diagnostic Explorer' dashboard. Objective: Allow the user to simulate how the kernel-whisperer engine filters raw syscalls into actionable advice.\n\nData State (Simulated Scenarios):\n1. Scenario: 'Missing Configuration'\n   - Raw Trace: ['openat(AT_FDCWD, \"/etc/ld.so.cache\") -> 0', 'mmap(NULL, 8192) -> 0', 'openat(AT_FDCWD, \"/etc/nginx/ghost_site.conf\") -> ENOENT', 'exit_group(1)']\n   - Filtered Target: 'openat(/etc/nginx/ghost_site.conf) -> ENOENT'\n   - Diagnosis: 'Required path appears missing: /etc/nginx/ghost_site.conf. The process failed while resolving this file/path.'\n   - Fix: 'Verify and create/restore path: ls -l /etc/nginx/ghost_site.conf'\n2. Scenario: 'Port Bind Failure'\n   - Raw Trace: ['socket(AF_INET, SOCK_STREAM) -> 3', 'setsockopt(3, SOL_SOCKET, SO_REUSEADDR) -> 0', 'bind(3, {sa_family=AF_INET, sin_port=htons(80)}) -> EACCES', 'exit_group(1)']\n   - Filtered Target: 'bind(port 80) -> EACCES'\n   - Diagnosis: 'Permission failure. The process identity does not have required access to bind a privileged port.'\n   - Fix: 'Inspect service user privileges or run with elevated capabilities (CAP_NET_BIND_SERVICE).'\n3. Scenario: 'Database Timeout'\n   - Raw Trace: ['epoll_wait(4, ...) -> 1', 'connect(5, {sin_addr=\"10.0.0.5\", sin_port=5432}) -> ETIMEDOUT', 'close(5) -> 0', 'exit_group(1)']\n   - Filtered Target: 'connect(10.0.0.5:5432) -> ETIMEDOUT'\n   - Diagnosis: 'Network operation timed out; route/firewall/remote responsiveness issue is likely.'\n   - Fix: 'Test reachability and policy: ping 10.0.0.5; check firewall/security groups.'\n\nStrategy: Explorer Layout.\n\nInputs:\n- A sidebar or top navigation menu to select one of the three scenarios.\n\nBehavior:\n- When a scenario is selected, display three distinct panels:\n  1. 'Raw Trace': Show the raw syscalls as a scrolling terminal-like block.\n  2. 'Engine Filter': Highlight the specific 'Filtered Target' syscall that the engine isolated, explaining that startup noise (like mmap) was ignored.\n  3. 'Deterministic Output': Display the final 'Diagnosis' and 'Fix' cleanly formatted.\n- Distinguish the panels visually so the user can easily see the transformation pipeline from raw data to human explanation.","id":"im_7886cd3933c69e50"}}

```
