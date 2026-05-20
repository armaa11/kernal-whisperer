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
