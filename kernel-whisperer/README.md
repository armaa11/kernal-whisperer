# Kernel Whisperer

Kernel Whisperer is a Linux runtime debugging CLI that traces a command's syscalls and explains failures in plain English.

It is built with a deterministic-first architecture:
- Trace collection (`strace` today, eBPF planned)
- Deterministic correlation and diagnosis
- Optional LLM enhancement for explanation quality

## Why This Exists

Most production failures are not solved by "AI guesses." They are solved by evidence:
- missing files
- permission errors
- connection failures
- environment mismatches

Kernel Whisperer prioritizes deterministic evidence and only uses AI as an optional interpretation layer.

## Current Status

- Linux-only binary
- `strace` backend production-ready
- eBPF backend not implemented yet (graceful fallback)
- Deterministic diagnostics available without any LLM
- CI checks enabled (format, build, clippy, tests)

## Install

### Build from source

```bash
cargo build --release
```

Binary path:

```bash
./target/release/kernel-whisperer
```

## Quick Start

### Deterministic mode (recommended default)

```bash
./target/release/kernel-whisperer --mode strace --no-llm run -- cat /nonexistent
```

### Auto mode (falls back to strace)

```bash
./target/release/kernel-whisperer --no-llm run -- python3 app.py
```

### Optional AI mode

Start local `llama-server` on `http://localhost:8080`, then:

```bash
./target/release/kernel-whisperer --mode strace run -- python3 app.py
```

## CLI

```text
kernel-whisperer [OPTIONS] <COMMAND>

Commands:
  run -- <CMD...>     Trace a spawned command
  attach <PID>        Attach mode (not implemented yet)

Options:
  --mode <auto|strace|ebpf>
  --llm-url <URL>
  --no-llm
  --verbose
  --last-n <N>
  --json
```

## Typical Output

- Root cause syscall + errno
- Deterministic explanation
- Suggested fix
- Files accessed
- Network addresses
- Last-N syscall timeline

## Testing

Fast local checks:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

Real-world Linux validation:

```bash
bash scripts/e2e_linux.sh
```

See [TESTING.md](./TESTING.md) for full workflow and triage loop.

## Architecture

1. `src/tracer/`:
   syscall capture and parsing
2. `src/filter.rs`:
   noise filtering, deduplication, deterministic diagnosis
3. `src/llm.rs` + `src/prompt.rs`:
   optional LLM request + evidence-bounded sanitization
4. `src/output.rs`:
   terminal rendering

## Roadmap

- eBPF backend implementation
- install script / package distribution
- distro matrix testing
- richer deterministic signature library
- attach mode implementation

## Safety Model

- Deterministic analysis is primary
- LLM is optional and constrained by observed evidence
- On LLM failure/unavailability, deterministic output remains complete and actionable

