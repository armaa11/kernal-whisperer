# Production Testing Workflow

## 1) Fast gate (every change)

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

## 2) Real-world Linux e2e

Run on Linux/WSL where `strace`, `python3`, and `gcc` are available:

```bash
cargo build --release
bash scripts/e2e_linux.sh
```

Artifacts are written under `/tmp/kw_e2e_logs`:
- full run log
- per-test output files
- pass/fail summary

## 3) Failure triage loop

1. Open the latest summary in `/tmp/kw_e2e_logs/summary_*.txt`.
2. For each failing test, inspect matching output file `L*_T*.out`.
3. Re-run only the failing command from the log.
4. Patch code and re-run `cargo test` + failing e2e command.
5. Re-run full `scripts/e2e_linux.sh` once all targeted failures are fixed.

## 4) High-value checks before release

- `--no-llm` gives deterministic explanation + actionable fix.
- LLM unavailable path remains graceful and non-crashing.
- No temp file leaks (`/tmp/kw_trace_*` count = 0).
- No zombie `strace` process after runs.
- Parser handles malformed/edge syscall lines without panic.
