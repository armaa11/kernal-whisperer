#![allow(dead_code)]

pub mod strace;
pub mod ebpf;

#[derive(Debug, Clone, serde::Serialize)]
pub struct SyscallEvent {
    pub pid:            u32,
    pub tid:            u32,
    pub syscall_name:   String,
    pub args:           Vec<String>,
    pub return_value:   i64,
    pub error:          Option<SyscallError>,
    pub timestamp_ns:   u64,
    pub duration_ns:    Option<u64>,
    pub repeat_count:   u32,
}

impl SyscallEvent {
    /// Returns the most meaningful argument for display.
    /// For *at() syscalls (openat, mkdirat, etc.) the path
    /// is args[1], not args[0] which is just AT_FDCWD.
    pub fn display_arg(&self) -> &str {
        let name = self.syscall_name.as_str();
        if matches!(name, "openat" | "mkdirat" | "unlinkat" | "faccessat" | "renameat") {
            self.args.get(1)
                .or_else(|| self.args.first())
                .map(|s| s.as_str())
                .unwrap_or("")
        } else {
            self.args.first().map(|s| s.as_str()).unwrap_or("")
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SyscallError {
    pub code:        String,   // "ENOENT", "EACCES", etc.
    pub description: String,   // "No such file or directory"
}

#[derive(Debug)]
pub struct TracerOutput {
    pub events:       Vec<SyscallEvent>,
    pub exit_code:    Option<i32>,
    pub exit_signal:  Option<String>,
    pub runtime_ms:   u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TracerMode { Auto, Strace, Ebpf }

pub trait Tracer {
    fn run(&self, cmd: &[String]) -> anyhow::Result<TracerOutput>;
}

pub fn detect_tracer_mode() -> TracerMode {
    let version_str = std::fs::read_to_string("/proc/version")
        .unwrap_or_default();

    let kernel_ok = parse_kernel_version(&version_str)
        .map(|(major, minor)| major > 5 || (major == 5 && minor >= 8))
        .unwrap_or(false);

    let btf_ok = std::path::Path::new("/sys/kernel/btf/vmlinux").exists();

    // eBPF backend is not implemented yet; keep auto mode reliable.
    if kernel_ok && btf_ok {
        eprintln!(
            "\x1b[2m  using strace fallback \
             (eBPF backend not implemented yet)\x1b[0m"
        );
        return TracerMode::Strace;
    }

    eprintln!(
        "\x1b[2m  using strace fallback \
         (kernel < 5.8 or BTF unavailable)\x1b[0m"
    );
    TracerMode::Strace
}

fn parse_kernel_version(version_str: &str) -> Option<(u32, u32)> {
    let after_version = version_str.split("version ").nth(1)?;
    let version_token = after_version.split_whitespace().next()?;
    let mut parts = version_token.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    Some((major, minor))
}
