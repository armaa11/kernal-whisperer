use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Context;

use super::{SyscallError, SyscallEvent, Tracer, TracerOutput};

// ── Public struct ─────────────────────────────────────────

pub struct StraceTracer;

impl Tracer for StraceTracer {
    fn run(&self, cmd: &[String]) -> anyhow::Result<TracerOutput> {
        struct TmpfileGuard(std::path::PathBuf);
        impl Drop for TmpfileGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }

        let start = std::time::Instant::now();
        let tmpfile = build_tmpfile_path();
        let _guard = TmpfileGuard(tmpfile.clone());
        let (exit_code, _) = spawn_strace(cmd, &tmpfile)?;
        let (events, exit_signal) = parse_strace_file(&tmpfile)?;
        Ok(TracerOutput {
            events,
            exit_code,
            exit_signal,
            runtime_ms: start.elapsed().as_millis() as u64,
        })
    }
}

// ── Private functions ──────────────────────────────────────

fn build_tmpfile_path() -> PathBuf {
    let kw_parent_pid = std::process::id();
    let suffix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() % 1_000_000)
        .unwrap_or(0);
    PathBuf::from(format!("/tmp/kw_trace_{}_{}.log", kw_parent_pid, suffix))
}

fn spawn_strace(
    cmd: &[String],
    tmpfile: &Path,
) -> anyhow::Result<(Option<i32>, Option<String>)> {
    let tmpfile_str = tmpfile
        .to_str()
        .context("tmpfile path is not valid UTF-8")?;

    let mut strace_cmd = std::process::Command::new("strace");
    strace_cmd
        .arg("-f")
        .arg("-tt")
        .arg("-T")
        .arg("-e")
        .arg("trace=all")
        .arg("-o")
        .arg(tmpfile_str);

    for arg in cmd {
        strace_cmd.arg(arg);
    }

    let mut child = match strace_cmd.spawn() {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!(
                "strace not found on PATH. \
                 Install with: sudo apt install strace"
            );
        }
        Err(e) => {
            return Err(anyhow::anyhow!("failed to spawn strace: {}", e));
        }
    };

    let status = child.wait().context("failed to wait for strace")?;
    Ok((status.code(), None))
}

fn parse_strace_file(
    path: &Path,
) -> anyhow::Result<(Vec<SyscallEvent>, Option<String>)> {
    let file =
        std::fs::File::open(path).context("failed to open strace output file")?;
    let reader = std::io::BufReader::new(file);

    let mut events = Vec::new();
    let mut exit_signal: Option<String> = None;
    let mut strace_diagnostics: Vec<String> = Vec::new();

    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!("failed to read strace line: {}", e);
                continue;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // CASE A — unfinished or resumed
        if trimmed.contains("<unfinished") || trimmed.contains("<... ") {
            tracing::trace!("skipping unfinished/resumed: {}", trimmed);
            continue;
        }

        // CASE B — signal line
        if trimmed.contains("--- SIG") {
            if let Some(signal) = extract_signal(trimmed) {
                exit_signal = Some(signal);
            }
            continue;
        }

        // CASE C — exit_group or = ?
        if trimmed.contains("= ?") {
            tracing::trace!("skipping = ? line: {}", trimmed);
            continue;
        }

        // Skip +++ lines
        if trimmed.starts_with("+++") || trimmed.contains("+++ exited")
            || trimmed.contains("+++ killed")
        {
            tracing::trace!("skipping exit line: {}", trimmed);
            continue;
        }

        // Collect strace diagnostic lines instead of silently dropping them.
        // These appear when the target binary doesn't exist, can't be exec'd, etc.
        if trimmed.starts_with("strace:") {
            strace_diagnostics.push(trimmed.to_string());
            continue;
        }

        // CASE D — normal syscall
        match parse_syscall_line(trimmed) {
            Ok(Some(event)) => events.push(event),
            Ok(None) => {
                tracing::trace!("unrecognized format: {}", trimmed);
            }
            Err(e) => {
                tracing::warn!("parse error: {} — {}", trimmed, e);
            }
        }
    }

    // If strace produced diagnostics but no actual syscall events,
    // the target likely failed to launch. Bail with the diagnostic
    // so the user sees a clear message instead of "0 total, 0 errors".
    if events.is_empty() && !strace_diagnostics.is_empty() {
        anyhow::bail!(
            "strace could not trace the target command:\n  {}",
            strace_diagnostics.join("\n  ")
        );
    }

    Ok((events, exit_signal))
}

fn parse_syscall_line(line: &str) -> anyhow::Result<Option<SyscallEvent>> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(None);
    }

    // Step 1 — Extract PID (first numeric token)
    let pid_end = match line.find(|c: char| !c.is_ascii_digit()) {
        Some(pos) if pos > 0 => pos,
        _ => return Ok(None),
    };
    let pid: u32 = line[..pid_end]
        .parse()
        .context("invalid PID")?;
    let rest = line[pid_end..].trim_start();

    // Step 2 — Skip optional timestamp (HH:MM:SS.ffffff from -tt)
    let rest = skip_timestamp(rest);

    // Step 3 — Find syscall name
    let paren_pos = match rest.find('(') {
        Some(pos) => pos,
        None => return Ok(None),
    };
    let syscall_name = rest[..paren_pos].trim().to_string();
    if syscall_name.is_empty() || syscall_name.contains(' ') {
        return Ok(None);
    }

    // Step 4 — Find " = " marker
    let eq_marker = " = ";
    let eq_pos = match rest.find(eq_marker) {
        Some(pos) => pos,
        None => return Ok(None),
    };

    // Extract args between first '(' and last ')' before " = "
    let call_section = &rest[..eq_pos];
    let last_rparen = match call_section.rfind(')') {
        Some(pos) => pos,
        None => return Ok(None),
    };
    let args_str = &rest[paren_pos + 1..last_rparen];
    let args: Vec<String> = if args_str.trim().is_empty() {
        Vec::new()
    } else {
        split_top_level_args(args_str)
            .into_iter()
            .take(4)
            .map(|s| unquote(s.trim()))
            .collect()
    };

    // Step 5 — Extract return value
    let after_eq = &rest[eq_pos + eq_marker.len()..];
    let retval_token = after_eq.split_whitespace().next().unwrap_or("0");
    let return_value = parse_retval(retval_token);

    // Step 6 — Extract errno (only if return_value < 0)
    let error = if return_value < 0 {
        extract_errno(after_eq)
    } else {
        None
    };

    // Step 7 — Extract duration
    let duration_ns = extract_duration(after_eq);

    Ok(Some(SyscallEvent {
        pid,
        tid: pid,
        syscall_name,
        args,
        return_value,
        error,
        timestamp_ns: 0,
        duration_ns,
        repeat_count: 1,
    }))
}

fn skip_timestamp(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 8
        && bytes[0].is_ascii_digit()
        && bytes[1].is_ascii_digit()
        && bytes[2] == b':'
        && bytes[5] == b':'
    {
        match s.find(' ') {
            Some(pos) => s[pos..].trim_start(),
            None => s,
        }
    } else {
        s
    }
}

fn extract_signal(line: &str) -> Option<String> {
    let marker = "--- SIG";
    let start = line.find(marker)?;
    let after = &line[start + 4..]; // skip "--- "
    let end = after
        .find(|c: char| c == ' ' || c == '{')
        .unwrap_or(after.len());
    let signal = after[..end].trim();
    if signal.is_empty() {
        None
    } else {
        Some(signal.to_string())
    }
}

fn extract_errno(after_eq: &str) -> Option<SyscallError> {
    let mut tokens = after_eq.split_whitespace();
    tokens.next(); // skip return value
    let candidate = tokens.next()?;
    if is_known_errno(candidate) {
        Some(SyscallError {
            code: candidate.to_string(),
            description: errno_description(candidate).to_string(),
        })
    } else {
        None
    }
}

fn extract_duration(s: &str) -> Option<u64> {
    let angle_start = s.rfind('<')?;
    let angle_end = s.rfind('>')?;
    if angle_end <= angle_start {
        return None;
    }
    let duration_str = &s[angle_start + 1..angle_end];
    let secs: f64 = duration_str.parse().ok()?;
    Some((secs * 1_000_000_000.0) as u64)
}

fn parse_retval(s: &str) -> i64 {
    let s = s.trim().trim_end_matches('?');
    if s.starts_with("0x") || s.starts_with("0X") {
        i64::from_str_radix(&s[2..], 16).unwrap_or(0)
    } else {
        s.parse::<i64>().unwrap_or(0)
    }
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn split_top_level_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_string = false;
    let mut escape = false;
    let mut depth_paren = 0i32;
    let mut depth_brace = 0i32;
    let mut depth_bracket = 0i32;

    for ch in s.chars() {
        if in_string {
            buf.push(ch);
            if escape {
                escape = false;
                continue;
            }
            if ch == '\\' {
                escape = true;
                continue;
            }
            if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => {
                in_string = true;
                buf.push(ch);
            }
            '(' => {
                depth_paren += 1;
                buf.push(ch);
            }
            ')' => {
                depth_paren -= 1;
                buf.push(ch);
            }
            '{' => {
                depth_brace += 1;
                buf.push(ch);
            }
            '}' => {
                depth_brace -= 1;
                buf.push(ch);
            }
            '[' => {
                depth_bracket += 1;
                buf.push(ch);
            }
            ']' => {
                depth_bracket -= 1;
                buf.push(ch);
            }
            ',' if depth_paren == 0 && depth_brace == 0 && depth_bracket == 0 => {
                out.push(buf.trim().to_string());
                buf.clear();
            }
            _ => buf.push(ch),
        }
    }

    if !buf.trim().is_empty() {
        out.push(buf.trim().to_string());
    }
    out
}

fn is_known_errno(s: &str) -> bool {
    matches!(
        s,
        "ENOENT"
            | "EACCES"
            | "EPERM"
            | "ECONNREFUSED"
            | "ETIMEDOUT"
            | "EADDRINUSE"
            | "EEXIST"
            | "EAGAIN"
            | "EINTR"
            | "EBADF"
            | "ENOMEM"
            | "ENOSPC"
            | "EROFS"
            | "ENOTDIR"
            | "EISDIR"
            | "ELOOP"
            | "EMFILE"
            | "ENFILE"
            | "EXDEV"
            | "EFAULT"
            | "EBUSY"
            | "ENOTSUP"
            | "EOPNOTSUPP"
    )
}

fn errno_description(code: &str) -> &'static str {
    match code {
        "ENOENT" => "No such file or directory",
        "EACCES" => "Permission denied",
        "EPERM" => "Operation not permitted",
        "ECONNREFUSED" => "Connection refused",
        "ETIMEDOUT" => "Connection timed out",
        "EADDRINUSE" => "Address already in use",
        "EEXIST" => "File already exists",
        "EAGAIN" => "Resource temporarily unavailable",
        "EINTR" => "Interrupted system call",
        "EBADF" => "Bad file descriptor",
        "ENOMEM" => "Out of memory",
        "ENOSPC" => "No space left on device",
        "EROFS" => "Read-only file system",
        "ENOTDIR" => "Not a directory",
        "EISDIR" => "Is a directory",
        "ELOOP" => "Too many symbolic links",
        "EMFILE" => "Too many open files",
        "ENFILE" => "File table overflow",
        "EXDEV" => "Cross-device link",
        "EFAULT" => "Bad address",
        "EBUSY" => "Device or resource busy",
        _ => "System error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_syscall_line_extracts_openat_error() {
        let line = r#"12345 12:34:56.123456 openat(AT_FDCWD, "/etc/missing.conf", O_RDONLY) = -1 ENOENT (No such file or directory) <0.000012>"#;
        let event = parse_syscall_line(line)
            .expect("parse should succeed")
            .expect("event should exist");

        assert_eq!(event.pid, 12345);
        assert_eq!(event.syscall_name, "openat");
        assert_eq!(event.args[0], "AT_FDCWD");
        assert_eq!(event.args[1], "/etc/missing.conf");
        assert_eq!(event.return_value, -1);
        assert_eq!(
            event.error.as_ref().map(|e| e.code.as_str()),
            Some("ENOENT")
        );
        assert!(event.duration_ns.is_some());
    }

    #[test]
    fn parse_syscall_line_handles_hex_return_value() {
        let line = r#"77777 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f9abcde0000 <0.000001>"#;
        let event = parse_syscall_line(line)
            .expect("parse should succeed")
            .expect("event should exist");

        assert_eq!(event.syscall_name, "mmap");
        assert!(event.return_value > 0);
        assert!(event.error.is_none());
    }

    #[test]
    fn parse_syscall_line_skips_invalid_line() {
        let line = "this is not a syscall line";
        let event = parse_syscall_line(line).expect("function should not error");
        assert!(event.is_none());
    }

    #[test]
    fn split_top_level_args_respects_nested_structures() {
        let args = r#"AT_FDCWD, "/tmp/a,b", {sa_family=AF_INET, sin_port=htons(8080)}, [1,2,3]"#;
        let parts = split_top_level_args(args);
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "AT_FDCWD");
        assert_eq!(parts[1], r#""/tmp/a,b""#);
        assert!(parts[2].contains("sin_port=htons(8080)"));
        assert_eq!(parts[3], "[1,2,3]");
    }

    #[test]
    fn extract_signal_parses_sigsegv() {
        let line = "--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR} ---";
        assert_eq!(extract_signal(line).as_deref(), Some("SIGSEGV"));
    }
}
