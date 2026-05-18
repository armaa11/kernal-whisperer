use std::collections::HashSet;
use crate::tracer::SyscallEvent;

#[derive(Debug, Clone, serde::Serialize)]
pub struct DeterministicDiagnosis {
    pub root_cause_syscall: Option<String>,
    pub explanation: String,
    pub suggested_fix: String,
}

#[derive(Debug, serde::Serialize)]
pub struct CrashContext {
    pub process_name:              String,
    pub exit_signal:               Option<String>,
    pub exit_code:                 Option<i32>,
    pub runtime_ms:                u64,
    pub total_syscalls:            usize,
    pub error_syscalls:            Vec<SyscallEvent>,
    pub last_n_syscalls:           Vec<SyscallEvent>,
    pub unique_files_accessed:     Vec<String>,
    pub unique_addresses_connected:Vec<String>,
    pub confidence:                String,
    pub deterministic:             DeterministicDiagnosis,
}

pub fn build_crash_context(
    output: crate::tracer::TracerOutput,
    process_name: &str,
    last_n: usize,
) -> CrashContext {
    let total_syscalls = output.events.len();

    // STEP 1: CAPTURE LAST-N WINDOW
    let last_n_syscalls: Vec<SyscallEvent> = output.events
        .iter()
        .rev()
        .take(last_n)
        .rev()
        .cloned()
        .collect();

    // STEP 2: COLLECT ERROR EVENTS
    let raw_errors: Vec<SyscallEvent> = output.events
        .iter()
        .filter(|e| e.return_value < 0)
        .cloned()
        .collect();

    // STEP 3: REMOVE NOISE
    let filtered_errors: Vec<SyscallEvent> = raw_errors
        .into_iter()
        .filter(|e| {
            let name = e.syscall_name.as_str();
            let err_code = e.error.as_ref().map(|err| err.code.as_str()).unwrap_or("");
            let arg0 = e.args.first().map(|s| s.as_str()).unwrap_or("");
            let arg1 = e.args.get(1).map(|s| s.as_str()).unwrap_or("");

            // Rule 0: If we couldn't parse an errno token, don't treat as actionable error.
            if e.error.is_none() {
                return false;
            }

            // Rule 1: Memory management
            if matches!(name, "mmap" | "munmap" | "mprotect" | "brk" | "mremap" | "madvise" | "mincore") {
                return false;
            }

            // Rule 2: Threading
            if name == "futex" && !matches!(err_code, "ETIMEDOUT" | "EDEADLK" | "EPERM") {
                return false;
            }

            // Rule 3: I/O wait
            if matches!(name, "poll" | "select" | "epoll_wait" | "epoll_pwait" | "ppoll" | "pselect6") 
                && err_code != "EINTR" {
                return false;
            }

            // Rule 4: Pure query calls
            if matches!(name, "getpid" | "getuid" | "gettid" | "getppid" | "getpgid" | "getpgrp" | "getsid" 
                | "clock_gettime" | "gettimeofday" | "time" | "uname" | "getrusage") {
                return false;
            }

            // Rule 4b: newfstatat ENOENT is typically runtime probing noise.
            if name == "newfstatat" && err_code == "ENOENT" {
                return false;
            }

            // Rule 5: Capability probes
            if matches!(name, "prctl" | "capget" | "capset") && err_code == "EPERM" {
                return false;
            }

            // Rule 6: Dynamic loader / SELinux probes are startup noise.
            let startup_noise_path = matches!(
                arg0,
                "/etc/ld.so.preload" | "/selinux" | "/etc/selinux/config"
            ) || matches!(
                arg1,
                "/etc/ld.so.preload" | "/selinux" | "/etc/selinux/config"
            );
            if startup_noise_path {
                return false;
            }

            // Rule 7: language/runtime probing noise for missing optional assets.
            if err_code == "ENOENT" {
                let p0 = arg0.trim_matches('"');
                let p1 = arg1.trim_matches('"');
                let pp = preferred_path_arg(e).unwrap_or_default();
                let pp = pp.trim_matches('"');
                let noisy_prefix = |p: &str| {
                    p.starts_with("/usr/lib/locale/")
                        || p.starts_with("/usr/share/locale/")
                        || p.starts_with("/usr/lib/python")
                        || p.starts_with("/usr/local/lib/python")
                        || p.starts_with("/usr/bin/python")
                        || p == "/usr/pyvenv.cfg"
                        || p == "/usr/bin/pyvenv.cfg"
                        || p == "/usr/bin/pybuilddir.txt"
                        || p == "/proc/sys/crypto/fips_enabled"
                        || p == "/etc/ubuntu-fips"
                        || p.starts_with("/home/") && p.contains("/.cargo/bin/")
                };
                if noisy_prefix(p0) || noisy_prefix(p1) {
                    return false;
                }

                // Rule 8: suppress generic runtime probing misses in system trees.
                if matches!(name, "openat" | "newfstatat" | "statx" | "readlink")
                    && (pp.starts_with("/usr/")
                        || pp.starts_with("/proc/")
                        || pp.starts_with("/sys/")
                        || pp.starts_with("/home/")
                        || pp == "AT_FDCWD"
                        || pp == "<unknown>")
                    && !pp.starts_with("/tmp/")
                    && !pp.starts_with("/etc/")
                    && !pp.starts_with("/opt/")
                {
                    return false;
                }

                if name == "newfstatat" && pp == "AT_FDCWD" {
                    return false;
                }
            }

            true
        })
        .collect();

    // STEP 4: DEDUPLICATE ERROR EVENTS
    let mut error_syscalls: Vec<SyscallEvent> = Vec::new();
    let mut seen: HashSet<(String, String, String)> = HashSet::new();

    for event in filtered_errors {
        let err_code = event.error.as_ref().map(|e| e.code.clone()).unwrap_or_default();
        let dedup_arg = preferred_path_arg(&event).unwrap_or_default();
        let key = (event.syscall_name.clone(), err_code, dedup_arg);

        if !seen.contains(&key) {
            seen.insert(key.clone());
            error_syscalls.push(event);
        } else {
            if let Some(existing) = error_syscalls.iter_mut().find(|e| {
                let e_err_code = e.error.as_ref().map(|e| e.code.clone()).unwrap_or_default();
                let e_dedup_arg = preferred_path_arg(e).unwrap_or_default();
                e.syscall_name == event.syscall_name && e_err_code == key.1 && e_dedup_arg == key.2
            }) {
                existing.repeat_count += 1;
            }
        }
    }

    error_syscalls.sort_by_key(|e| std::cmp::Reverse(error_priority(e)));

    // STEP 5: EXTRACT FILE PATHS
    let mut unique_files_accessed: Vec<String> = Vec::new();
    let mut files_seen: HashSet<String> = HashSet::new();

    for event in &output.events {
        let name = event.syscall_name.as_str();
        if !matches!(name, "open" | "openat" | "creat" | "stat" | "lstat" 
            | "access" | "faccessat" | "unlink" | "unlinkat" 
            | "rename" | "renameat" | "mkdir" | "mkdirat" | "rmdir" 
            | "truncate" | "chmod" | "chown" | "readlink") {
            continue;
        }

        let path_arg_idx = if matches!(name, "openat" | "mkdirat" | "unlinkat" | "faccessat") {
            1
        } else {
            0
        };

        if let Some(raw_path) = event.args.get(path_arg_idx) {
            let path = raw_path.trim_matches('"');
            
            if !path.is_empty() 
                && (path.starts_with('/') || path.starts_with('.'))
                && path != "AT_FDCWD"
                && path != "NULL"
                && path.len() > 1 {
                
                let p_str = path.to_string();
                if !files_seen.contains(&p_str) {
                    files_seen.insert(p_str.clone());
                    unique_files_accessed.push(p_str);
                }
            }
        }
    }

    // STEP 6: EXTRACT NETWORK ADDRESSES
    let mut unique_addresses_connected: Vec<String> = Vec::new();
    let mut addrs_seen: HashSet<String> = HashSet::new();

    for event in &output.events {
        let name = event.syscall_name.as_str();
        if !matches!(name, "connect" | "bind" | "listen" | "accept" | "accept4" 
            | "sendto" | "recvfrom" | "sendmsg" | "recvmsg") {
            continue;
        }

        let joined_args = event.args.join(", ");
        let looks_like_net = joined_args.contains("sin_port")
            || joined_args.contains("inet_addr")
            || joined_args.contains("AF_INET")
            || joined_args.contains("127.0.0.1");
        if looks_like_net {
            let addr = joined_args.trim_matches('"').to_string();
            if !addrs_seen.contains(&addr) {
                addrs_seen.insert(addr.clone());
                unique_addresses_connected.push(addr);
            }
        }
    }

    // STEP 7: COMPUTE CONFIDENCE
    let confidence = compute_confidence(
        &error_syscalls,
        &output.exit_signal,
        &output.exit_code,
        total_syscalls,
    );
    let deterministic = build_deterministic_diagnosis(
        &error_syscalls,
        &output.exit_signal,
        &output.exit_code,
    );

    CrashContext {
        process_name: process_name.to_string(),
        exit_signal: output.exit_signal,
        exit_code: output.exit_code,
        runtime_ms: output.runtime_ms,
        total_syscalls,
        error_syscalls,
        last_n_syscalls,
        unique_files_accessed,
        unique_addresses_connected,
        confidence,
        deterministic,
    }
}

fn build_deterministic_diagnosis(
    error_syscalls: &[SyscallEvent],
    exit_signal: &Option<String>,
    exit_code: &Option<i32>,
) -> DeterministicDiagnosis {
    if let Some(sig) = exit_signal {
        if sig == "SIGSEGV" || sig == "SIGBUS" {
            return DeterministicDiagnosis {
                root_cause_syscall: Some(format!("unknown -> {}", sig)),
                explanation: "Process crashed in memory space; syscall trace does not show direct in-process memory faults.".to_string(),
                suggested_fix: "Run with symbols and capture userspace backtrace (gdb --args <cmd>; run; bt).".to_string(),
            };
        }
    }

    if error_syscalls.is_empty() {
        let explanation = match exit_code {
            Some(0) => "No actionable syscall errors detected and process exited cleanly.".to_string(),
            Some(code) => format!("Process exited with code {} but no actionable syscall errors were captured.", code),
            None => "Process exited without actionable syscall errors in trace.".to_string(),
        };
        return DeterministicDiagnosis {
            root_cause_syscall: None,
            explanation,
            suggested_fix: "Increase trace window (--last-n), run with --verbose, and capture application logs for userspace-level failures.".to_string(),
        };
    }

    let e = &error_syscalls[0];
    let code = e.error.as_ref().map(|x| x.code.as_str()).unwrap_or("?");
    let arg = preferred_path_arg(e).unwrap_or_default();
    let root = format!("{}({}) -> {}", e.syscall_name, arg, code);

    let (explanation, fix) = match code {
        "ENOENT" => (
            format!("Required path appears missing: {}. The process failed while resolving this file/path.", arg),
            format!("Verify and create/restore path: ls -l {}; then fix config/path or deploy missing artifact.", arg),
        ),
        "EACCES" | "EPERM" => (
            format!("Permission failure on {}. The process identity does not have required access.", arg),
            format!("Inspect ownership/mode and service user: ls -l {}; id; then adjust with chmod/chown or service account policy.", arg),
        ),
        "ECONNREFUSED" => (
            "Connection target refused traffic; service is not listening or listener is bound elsewhere.".to_string(),
            "Validate listener state and target endpoint: ss -ltnp; systemctl status <service>; check bind address/port.".to_string(),
        ),
        "ETIMEDOUT" => (
            "Network operation timed out; route/firewall/remote responsiveness issue is likely.".to_string(),
            "Test reachability and policy: ping/traceroute target; check firewall/security groups; confirm remote service health.".to_string(),
        ),
        "EADDRINUSE" => (
            "Bind failed because address/port is already in use by another process.".to_string(),
            "Find and resolve port owner: ss -ltnp | grep <port>; stop conflicting process or reconfigure port.".to_string(),
        ),
        "ENOTDIR" => (
            format!("Path component is not a directory: {}.", arg),
            format!("Inspect each parent path component: namei -l {}; correct file-vs-directory mismatch.", arg),
        ),
        _ => (
            format!("Primary failing syscall is {} with {}.", e.syscall_name, code),
            "Inspect syscall context and surrounding events; compare with app logs to isolate higher-level failure.".to_string(),
        ),
    };

    DeterministicDiagnosis {
        root_cause_syscall: Some(root),
        explanation,
        suggested_fix: fix,
    }
}

fn error_priority(event: &SyscallEvent) -> i32 {
    let code = event.error.as_ref().map(|e| e.code.as_str()).unwrap_or("");
    let path = preferred_path_arg(event).unwrap_or_default();
    let p = path.trim_matches('"');

    let mut score = match code {
        "EACCES" | "EPERM" => 100,
        "ECONNREFUSED" | "ETIMEDOUT" | "EADDRINUSE" => 90,
        "ENOENT" => 80,
        _ => 50,
    };

    if p.starts_with("/tmp/") || p.starts_with("/etc/") || p.starts_with("/opt/") {
        score += 30;
    } else if p.starts_with("/usr/") || p.starts_with("/proc/") || p.starts_with("/sys/") {
        score -= 20;
    }

    if event.repeat_count > 1 {
        score += 5;
    }

    score
}

pub fn preferred_path_arg(event: &SyscallEvent) -> Option<String> {
    let idx = match event.syscall_name.as_str() {
        "openat" | "faccessat" | "newfstatat" | "statx" | "mkdirat" | "unlinkat" | "renameat" => 1,
        _ => 0,
    };
    event.args.get(idx).map(|s| s.clone())
}

pub fn compute_confidence(
    error_syscalls: &[SyscallEvent],
    exit_signal: &Option<String>,
    exit_code: &Option<i32>,
    total_syscalls: usize,
) -> String {
    if total_syscalls < 5 {
        return "low".to_string();
    }

    if error_syscalls.is_empty() {
        if exit_signal.as_deref() == Some("SIGSEGV") || exit_signal.as_deref() == Some("SIGBUS") {
            return "low".to_string();
        } else if *exit_code == Some(0) {
            return "low".to_string();
        } else {
            return "medium".to_string();
        }
    }

    if error_syscalls.len() == 1 {
        return "high".to_string();
    }

    if error_syscalls.len() <= 3 {
        let first_err_code = error_syscalls[0].error.as_ref().map(|e| e.code.as_str()).unwrap_or("");
        let all_same = error_syscalls.iter().all(|e| {
            let code = e.error.as_ref().map(|err| err.code.as_str()).unwrap_or("");
            code == first_err_code
        });

        if all_same {
            return "high".to_string();
        } else {
            return "medium".to_string();
        }
    }

    "medium".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracer::{SyscallError, TracerOutput};

    fn make_event(syscall: &str, arg0: &str, retval: i64, errno: Option<&str>) -> SyscallEvent {
        SyscallEvent {
            pid: 1000,
            tid: 1000,
            syscall_name: syscall.to_string(),
            args: if arg0.is_empty() {
                vec![]
            } else {
                vec![arg0.to_string()]
            },
            return_value: retval,
            error: errno.map(|e| SyscallError {
                code: e.to_string(),
                description: "test".to_string(),
            }),
            timestamp_ns: 0,
            duration_ns: None,
            repeat_count: 1,
        }
    }

    fn make_tracer_output(events: Vec<SyscallEvent>) -> TracerOutput {
        TracerOutput {
            events,
            exit_code: Some(1),
            exit_signal: None,
            runtime_ms: 100,
        }
    }

    #[test]
    fn test_enoent_dedup() {
        let events = vec![
            make_event("openat", "/etc/missing.conf", -1, Some("ENOENT")),
            make_event("openat", "/etc/missing.conf", -1, Some("ENOENT")),
            make_event("openat", "/etc/missing.conf", -1, Some("ENOENT")),
            make_event("mmap", "NULL", -1, Some("ENOMEM")),
            make_event("read", "data", 10, None),
        ];
        let ctx = build_crash_context(make_tracer_output(events), "nginx", 20);
        let openat_errors: Vec<_> = ctx
            .error_syscalls
            .iter()
            .filter(|e| e.syscall_name == "openat")
            .collect();
        assert_eq!(openat_errors.len(), 1);
        assert_eq!(openat_errors[0].repeat_count, 3);
        assert_eq!(ctx.total_syscalls, 5);
    }

    #[test]
    fn test_noise_filtered() {
        let events = vec![
            make_event("getpid", "", -1, Some("EPERM")),
            make_event("gettid", "", -1, Some("EPERM")),
            make_event("clock_gettime", "", -1, Some("EFAULT")),
            make_event("mmap", "NULL", -1, Some("ENOMEM")),
            make_event("futex", "", -1, Some("EAGAIN")),
        ];
        let ctx = build_crash_context(make_tracer_output(events), "test", 20);
        assert!(ctx.error_syscalls.is_empty());
    }

    #[test]
    fn test_file_path_extraction() {
        let mut e1 = make_event("openat", "AT_FDCWD", 3, None);
        e1.args = vec!["AT_FDCWD".to_string(), "/etc/nginx.conf".to_string()];
        let e2 = make_event("stat", "/var/log/nginx/", 0, None);
        let mut e3 = make_event("openat", "AT_FDCWD", -1, Some("ENOENT"));
        e3.args = vec!["AT_FDCWD".to_string(), "/etc/missing.conf".to_string()];
        let e4 = make_event("openat", "AT_FDCWD", 5, None);
        let events = vec![e1, e2, e3, e4];
        let ctx = build_crash_context(make_tracer_output(events), "nginx", 20);
        assert!(
            ctx.unique_files_accessed
                .contains(&"/etc/nginx.conf".to_string())
        );
        assert!(
            ctx.unique_files_accessed
                .contains(&"/var/log/nginx/".to_string())
        );
        assert!(
            ctx.unique_files_accessed
                .contains(&"/etc/missing.conf".to_string())
        );
        assert!(!ctx.unique_files_accessed.contains(&"AT_FDCWD".to_string()));
    }

    #[test]
    fn test_sigsegv_no_errors() {
        let events: Vec<SyscallEvent> = (0..20)
            .map(|i| make_event("read", "data", i as i64, None))
            .collect();
        let output = TracerOutput {
            events,
            exit_code: None,
            exit_signal: Some("SIGSEGV".to_string()),
            runtime_ms: 500,
        };
        let ctx = build_crash_context(output, "myapp", 20);
        assert_eq!(ctx.confidence, "low");
        assert_eq!(
            ctx.deterministic.root_cause_syscall.as_deref(),
            Some("unknown -> SIGSEGV")
        );
    }

    #[test]
    fn test_deterministic_diagnosis_prefers_primary_error() {
        let mut e1 = make_event("openat", "AT_FDCWD", -1, Some("ENOENT"));
        e1.args = vec!["AT_FDCWD".to_string(), "/etc/missing.conf".to_string()];
        let e2 = make_event("connect", "127.0.0.1:5432", -1, Some("ECONNREFUSED"));
        let output = make_tracer_output(vec![e1, e2]);
        let ctx = build_crash_context(output, "svc", 20);

        let root = ctx
            .deterministic
            .root_cause_syscall
            .as_deref()
            .unwrap_or("");
        assert!(root.contains("openat"));
        assert!(root.contains("ENOENT"));
        assert!(ctx
            .deterministic
            .suggested_fix
            .contains("ls -l /etc/missing.conf"));
    }
}
