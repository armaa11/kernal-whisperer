pub const SYSTEM_PROMPT: &str = r#"You are a Linux systems debugger. You analyze syscall traces from crashed processes and explain the root cause in plain English for developers.

You will receive:
- Process name and exit information
- Failed syscalls with their error codes and repeat counts
- The last syscalls before process exit
- File paths the process accessed
- Network addresses the process attempted

RESPOND IN EXACTLY THIS FORMAT. No preamble. No explanation of your reasoning. No markdown. Just these 4 lines:

ROOT_CAUSE_SYSCALL: <syscall_name>(<first_arg>) → <error_code>
EXPLANATION: <2-3 sentences using the actual paths and values from the trace>
SUGGESTED_FIX: <1-2 concrete actionable commands or config changes>
CONFIDENCE: <high|medium|low>

RULES:
- Do not invent facts. Only use values present in the trace context.
- Use actual file paths from the trace. Never use placeholders like <path> or /your/path.
- ENOENT: name the exact missing file and explain why it might be missing
- EACCES or EPERM: identify the permission mismatch — what uid/gid vs what the file requires
- ECONNREFUSED: name the exact port or socket that was unreachable
- EADDRINUSE: name the exact port already in use
- SIGSEGV with no syscall errors: respond with ROOT_CAUSE_SYSCALL: unknown → SIGSEGV and explain it's a memory crash not visible in syscall trace
- CONFIDENCE must match the value provided in the context
- If deterministic diagnosis is present, do not contradict it unless stronger direct syscall evidence exists in FAILED SYSCALLS.
- SUGGESTED_FIX must be actionable: a real shell command or config change, not advice like "check your configuration""#;

pub fn format_context(ctx: &crate::filter::CrashContext) -> String {
    let exit_info = match (&ctx.exit_signal, ctx.exit_code) {
        (Some(signal), _) => format!("exited with signal {}", signal),
        (None, Some(0)) => "exited cleanly".to_string(),
        (None, Some(n)) => format!("exited with code {}", n),
        (None, None) => "exited (unknown)".to_string(),
    };

    let mut out = String::new();
    out.push_str("---\n");
    out.push_str(&format!("PROCESS: {} ({} after {}ms)\n", ctx.process_name, exit_info, ctx.runtime_ms));
    out.push_str(&format!("TOTAL SYSCALLS OBSERVED: {}\n", ctx.total_syscalls));
    out.push_str(&format!("CONFIDENCE LEVEL: {}\n\n", ctx.confidence));
    out.push_str("DETERMINISTIC DIAGNOSIS:\n");
    if let Some(root) = &ctx.deterministic.root_cause_syscall {
        out.push_str(&format!("  root: {}\n", root));
    } else {
        out.push_str("  root: (none)\n");
    }
    out.push_str(&format!("  explanation: {}\n", ctx.deterministic.explanation));
    out.push_str(&format!("  suggested_fix: {}\n\n", ctx.deterministic.suggested_fix));

    out.push_str("FAILED SYSCALLS:\n");
    if ctx.error_syscalls.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for e in &ctx.error_syscalls {
            let err_code = e.error.as_ref().map(|err| err.code.as_str()).unwrap_or("");
            if let Some(first_arg) = e.args.first() {
                out.push_str(&format!("  {}({}) → {} [×{}]\n", e.syscall_name, first_arg, err_code, e.repeat_count));
            } else {
                out.push_str(&format!("  {}() → {} [×{}]\n", e.syscall_name, err_code, e.repeat_count));
            }
        }
    }
    out.push_str("\n");

    let mut last_n_str = String::new();
    for e in &ctx.last_n_syscalls {
        if let Some(first_arg) = e.args.first() {
            last_n_str.push_str(&format!("  {}({}) = {}\n", e.syscall_name, first_arg, e.return_value));
        } else {
            last_n_str.push_str(&format!("  {}() = {}\n", e.syscall_name, e.return_value));
        }
    }

    let mut files_str = String::new();
    if ctx.unique_files_accessed.is_empty() {
        files_str.push_str("FILES ACCESSED: (none)\n");
    } else {
        files_str.push_str(&format!("FILES ACCESSED: {}\n", ctx.unique_files_accessed.join(", ")));
    }

    let mut net_str = String::new();
    if ctx.unique_addresses_connected.is_empty() {
        net_str.push_str("NETWORK ADDRESSES: (none)\n");
    } else {
        net_str.push_str(&format!("NETWORK ADDRESSES: {}\n", ctx.unique_addresses_connected.join(", ")));
    }

    let footer = "---\n";

    // HARD LIMIT: Check if length exceeds 3000
    // Estimate size first
    let mut temp_full = out.clone();
    temp_full.push_str(&format!("LAST {} SYSCALLS BEFORE EXIT:\n", ctx.last_n_syscalls.len()));
    temp_full.push_str(&last_n_str);
    temp_full.push_str("\n");
    temp_full.push_str(&files_str);
    temp_full.push_str("\n");
    temp_full.push_str(&net_str);
    temp_full.push_str(footer);

    if temp_full.len() > 3000 && ctx.last_n_syscalls.len() > 10 {
        let truncated_len = 10;
        out.push_str(&format!("LAST {} SYSCALLS BEFORE EXIT:\n", truncated_len));
        for e in ctx.last_n_syscalls.iter().take(truncated_len) {
            if let Some(first_arg) = e.args.first() {
                out.push_str(&format!("  {}({}) = {}\n", e.syscall_name, first_arg, e.return_value));
            } else {
                out.push_str(&format!("  {}() = {}\n", e.syscall_name, e.return_value));
            }
        }
        out.push_str("  [truncated for LLM context limit]\n");
    } else {
        out.push_str(&format!("LAST {} SYSCALLS BEFORE EXIT:\n", ctx.last_n_syscalls.len()));
        out.push_str(&last_n_str);
    }

    out.push_str("\n");
    out.push_str(&files_str);
    out.push_str("\n");
    out.push_str(&net_str);
    out.push_str(footer);

    out
}
