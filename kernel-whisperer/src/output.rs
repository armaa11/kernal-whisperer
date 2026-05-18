use owo_colors::OwoColorize;
use crate::filter::CrashContext;
use crate::llm::WhisperResult;

const WRAP_WIDTH:    usize = 72;
const RULE_WIDTH:    usize = 52;
const RULE_CHAR:     char  = '─';
const BOX_TOP_LEFT:  char  = '┌';
const BOX_TOP_RIGHT: char  = '┐';
const BOX_BOTTOM_LEFT:  char = '└';
const BOX_BOTTOM_RIGHT: char = '┘';
const BOX_HORIZONTAL: char  = '─';
const BOX_VERTICAL:   char  = '│';

fn rule(label: &str) -> String {
    let prefix = format!("── {} ", label);
    let remaining = RULE_WIDTH.saturating_sub(prefix.chars().count());
    format!("{}{}", prefix, RULE_CHAR.to_string().repeat(remaining))
}

fn word_wrap(text: &str, width: usize) -> String {
    let mut lines = Vec::new();
    for paragraph in text.lines() {
        let mut current_line = String::new();
        let mut line_len = 0;
        for word in paragraph.split_whitespace() {
            let word_len = word.chars().count();
            
            if current_line.is_empty() {
                // First word on the line
                current_line.push_str(word);
                line_len = word_len;
            } else if line_len + 1 + word_len > width {
                // Time to wrap
                lines.push(current_line);
                current_line = format!("  {}", word); // indent with 2 spaces
                line_len = 2 + word_len;
            } else {
                // Fits on current line
                current_line.push(' ');
                current_line.push_str(word);
                line_len += 1 + word_len;
            }
        }
        if !current_line.is_empty() {
            lines.push(current_line);
        }
    }
    lines.join("\n")
}

fn shell_box(cmd: &str) -> String {
    let inner_width = cmd.chars().count() + 4;
    let horizontal_bar = BOX_HORIZONTAL.to_string().repeat(inner_width);
    
    let top = format!("  {}{}{}", BOX_TOP_LEFT, horizontal_bar, BOX_TOP_RIGHT);
    let middle = format!("  {}  {}  {}", BOX_VERTICAL, cmd, BOX_VERTICAL);
    let bottom = format!("  {}{}{}", BOX_BOTTOM_LEFT, horizontal_bar, BOX_BOTTOM_RIGHT);
    
    format!("{}\n{}\n{}", top, middle, bottom)
}

fn looks_like_shell_command(text: &str) -> bool {
    let t = text.trim();
    let prefixes = [
        "chmod", "chown", "touch", "mkdir", "rm ",
        "systemctl", "docker", "kubectl", "sudo ",
        "export", "echo", "cat ", "ls ", "cp ", "mv "
    ];
    prefixes.iter().any(|p| t.starts_with(p))
}

fn build_exit_info(ctx: &CrashContext) -> String {
    match (&ctx.exit_signal, &ctx.exit_code) {
        (Some(sig), _) => 
            format!("exited with {} after {}ms", sig, ctx.runtime_ms),
        (None, Some(0)) => 
            format!("exited cleanly after {}ms", ctx.runtime_ms),
        (None, Some(n)) => 
            format!("exited with code {} after {}ms", n, ctx.runtime_ms),
        (None, None) => 
            format!("exited after {}ms", ctx.runtime_ms),
    }
}

pub fn render_result(ctx: &CrashContext, result: &WhisperResult) {
    // ── LINE 1: Status ───────────────────────────────────────
    let exit_info = build_exit_info(ctx);
    
    let status_line = if ctx.exit_signal.is_some() 
                      || ctx.exit_code.unwrap_or(0) != 0 {
        format!("✗  {} {}", ctx.process_name, exit_info)
            .red()
            .bold()
            .to_string()
    } else {
        format!("✓  {} {}", ctx.process_name, exit_info)
            .green()
            .bold()
            .to_string()
    };
    println!("{}", status_line);
    println!();
    
    // ── ROOT CAUSE (only if LLM returned one) ────────────────
    if let Some(ref rc) = result.root_cause_syscall {
        println!("{}", rule("Root Cause").yellow().bold());
        println!("  {}", rc.bright_white().bold());
        println!();
    } else {
        // LLM unavailable — show raw errors instead
        println!("{}", rule("Raw Errors").yellow().bold());
        if ctx.error_syscalls.is_empty() {
            println!("  (no syscall errors detected)");
        } else {
            for e in &ctx.error_syscalls {
                let code = e.error.as_ref()
                    .map(|err| err.code.as_str()).unwrap_or("?");
                println!(
                    "  {}({}) → {} [×{}]",
                    e.syscall_name.bright_white(),
                    e.display_arg(),
                    code.red(),
                    e.repeat_count
                );
            }
        }
        println!();
    }
    
    // ── EXPLANATION ──────────────────────────────────────────
    println!("{}", rule("Explanation").cyan().bold());
    let wrapped = word_wrap(&result.explanation, WRAP_WIDTH);
    for line in wrapped.lines() {
        println!("  {}", line);
    }
    println!();
    
    // ── SUGGESTED FIX ────────────────────────────────────────
    println!("{}", rule("Suggested Fix").green().bold());
    if looks_like_shell_command(&result.suggested_fix) {
        println!("{}", shell_box(&result.suggested_fix));
    } else {
        let wrapped_fix = word_wrap(&result.suggested_fix, WRAP_WIDTH);
        for line in wrapped_fix.lines() {
            println!("  {}", line);
        }
    }
    println!();
    
    // ── FOOTER ───────────────────────────────────────────────
    println!(
        "  {}",
        format!(
            "confidence: {} · {} syscalls analyzed",
            result.confidence,
            ctx.total_syscalls
        ).dimmed()
    );
}
