// Linux-only guard — must be first item in file
#[cfg(not(target_os = "linux"))]
compile_error!("kernel-whisperer only supports Linux.");

mod cli;
mod filter;
mod llm;
mod output;
mod prompt;
mod tracer;

use anyhow::Result;

fn event_display_arg(event: &crate::tracer::SyscallEvent) -> String {
    crate::filter::preferred_path_arg(event).unwrap_or_default()
}

fn print_no_llm_report(ctx: &crate::filter::CrashContext, verbose: bool) {
    const MAX_ERRORS_SHOWN: usize = 25;
    const MAX_FILES_SHOWN: usize = 80;
    let failed = ctx.exit_signal.is_some() || ctx.exit_code.unwrap_or(0) != 0;
    if failed {
        println!("✗  {} exited with code {:?} after {}ms", ctx.process_name, ctx.exit_code.unwrap_or(1), ctx.runtime_ms);
    } else {
        println!("✓  {} exited cleanly after {}ms", ctx.process_name, ctx.runtime_ms);
    }
    println!();
    println!(
        "Syscalls: {} total, {} errors",
        ctx.total_syscalls,
        ctx.error_syscalls.len()
    );
    println!();

    println!("── Raw Errors ──────────────────────────────────────");
    if verbose {
        println!("  verbose mode enabled (showing syscall context below)");
        println!();
        println!("  errors:");
        if ctx.error_syscalls.is_empty() {
            println!("    (none)");
        } else {
            for e in &ctx.error_syscalls {
                println!(
                    "    {}({}) → {} [×{}]",
                    e.syscall_name,
                    event_display_arg(e),
                    e.error.as_ref().map(|x| x.code.as_str()).unwrap_or("?"),
                    e.repeat_count
                );
            }
        }
        println!();
        println!("  all syscall context:");
        for e in &ctx.last_n_syscalls {
            let code = e.error.as_ref().map(|x| x.code.as_str()).unwrap_or("-");
            println!("    {}({}) = {} {}",
                e.syscall_name,
                event_display_arg(e),
                e.return_value,
                code
            );
        }
    } else {
        if ctx.error_syscalls.is_empty() {
            println!("  (none)");
        } else {
            for e in ctx.error_syscalls.iter().take(MAX_ERRORS_SHOWN) {
                println!(
                    "  {}({}) → {} [×{}]",
                    e.syscall_name,
                    event_display_arg(e),
                    e.error.as_ref().map(|x| x.code.as_str()).unwrap_or("?"),
                    e.repeat_count
                );
            }
            if ctx.error_syscalls.len() > MAX_ERRORS_SHOWN {
                println!(
                    "  ... {} additional errors omitted (use --verbose for full context)",
                    ctx.error_syscalls.len() - MAX_ERRORS_SHOWN
                );
            }
        }
    }
    println!();

    println!("── Explanation ─────────────────────────────────────");
    println!("  {}", ctx.deterministic.explanation);
    if let Some(root) = &ctx.deterministic.root_cause_syscall {
        println!();
        println!("  Root cause: {}", root);
    }
    println!();

    println!("── Suggested Fix ───────────────────────────────────");
    println!("  {}", ctx.deterministic.suggested_fix);
    println!();

    println!("FILES ACCESSED:");
    if ctx.unique_files_accessed.is_empty() {
        println!("  (none)");
    } else {
        for f in ctx.unique_files_accessed.iter().take(MAX_FILES_SHOWN) {
            println!("  {}", f);
        }
        if ctx.unique_files_accessed.len() > MAX_FILES_SHOWN {
            println!(
                "  ... {} additional paths omitted",
                ctx.unique_files_accessed.len() - MAX_FILES_SHOWN
            );
        }
    }

    println!("NETWORK ADDRESSES:");
    if ctx.unique_addresses_connected.is_empty() {
        println!("  (none)");
    } else {
        for a in &ctx.unique_addresses_connected {
            println!("  {}", a);
        }
    }

    println!("LAST {} SYSCALLS:", ctx.last_n_syscalls.len());
    for e in &ctx.last_n_syscalls {
        let code = e.error.as_ref().map(|x| x.code.as_str()).unwrap_or("-");
        println!(
            "  {}({}) = {} {}",
            e.syscall_name,
            event_display_arg(e),
            e.return_value,
            code
        );
    }

    println!(
        "confidence: {} · {} syscalls analyzed",
        ctx.confidence, ctx.total_syscalls
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
        )
        .with_target(false)
        .init();

    let args = <cli::Args as clap::Parser>::parse();
    
    match args.command {
        cli::Command::Run { cmd } => {
            let mode = match args.mode {
                cli::Mode::Strace => crate::tracer::TracerMode::Strace,
                cli::Mode::Ebpf => crate::tracer::TracerMode::Ebpf,
                cli::Mode::Auto => crate::tracer::detect_tracer_mode(),
            };

            match mode {
                crate::tracer::TracerMode::Strace
                | crate::tracer::TracerMode::Auto => {
                    let tracer = crate::tracer::strace::StraceTracer;
                    use crate::tracer::Tracer;
                    let output = tracer.run(&cmd)?;
                    let process_name = cmd.first()
                        .and_then(|s| std::path::Path::new(s).file_name())
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();

                    let ctx = crate::filter::build_crash_context(
                        output,
                        &process_name,
                        args.last_n,
                    );

                    if args.no_llm {
                        print_no_llm_report(&ctx, args.verbose);
                        return Ok(());
                    }

                    // Phase 4: LLM call
                    let mut result = crate::llm::query_llm(&ctx, &args.llm_url).await?;
                    if result.root_cause_syscall.is_none() {
                        result.root_cause_syscall = ctx.deterministic.root_cause_syscall.clone();
                    }
                    let llm_unavailable = result.explanation.contains("LLM server unavailable");
                    if result.explanation.trim().is_empty() || llm_unavailable {
                        result.explanation = ctx.deterministic.explanation.clone();
                    }
                    if result.suggested_fix.trim().is_empty()
                        || llm_unavailable
                        || result
                            .suggested_fix
                            .contains("Start the llama-server command shown above")
                    {
                        result.suggested_fix = ctx.deterministic.suggested_fix.clone();
                    }
                    if result.confidence.trim().is_empty() {
                        result.confidence = ctx.confidence.clone();
                    }

                    if args.json {
                        println!("{}", serde_json::to_string_pretty(&result)?);
                        return Ok(());
                    }

                    crate::output::render_result(&ctx, &result);
                }
                crate::tracer::TracerMode::Ebpf => {
                    anyhow::bail!(
                        "eBPF tracer not yet implemented. \
                         Use --mode strace"
                    );
                }
            }
        }
        cli::Command::Attach { .. } => {
            println!("kernel-whisperer: attach not yet implemented");
        }
    }
    
    Ok(())
}
