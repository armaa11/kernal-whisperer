use crate::tracer::TracerOutput;

#[cfg(feature = "ebpf_available")]
mod ebpf_impl {
    use crate::tracer::{SyscallError, SyscallEvent, TracerOutput};

    pub fn run_ebpf(cmd: &[String]) -> anyhow::Result<TracerOutput> {
        let start = std::time::Instant::now();
        
        // Step 1: Load BPF object
        let bpf_bytes = include_bytes!(
            concat!(env!("OUT_DIR"), "/tracer.bpf.o")
        );
        
        let mut bpf = libbpf_rs::ObjectBuilder::default()
            .open_memory("tracer", bpf_bytes)
            .map_err(|e| anyhow::anyhow!(
                "Failed to open BPF object: {}. \
                 Is kernel 5.8+ with BTF support?", e
            ))?
            .load()
            .map_err(|e| anyhow::anyhow!(
                "BPF verifier rejected program: {}. \
                 This usually means kernel is too old.", e
            ))?;
        
        // Step 2: Spawn child process
        if cmd.is_empty() {
            anyhow::bail!("No command provided to eBPF tracer");
        }
        let mut child = std::process::Command::new(&cmd[0])
            .args(&cmd[1..])
            .spawn()
            .map_err(|e| anyhow::anyhow!(
                "Failed to spawn {}: {}", cmd[0], e
            ))?;
        
        let child_pid = child.id();
        
        // Step 3: Set target PID in BPF map
        let target_map = bpf.map_mut("target_pid_map")
            .ok_or_else(|| anyhow::anyhow!(
                "BPF map 'target_pid_map' not found"
            ))?;
        let key: u32 = 0;
        let val: u32 = child_pid;
        target_map.update(
            &key.to_ne_bytes(),
            &val.to_ne_bytes(),
            libbpf_rs::MapFlags::ANY,
        )?;
        
        // Step 4: Attach tracepoints
        let enter_prog = bpf.prog_mut("handle_sys_enter")
            .ok_or_else(|| anyhow::anyhow!(
                "BPF prog 'handle_sys_enter' not found"
            ))?;
        let _enter_link = enter_prog.attach_tracepoint(
            "raw_syscalls", "sys_enter"
        )?;
        
        let exit_prog = bpf.prog_mut("handle_sys_exit")
            .ok_or_else(|| anyhow::anyhow!(
                "BPF prog 'handle_sys_exit' not found"
            ))?;
        let _exit_link = exit_prog.attach_tracepoint(
            "raw_syscalls", "sys_exit"
        )?;
        
        // Step 5: Poll ring buffer until child exits
        let mut events: Vec<SyscallEvent> = Vec::new();
        let mut exit_code: Option<i32> = None;
        let mut exit_signal: Option<String> = None;
        
        let ringbuf_map = bpf.map("events")
            .ok_or_else(|| anyhow::anyhow!("Ring buffer map not found"))?;
        
        let mut ringbuf = libbpf_rs::RingBufferBuilder::new();
        ringbuf.add(ringbuf_map, |data: &[u8]| {
            if let Some(event) = parse_bpf_event(data) {
                events.push(event);
            }
            0
        })?;
        let ringbuf = ringbuf.build()?;
        
        loop {
            ringbuf.poll(std::time::Duration::from_millis(100))?;
            
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Child exited — drain remaining events
                    ringbuf.poll(std::time::Duration::from_millis(50))?;
                    exit_code = status.code();
                    // Detect signal on Linux
                    #[cfg(target_os = "linux")]
                    {
                        use std::os::unix::process::ExitStatusExt;
                        if let Some(sig) = status.signal() {
                            exit_signal = Some(signal_name(sig));
                        }
                    }
                    break;
                }
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!("Error waiting for child: {}", e);
                    break;
                }
            }
        }
        
        Ok(TracerOutput {
            events,
            exit_code,
            exit_signal,
            runtime_ms: start.elapsed().as_millis() as u64,
        })
    }

    fn parse_bpf_event(data: &[u8]) -> Option<SyscallEvent> {
        if data.len() < 56 { return None; }
        
        let pid_bytes: [u8; 4] = data[0..4].try_into().ok()?;
        let tid_bytes: [u8; 4] = data[4..8].try_into().ok()?;
        let syscall_nr_bytes: [u8; 8] = data[8..16].try_into().ok()?;
        let arg0_bytes: [u8; 8] = data[16..24].try_into().ok()?;
        let arg1_bytes: [u8; 8] = data[24..32].try_into().ok()?;
        let arg2_bytes: [u8; 8] = data[32..40].try_into().ok()?;
        let retval_bytes: [u8; 8] = data[40..48].try_into().ok()?;
        let entry_time_bytes: [u8; 8] = data[48..56].try_into().ok()?;
        let exit_time_bytes: [u8; 8] = data[56..64].try_into().ok()?;

        let pid = u32::from_ne_bytes(pid_bytes);
        let tid = u32::from_ne_bytes(tid_bytes);
        let syscall_nr = u64::from_ne_bytes(syscall_nr_bytes);
        let arg0 = u64::from_ne_bytes(arg0_bytes);
        let arg1 = u64::from_ne_bytes(arg1_bytes);
        let arg2 = u64::from_ne_bytes(arg2_bytes);
        let retval = i64::from_ne_bytes(retval_bytes);
        let entry_time_ns = u64::from_ne_bytes(entry_time_bytes);
        let exit_time_ns = u64::from_ne_bytes(exit_time_bytes);

        let syscall_name = nr_to_name(syscall_nr).to_string();
        let mut args = Vec::new();
        if arg0 != 0 { args.push(arg0.to_string()); }
        if arg1 != 0 { args.push(arg1.to_string()); }
        if arg2 != 0 { args.push(arg2.to_string()); }

        let error = if retval < 0 {
            Some(SyscallError {
                code: "ERROR".to_string(),
                description: format!("returned {}", retval),
            })
        } else {
            None
        };

        let duration_ns = if exit_time_ns > entry_time_ns {
            Some(exit_time_ns - entry_time_ns)
        } else {
            None
        };

        Some(SyscallEvent {
            pid,
            tid,
            syscall_name,
            args,
            return_value: retval,
            error,
            timestamp_ns: entry_time_ns,
            duration_ns,
            repeat_count: 1,
        })
    }

    fn nr_to_name(nr: u64) -> &'static str {
        match nr {
            0 => "read",
            1 => "write",
            2 => "open",
            3 => "close",
            4 => "stat",
            5 => "fstat",
            6 => "lstat",
            8 => "lseek",
            9 => "mmap",
            10 => "mprotect",
            11 => "munmap",
            12 => "brk",
            14 => "rt_sigaction",
            21 => "access",
            32 => "dup",
            39 => "getpid",
            41 => "socket",
            42 => "connect",
            43 => "accept",
            49 => "bind",
            50 => "listen",
            56 => "clone",
            57 => "fork",
            59 => "execve",
            60 => "exit",
            61 => "wait4",
            62 => "kill",
            72 => "fcntl",
            89 => "readlink",
            192 => "mmap2",
            257 => "openat",
            258 => "mkdirat",
            260 => "fchmodat",
            _ => "unknown",
        }
    }

    fn signal_name(sig: i32) -> String {
        match sig {
            1 => "SIGHUP",
            2 => "SIGINT",
            3 => "SIGQUIT",
            4 => "SIGILL",
            6 => "SIGABRT",
            7 => "SIGBUS",
            8 => "SIGFPE",
            9 => "SIGKILL",
            11 => "SIGSEGV",
            13 => "SIGPIPE",
            14 => "SIGALRM",
            15 => "SIGTERM",
            n => return format!("SIG{}", n),
        }
        .to_string()
    }
}

pub struct EbpfTracer;

impl crate::tracer::Tracer for EbpfTracer {
    fn run(&self, cmd: &[String]) -> anyhow::Result<TracerOutput> {
        #[cfg(feature = "ebpf_available")]
        return ebpf_impl::run_ebpf(cmd);
        
        #[cfg(not(feature = "ebpf_available"))]
        let _ = cmd;
        #[cfg(not(feature = "ebpf_available"))]
        anyhow::bail!(
            "eBPF tracer was not compiled. \
             Ensure clang and libbpf-dev are installed, \
             then rebuild. Or use --mode strace."
        )
    }
}
