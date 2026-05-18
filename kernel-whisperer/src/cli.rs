use clap::{Parser, Subcommand, ValueEnum};

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum Mode {
    Auto,
    Strace,
    Ebpf,
}

#[derive(Parser, Debug)]
#[command(
    name = "kernel-whisperer",
    about = "Translate kernel crashes into plain English",
    version
)]
pub struct Args {
    #[arg(long, value_enum, default_value_t = Mode::Auto,
          help = "Tracer backend: auto, strace, or ebpf")]
    pub mode: Mode,

    #[arg(long, default_value = "http://localhost:8080",
          help = "llama.cpp server URL")]
    pub llm_url: String,

    #[arg(long, help = "Skip LLM, print raw syscall errors only")]
    pub no_llm: bool,

    #[arg(long, help = "Show all captured syscalls, not just errors")]
    pub verbose: bool,

    #[arg(long, default_value = "20",
          help = "How many pre-exit syscalls to include in context")]
    pub last_n: usize,

    #[arg(long, help = "Output result as JSON")]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Spawn and trace a command
    /// Usage: kernel-whisperer run -- nginx -c /etc/nginx/broken.conf
    Run {
        #[arg(
            last = true,
            required = true,
            help = "Command to run (everything after --)"
        )]
        cmd: Vec<String>,
    },
    /// Attach to a running process by PID (strace only)
    Attach {
        #[arg(help = "PID of the target process")]
        pid: u32,
    },
}
