use std::process::Command;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=bpf/tracer.bpf.c");
    
    // Check 1: Are we on Linux?
    if !cfg!(target_os = "linux") {
        return; // eBPF only on Linux
    }
    
    // Check 2: Is clang available?
    let clang_check = Command::new("clang")
        .arg("--version")
        .output();
    
    if clang_check.is_err() {
        println!(
            "cargo:warning=clang not found. \
             eBPF tracer disabled. strace fallback active. \
             To enable eBPF: sudo apt install clang libbpf-dev"
        );
        return; // Graceful — strace still works
    }
    
    // Check 3: Does /sys/kernel/btf/vmlinux exist?
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        println!(
            "cargo:warning=BTF vmlinux not found at \
             /sys/kernel/btf/vmlinux. \
             eBPF CO-RE tracer disabled. strace fallback active."
        );
        return;
    }
    
    // Compile the BPF C program
    let out_dir = PathBuf::from(
        std::env::var("OUT_DIR").expect("OUT_DIR not set")
    );
    let bpf_obj = out_dir.join("tracer.bpf.o");
    
    let status = Command::new("clang")
        .args([
            "-g",
            "-O2",
            "-target", "bpf",
            "-D__TARGET_ARCH_x86",
            "-I/usr/include",
            "-I/usr/include/bpf",
            "-c", "bpf/tracer.bpf.c",
            "-o", bpf_obj.to_str().expect("invalid OUT_DIR path"),
        ])
        .status();
    
    match status {
        Ok(s) if s.success() => {
            println!("cargo:warning=eBPF tracer compiled successfully.");
            // Signal to Rust code that eBPF is available
            println!("cargo:rustc-cfg=feature=\"ebpf_available\"");
        }
        Ok(s) => {
            println!(
                "cargo:warning=eBPF compilation failed (exit {}). \
                 strace fallback active.",
                s.code().unwrap_or(-1)
            );
        }
        Err(e) => {
            println!(
                "cargo:warning=Could not run clang: {}. \
                 strace fallback active.",
                e
            );
        }
    }
}
