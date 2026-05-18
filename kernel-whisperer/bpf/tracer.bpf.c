// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ── Event struct sent to userspace ────────────────────────
struct syscall_event {
    __u32 pid;
    __u32 tid;
    __u64 syscall_nr;
    __u64 args[3];
    __s64 retval;
    __u64 entry_time_ns;
    __u64 exit_time_ns;
};

// ── Entry correlation struct (stored in inflight map) ─────
struct entry_data {
    __u64 entry_time_ns;
    __u64 args[3];
    __u64 syscall_nr;
};

// ── Maps ──────────────────────────────────────────────────

// Set from userspace: key=0, value=target_pid to trace
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid_map SEC(".maps");

// Correlate sys_enter with sys_exit: key=(pid<<32|tid)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct entry_data);
} inflight SEC(".maps");

// Ring buffer output to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// ── Helper: check if current PID matches target ───────────
static __always_inline int is_target_pid(__u32 pid) {
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&target_pid_map, &key);
    if (!target || *target == 0) return 0;
    return pid == *target;
}

// ── sys_enter tracepoint ─────────────────────────────────
SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    
    if (!is_target_pid(pid)) return 0;
    
    __u64 map_key = ((__u64)pid << 32) | tid;
    
    struct entry_data entry = {};
    entry.entry_time_ns = bpf_ktime_get_ns();
    entry.syscall_nr    = ctx->id;
    entry.args[0]       = ctx->args[0];
    entry.args[1]       = ctx->args[1];
    entry.args[2]       = ctx->args[2];
    
    bpf_map_update_elem(&inflight, &map_key, &entry, BPF_ANY);
    return 0;
}

// ── sys_exit tracepoint ──────────────────────────────────
SEC("tracepoint/raw_syscalls/sys_exit")
int handle_sys_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    
    if (!is_target_pid(pid)) return 0;
    
    __u64 map_key = ((__u64)pid << 32) | tid;
    
    struct entry_data *entry = 
        bpf_map_lookup_elem(&inflight, &map_key);
    if (!entry) return 0;
    
    struct syscall_event *event = 
        bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&inflight, &map_key);
        return 0;
    }
    
    event->pid            = pid;
    event->tid            = tid;
    event->syscall_nr     = entry->syscall_nr;
    event->args[0]        = entry->args[0];
    event->args[1]        = entry->args[1];
    event->args[2]        = entry->args[2];
    event->retval         = ctx->ret;
    event->entry_time_ns  = entry->entry_time_ns;
    event->exit_time_ns   = bpf_ktime_get_ns();
    
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&inflight, &map_key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
