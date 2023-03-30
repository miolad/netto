#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "prog.bpf.h"

#ifndef likely
#define likely(x) __builtin_expect((x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect((x), 0)
#endif

char LICENSE[] SEC("license") = "GPL";

enum {
    EVENT_SOCK_SENDMSG   = (1 << 0),
    EVENT_NET_RX_SOFTIRQ = (1 << 1)
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __type(key, uint32_t);
    __type(value, int64_t);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} traced_pids_sock_send SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __type(key, uint32_t);
    __type(value, int64_t);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} traced_pids_net_rx_softirq SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} traced_pids_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct per_cpu_data));
    __uint(max_entries, 1);
} per_cpu SEC(".maps");

SEC("fentry/sock_sendmsg")
int BPF_PROG(send_msg_entry) {
    int zero = 0;
    int64_t* depth;
    struct per_cpu_data* timestamps;
    uint64_t* events;
    struct task_struct* task = bpf_get_current_task_btf();
    
    if (
        likely(depth = bpf_task_storage_get(&traced_pids_sock_send, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE)) &&
        likely((int64_t)__sync_fetch_and_add(depth, 1) == 0)                                                     &&
        likely(timestamps = bpf_map_lookup_elem(&per_cpu, &zero))                                                &&
        likely(events = bpf_task_storage_get(&traced_pids_events, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE))   &&
        (uint64_t)__sync_fetch_and_or(events, EVENT_SOCK_SENDMSG) == 0
    ) {
        timestamps->prev_ts = bpf_ktime_get_ns();
    }

    return 0;
}

SEC("fexit/sock_sendmsg")
int BPF_PROG(send_msg_exit) {
    int zero = 0;
    int64_t* depth;
    struct per_cpu_data* timestamps;
    uint64_t* events;
    struct task_struct* task = bpf_get_current_task_btf();

    if (
        likely(depth = bpf_task_storage_get(&traced_pids_sock_send, task, NULL, 0)) &&
        likely((int64_t)__sync_sub_and_fetch(depth, 1) == 0)                        &&
        likely(timestamps = bpf_map_lookup_elem(&per_cpu, &zero))                   &&
        likely(events = bpf_task_storage_get(&traced_pids_events, task, NULL, 0))   &&
        (uint64_t)__sync_and_and_fetch(events, ~EVENT_SOCK_SENDMSG) == 0
    ) {
        __sync_fetch_and_add(&timestamps->total_time, bpf_ktime_get_ns() - timestamps->prev_ts);
    }

    return 0;
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(net_rx_softirq_entry, unsigned int vec) {
    int zero = 0;
    int64_t* depth;
    struct per_cpu_data* timestamps;
    uint64_t* events;
    struct task_struct* task = bpf_get_current_task_btf();

    if (
        vec == NET_RX_SOFTIRQ                                                                                         &&
        likely(depth = bpf_task_storage_get(&traced_pids_net_rx_softirq, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE)) &&
        (int64_t)__sync_fetch_and_add(depth, 1) == 0                                                                  &&
        likely(timestamps = bpf_map_lookup_elem(&per_cpu, &zero))                                                     &&
        likely(events = bpf_task_storage_get(&traced_pids_events, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE))        &&
        (uint64_t)__sync_fetch_and_or(events, EVENT_NET_RX_SOFTIRQ) == 0
    ) {
        timestamps->prev_ts = bpf_ktime_get_ns();
    }

    return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(net_rx_softirq_exit, unsigned int vec) {
    int zero = 0;
    int64_t* depth;
    struct per_cpu_data* timestamps;
    uint64_t* events;

    if (
        vec == NET_RX_SOFTIRQ                                                                                  &&
        likely(depth = bpf_task_storage_get(&traced_pids_net_rx_softirq, bpf_get_current_task_btf(), NULL, 0)) &&
        (int64_t)__sync_sub_and_fetch(depth, 1) == 0                                                           &&
        likely(timestamps = bpf_map_lookup_elem(&per_cpu, &zero))                                              &&
        likely(events = bpf_task_storage_get(&traced_pids_events, bpf_get_current_task_btf(), NULL, 0))        &&
        (uint64_t)__sync_and_and_fetch(events, ~EVENT_NET_RX_SOFTIRQ) == 0
    ) {
        __sync_fetch_and_add(&timestamps->total_time, bpf_ktime_get_ns() - timestamps->prev_ts);
    }

    return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(tp_sched_switch, bool preempt, struct task_struct* prev, struct task_struct* next) {
    int zero = 0;
    uint64_t* prev_events, * next_events;
    struct per_cpu_data* timestamps;
    int64_t now = bpf_ktime_get_ns();
    
    prev_events = bpf_task_storage_get(&traced_pids_events, prev, NULL, 0);
    next_events = bpf_task_storage_get(&traced_pids_events, next, NULL, 0);
    timestamps = bpf_map_lookup_elem(&per_cpu, &zero);

    if (likely(timestamps)) {
        if (prev_events && *prev_events != 0) {
            __sync_fetch_and_add(&timestamps->total_time, now - timestamps->prev_ts);
            // bpf_printk("Switching away from traced task: %d -> %d", prev->pid, next->pid);
        }

        if (next_events && *next_events != 0) {
            timestamps->prev_ts = now;
            // bpf_printk("Switching into traced task: %d -> %d", prev->pid, next->pid);
        }
    }
    
    return 0;
}

// SEC("fentry/br_handle_frame")
// BPF_PROG(br_handle_frame_entry) {
//     return 0;
// }
