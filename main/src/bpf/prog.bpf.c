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

#include "event_stack.bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct per_task_data {
    struct bpf_spin_lock lock;
    struct event_stack stack;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __type(key, uint32_t);
    __type(value, struct per_task_data);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} traced_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct per_cpu_data));
    __uint(max_entries, 1);
} per_cpu SEC(".maps");

SEC("fentry/sock_sendmsg")
int BPF_PROG(send_msg_entry) {
    int zero = 0;
    struct per_task_data* per_task_data;
    struct per_cpu_data* per_cpu_data;
    uint64_t now = bpf_ktime_get_ns();
    uint32_t ret;

    if (
        likely((per_task_data = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, BPF_LOCAL_STORAGE_GET_F_CREATE)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)
    ) {
        bpf_spin_lock(&per_task_data->lock);
        ret = event_stack_push(&per_task_data->stack, EVENT_SOCK_SENDMSG, per_cpu_data, now);
        bpf_spin_unlock(&per_task_data->lock);

        if (unlikely(ret != 0)) bpf_printk("fentry/sock_sendmsg: event stack full");
        else per_cpu_data->events[EVENT_SOCK_SENDMSG].prev_ts = now;
    }

    return 0;
}

SEC("fexit/sock_sendmsg")
int BPF_PROG(send_msg_exit) {
    int zero = 0;
    struct per_task_data* per_task_data;
    struct per_cpu_data* per_cpu_data;
    uint64_t now = bpf_ktime_get_ns();
    uint32_t ret;

    if (
        likely((per_task_data = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, 0)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)
    ) {
        bpf_spin_lock(&per_task_data->lock);
        ret = event_stack_pop(&per_task_data->stack, EVENT_SOCK_SENDMSG, per_cpu_data, now);
        bpf_spin_unlock(&per_task_data->lock);

        if (unlikely(ret == 0xFFFFFFFF))              bpf_printk("fexit/sock_sendmsg: event stack was empty");
        else if (unlikely(ret != EVENT_SOCK_SENDMSG)) bpf_printk("fexit/sock_sendmsg: popped unexpected event");
        else per_cpu_data->events[EVENT_SOCK_SENDMSG].total_time += now - per_cpu_data->events[EVENT_SOCK_SENDMSG].prev_ts;
    }

    return 0;
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(net_rx_softirq_entry, unsigned int vec) {
    // int zero = 0;
    // int64_t* depth;
    // struct per_cpu_data* timestamps;
    // uint64_t* events;
    // struct task_struct* task = bpf_get_current_task_btf();
    // uint64_t now = bpf_ktime_get_ns();

    // if (
    //     vec == NET_RX_SOFTIRQ                                                                                         &&
    //     likely(depth = bpf_task_storage_get(&traced_pids_net_rx_softirq, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE)) &&
    //     (int64_t)__sync_fetch_and_add(depth, 1) == 0                                                                  &&
    //     likely(timestamps = bpf_map_lookup_elem(&per_cpu, &zero))                                                     &&
    //     likely(events = bpf_task_storage_get(&traced_pids_events, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE))
    // ) {
    //     if ((uint64_t)__sync_fetch_and_or(events, EVENT_NET_RX_SOFTIRQ) == EVENT_SOCK_SENDMSG) {
    //         __sync_fetch_and_add(&timestamps->total_syscall, now - timestamps->prev_ts);
    //     }

    //     timestamps->prev_ts = now;
    // }

    return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(net_rx_softirq_exit, unsigned int vec) {
    // int zero = 0;
    // int64_t* depth;
    // struct per_cpu_data* timestamps;
    // uint64_t* events;
    // uint64_t now = bpf_ktime_get_ns();

    // if (
    //     vec == NET_RX_SOFTIRQ                                                                                  &&
    //     likely(depth = bpf_task_storage_get(&traced_pids_net_rx_softirq, bpf_get_current_task_btf(), NULL, 0)) &&
    //     (int64_t)__sync_sub_and_fetch(depth, 1) == 0                                                           &&
    //     likely(timestamps = bpf_map_lookup_elem(&per_cpu, &zero))                                              &&
    //     likely(events = bpf_task_storage_get(&traced_pids_events, bpf_get_current_task_btf(), NULL, 0))
    // ) {
    //     __sync_fetch_and_add(&timestamps->total_softirq, now - timestamps->prev_ts);

    //     if ((uint64_t)__sync_and_and_fetch(events, ~EVENT_NET_RX_SOFTIRQ) == EVENT_SOCK_SENDMSG) {
    //         timestamps->prev_ts = now;
    //     }
    // }

    return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(tp_sched_switch, bool preempt, struct task_struct* prev, struct task_struct* next) {
    // int zero = 0;
    // uint64_t* prev_events, * next_events;
    // struct per_cpu_data* timestamps;
    // int64_t now = bpf_ktime_get_ns();
    
    // prev_events = bpf_task_storage_get(&traced_pids_events, prev, NULL, 0);
    // next_events = bpf_task_storage_get(&traced_pids_events, next, NULL, 0);
    // timestamps = bpf_map_lookup_elem(&per_cpu, &zero);

    // if (likely(timestamps)) {
    //     if (prev_events && *prev_events != 0) {
    //         __sync_fetch_and_add(&timestamps->total_time, now - timestamps->prev_ts);
    //         // bpf_printk("Switching away from traced task: %d -> %d", prev->pid, next->pid);
    //     }

    //     if (next_events && *next_events != 0) {
    //         timestamps->prev_ts = now;
    //         // bpf_printk("Switching into traced task: %d -> %d", prev->pid, next->pid);
    //     }
    // }
    
    return 0;
}

// SEC("fentry/br_handle_frame")
// BPF_PROG(br_handle_frame_entry) {
//     return 0;
// }
