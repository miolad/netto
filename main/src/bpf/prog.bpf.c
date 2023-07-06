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

/**
 * Keeps track of which tasks are currently being tracked,
 * by associating an event bitfield to each task.
 * 
 * To protect against race conditions due to different events
 * being asynchronous, the value should only ever be updated with
 * atomic operations.
 */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __type(key, u32);
    __type(value, u64);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} traced_pids SEC(".maps");

/**
 * Per-cpu timestamps and counters
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct per_cpu_data));
    __uint(max_entries, 1);
} per_cpu SEC(".maps");

/**
 * Buffer with all the captured stack traces.
 * The buffer is logically split into two equal-sized slots,
 * that are swapped by the user-space just before each update.
 * 
 * Each element of the array encodes:
 *   - trace size in bytes (32 MSbits) | cpuid (32 LSbits) in the first u64
 *   - actual trace in the next 127 u64s
 * 
 * The array is mmapable to allow fast access from user-space
 * without the need for expensive syscalls.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64)*128);
    __uint(max_entries, 200000);
} stack_traces SEC(".maps");

/**
 * Counters of the number of traces present in each slot of
 * the `stack_traces` buffer.
 * 
 * Their increment must be atomic from the bpf side
 * as they are shared among all the cpus.
 */
u64 stack_traces_count_slot_0 = 0, stack_traces_count_slot_1 = 0;

/**
 * Slot selector into the `stack_traces` map.
 * 
 * The value represents the current offset to be applied to
 * the buffer, and will therefore only ever be 0 or 10000.
 * 
 * A non-zero value means select slot1, otherwise use slot0.
 */
u32 stack_traces_slot_off = 0;

inline void stop_all_events(struct per_cpu_data* per_cpu_data, u64 events, u64 now) {
    u32 i;
    
    for (i = 0; i < EVENT_MAX; ++i) {
        if (events & (1 << i)) {
            per_cpu_data->events[i].total_time += now - per_cpu_data->events[i].prev_ts;
            if (i == EVENT_NET_RX_SOFTIRQ) per_cpu_data->enable_stack_trace = 0;
        }
    }
}

inline void start_all_events(struct per_cpu_data* per_cpu_data, u64 events, u64 now) {
    u32 i;
    
    for (i = 0; i < EVENT_MAX; ++i) {
        if (events & (1 << i)) {
            per_cpu_data->events[i].prev_ts = now;
            if (i == EVENT_NET_RX_SOFTIRQ) per_cpu_data->enable_stack_trace = 1;
        }
    }
}

SEC("fentry/sock_sendmsg")
int BPF_PROG(sock_sendmsg_entry) {
    u32 zero = 0;
    struct per_cpu_data* per_cpu_data;
    u64* per_task_events, events, now = bpf_ktime_get_ns();

    if (
        likely((per_task_events = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, BPF_LOCAL_STORAGE_GET_F_CREATE)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)                                                                    &&
        likely(((events = __sync_fetch_and_or(per_task_events, 1 << EVENT_SOCK_SENDMSG)) & (1 << EVENT_SOCK_SENDMSG)) == 0)
    ) {
        stop_all_events(per_cpu_data, events, now);
        per_cpu_data->events[EVENT_SOCK_SENDMSG].prev_ts = now;
    }
    
    return 0;
}

SEC("fexit/sock_sendmsg")
int BPF_PROG(sock_sendmsg_exit) {
    u32 zero = 0;
    struct per_cpu_data* per_cpu_data;
    u64* per_task_events, events, now = bpf_ktime_get_ns();

    if (
        likely((per_task_events = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, 0)) != NULL)            &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)                                                  &&
        likely(((events = __sync_fetch_and_and(per_task_events, ~(1 << EVENT_SOCK_SENDMSG))) & (1 << EVENT_SOCK_SENDMSG)) != 0)
    ) {
        start_all_events(per_cpu_data, events & ~(1 << EVENT_SOCK_SENDMSG), now);
        per_cpu_data->events[EVENT_SOCK_SENDMSG].total_time += now - per_cpu_data->events[EVENT_SOCK_SENDMSG].prev_ts;
    }
    
    return 0;
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(net_rx_softirq_entry, unsigned int vec) {
    u32 zero = 0, softirq_ev = vec - 1;
    struct per_cpu_data* per_cpu_data;
    u64* per_task_events, events, now = bpf_ktime_get_ns();

    if (
        (vec == NET_TX_SOFTIRQ || vec == NET_RX_SOFTIRQ)                                                                                         &&
        likely((per_task_events = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, BPF_LOCAL_STORAGE_GET_F_CREATE)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)                                                                    &&
        likely(((events = __sync_fetch_and_or(per_task_events, 1 << softirq_ev)) & (1 << softirq_ev)) == 0)
    ) {
        stop_all_events(per_cpu_data, events, now);
        // Useless check makes the verifier happy
        if (softirq_ev < EVENT_MAX) per_cpu_data->events[softirq_ev].prev_ts = now;
        if (softirq_ev == EVENT_NET_RX_SOFTIRQ) per_cpu_data->enable_stack_trace = 1;
    }

    return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(net_rx_softirq_exit, unsigned int vec) {
    u32 zero = 0, softirq_ev = vec - 1;
    struct per_cpu_data* per_cpu_data;
    u64* per_task_events, events, now = bpf_ktime_get_ns();

    if (
        (vec == NET_TX_SOFTIRQ || vec == NET_RX_SOFTIRQ)                                                                            &&
        likely((per_task_events = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, 0)) != NULL)                 &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)                                                       &&
        likely(((events = __sync_fetch_and_and(per_task_events, ~(1 << softirq_ev))) & (1 << softirq_ev)) != 0)
    ) {
        start_all_events(per_cpu_data, events & ~(1 << softirq_ev), now);
        // Useless check makes the verifier happy
        if (softirq_ev < EVENT_MAX) per_cpu_data->events[softirq_ev].total_time += now - per_cpu_data->events[softirq_ev].prev_ts;
        if (softirq_ev == EVENT_NET_RX_SOFTIRQ) per_cpu_data->enable_stack_trace = 0;
    }

    return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(tp_sched_switch, bool preempt, struct task_struct* prev, struct task_struct* next) {
    u32 zero = 0;
    struct per_cpu_data* per_cpu_data;
    u64* prev_task_events, * next_task_events, now = bpf_ktime_get_ns();
    
    prev_task_events = bpf_task_storage_get(&traced_pids, prev, NULL, 0);
    next_task_events = bpf_task_storage_get(&traced_pids, next, NULL, 0);
    per_cpu_data     = bpf_map_lookup_elem(&per_cpu, &zero);

    if (likely(per_cpu_data != NULL)) {
        if (prev_task_events != NULL) stop_all_events(per_cpu_data, *prev_task_events, now);
        if (next_task_events != NULL) start_all_events(per_cpu_data, *next_task_events, now);
    }
    
    return 0;
}

SEC("perf_event")
int perf_event_prog(struct bpf_perf_event_data* ctx) {
    struct per_cpu_data* per_cpu_data;
    u32 index, zero = 0;
    u64* buf;
    
    if (
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL) &&
        per_cpu_data->enable_stack_trace
    ) {
        index = __sync_fetch_and_add(
            stack_traces_slot_off ? &stack_traces_count_slot_1 : &stack_traces_count_slot_0,
            1
        ) + stack_traces_slot_off;
        
        if (likely((buf = bpf_map_lookup_elem(&stack_traces, &index)) != NULL)) {
            *buf = (u64)bpf_get_smp_processor_id() |
                   ((u64)bpf_get_stack(ctx, buf+1, sizeof(u64)*127, 0) << 32);
        }
    }

    return 0;
}