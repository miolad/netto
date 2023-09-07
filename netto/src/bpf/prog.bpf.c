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
 * by associating an event identified to each task.
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
    __uint(max_entries, 1); // This is set at runtime based on configuration parameters
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
 * the buffer, and will therefore only ever be 0 or `stack_traces.max_entries/2`.
 * 
 * A non-zero value means select slot1, otherwise use slot0.
 */
u32 stack_traces_slot_off = 0;

const u64 event_max = EVENT_MAX;

inline void stop_event(u64 per_task_events, struct per_cpu_data* per_cpu_data, u64 now) {
    u64 t;
    
    if (per_task_events < EVENT_MAX) {
        t = now - per_cpu_data->entry_ts;
        
        per_cpu_data->per_event_total_time[per_task_events] += t;
        per_cpu_data->sched_switch_accounted_time += t;
    }
}

SEC("fentry/sock_sendmsg")
int BPF_PROG(sock_sendmsg_entry) {
    u32 zero = 0;
    struct per_cpu_data* per_cpu_data;
    u64* per_task_events, now = bpf_ktime_get_ns();

    if (
        likely((per_task_events = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), &event_max, BPF_LOCAL_STORAGE_GET_F_CREATE)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)
    ) {
        per_cpu_data->entry_ts = now;
        *per_task_events = EVENT_SOCK_SENDMSG;
    }
    
    return 0;
}

SEC("fexit/sock_sendmsg")
int BPF_PROG(sock_sendmsg_exit) {
    u32 zero = 0;
    struct per_cpu_data* per_cpu_data;
    u64* per_task_events, now = bpf_ktime_get_ns(), t;

    if (
        likely((per_task_events = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, 0)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)
    ) {
        t = now - per_cpu_data->entry_ts;
        
        *per_task_events = EVENT_MAX;
        per_cpu_data->per_event_total_time[EVENT_SOCK_SENDMSG] += t;
        per_cpu_data->sched_switch_accounted_time += t;
    }
    
    return 0;
}

SEC("fentry/sock_recvmsg")
int BPF_PROG(sock_recvmsg_entry) {
    u32 zero = 0;
    struct per_cpu_data* per_cpu_data;
    u64* per_task_events, now = bpf_ktime_get_ns();

    if (
        likely((per_task_events = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), &event_max, BPF_LOCAL_STORAGE_GET_F_CREATE)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)
    ) {
        per_cpu_data->entry_ts = now;
        *per_task_events = EVENT_SOCK_RECVMSG;
    }
    
    return 0;
}

SEC("fexit/sock_recvmsg")
int BPF_PROG(sock_recvmsg_exit) {
    u32 zero = 0;
    struct per_cpu_data* per_cpu_data;
    u64* per_task_events, now = bpf_ktime_get_ns(), t;

    if (
        likely((per_task_events = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, 0)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)
    ) {
        t = now - per_cpu_data->entry_ts;
        
        *per_task_events = EVENT_MAX;
        per_cpu_data->per_event_total_time[EVENT_SOCK_RECVMSG] += t;
        per_cpu_data->sched_switch_accounted_time += t;
    }
    
    return 0;
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(net_rx_softirq_entry, unsigned int vec) {
    u32 zero = 0;
    struct per_cpu_data* per_cpu_data;
    u64* per_task_events, now = bpf_ktime_get_ns();

    if (
        (vec == NET_RX_SOFTIRQ || vec == NET_TX_SOFTIRQ)                                                                                               &&
        likely((per_task_events = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), &event_max, BPF_LOCAL_STORAGE_GET_F_CREATE)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)
    ) {
        stop_event(*per_task_events, per_cpu_data, now);
        per_cpu_data->entry_ts = now;
        if (vec == NET_RX_SOFTIRQ) per_cpu_data->enable_stack_trace = 1;
    }

    return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(net_rx_softirq_exit, unsigned int vec) {
    u32 zero = 0;
    struct per_cpu_data* per_cpu_data;
    u64* per_task_events, now = bpf_ktime_get_ns(), t;

    if (
        (vec == NET_TX_SOFTIRQ || vec == NET_RX_SOFTIRQ)                                                            &&
        likely((per_task_events = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, 0)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)
    ) {
        t = now - per_cpu_data->entry_ts;
        
        // Convoluted expression makes the verifier happy
        switch (vec) {
        case NET_TX_SOFTIRQ:
            per_cpu_data->per_event_total_time[EVENT_NET_TX_SOFTIRQ] += t;
            break;

        default:
        case NET_RX_SOFTIRQ:
            per_cpu_data->per_event_total_time[EVENT_NET_RX_SOFTIRQ] += t;
            per_cpu_data->enable_stack_trace = 0;
        }

        per_cpu_data->sched_switch_accounted_time += t;
        if (*per_task_events != EVENT_MAX) per_cpu_data->entry_ts = now;
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
        if (prev_task_events != NULL) stop_event(*prev_task_events, per_cpu_data, now);
        if (next_task_events != NULL && *next_task_events != EVENT_MAX) per_cpu_data->entry_ts = now;

        if (prev->flags & 0x10 /* PF_IO_WORKER */)
            per_cpu_data->per_event_total_time[EVENT_IO_WORKER] += now - per_cpu_data->sched_switch_ts - per_cpu_data->sched_switch_accounted_time;
        per_cpu_data->sched_switch_ts = now;
        per_cpu_data->sched_switch_accounted_time = 0;
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