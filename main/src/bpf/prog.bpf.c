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

#define GENERIC_TRACE_EVENT(entry_sec, entry_name, exit_sec, exit_name, entry_flag, event_idx)                                \
SEC(entry_sec)                                                                                                                \
int BPF_PROG(entry_name) {                                                                                                    \
    int zero = 0;                                                                                                             \
    struct per_task_data* per_task_data;                                                                                      \
    struct per_cpu_data* per_cpu_data;                                                                                        \
    uint64_t now = bpf_ktime_get_ns();                                                                                        \
    uint32_t ret, nested = 0;                                                                                                 \
                                                                                                                              \
    if (                                                                                                                      \
        likely((per_task_data = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, entry_flag)) != NULL) && \
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)                                                 \
    ) {                                                                                                                       \
        bpf_spin_lock(&per_task_data->lock);                                                                                  \
        ret = event_stack_push(&per_task_data->stack, event_idx, per_cpu_data, now, &nested);                                 \
        bpf_spin_unlock(&per_task_data->lock);                                                                                \
                                                                                                                              \
        if (unlikely(ret != 0)) bpf_printk(entry_sec ": event stack full");                                                   \
        else if (!nested) per_cpu_data->events[event_idx].prev_ts = now;                                                      \
    }                                                                                                                         \
                                                                                                                              \
    return 0;                                                                                                                 \
}                                                                                                                             \
                                                                                                                              \
SEC(exit_sec)                                                                                                                 \
int BPF_PROG(exit_name) {                                                                                                     \
    int zero = 0;                                                                                                             \
    struct per_task_data* per_task_data;                                                                                      \
    struct per_cpu_data* per_cpu_data;                                                                                        \
    uint64_t now = bpf_ktime_get_ns();                                                                                        \
    uint32_t ret, nested = 0;                                                                                                 \
                                                                                                                              \
    if (                                                                                                                      \
        likely((per_task_data = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, 0)) != NULL) &&          \
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)                                                 \
    ) {                                                                                                                       \
        bpf_spin_lock(&per_task_data->lock);                                                                                  \
        ret = event_stack_pop(&per_task_data->stack, event_idx, per_cpu_data, now, &nested);                                  \
        bpf_spin_unlock(&per_task_data->lock);                                                                                \
                                                                                                                              \
        if (unlikely(ret == 0xFFFF))         bpf_printk(exit_sec ": event stack was empty");                                  \
        else if (unlikely(ret != event_idx)) bpf_printk(exit_sec ": popped unexpected event");                                \
        else if (!nested) per_cpu_data->events[event_idx].total_time += now - per_cpu_data->events[event_idx].prev_ts;        \
    }                                                                                                                         \
                                                                                                                              \
    return 0;                                                                                                                 \
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(net_rx_softirq_entry, unsigned int vec) {
    int zero = 0;
    struct per_task_data* per_task_data;
    struct per_cpu_data* per_cpu_data;
    uint64_t now = bpf_ktime_get_ns();
    uint32_t ret;

    if (
        vec == NET_RX_SOFTIRQ                                                                                                                  &&
        likely((per_task_data = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, BPF_LOCAL_STORAGE_GET_F_CREATE)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)
    ) {
        bpf_spin_lock(&per_task_data->lock);
        ret = event_stack_push(&per_task_data->stack, EVENT_NET_RX_SOFTIRQ, per_cpu_data, now, NULL);
        bpf_spin_unlock(&per_task_data->lock);

        if (unlikely(ret != 0)) bpf_printk("tp_btf/softirq_entry: event stack full");
        else per_cpu_data->events[EVENT_NET_RX_SOFTIRQ].prev_ts = now;
    }

    return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(net_rx_softirq_exit, unsigned int vec) {
    int zero = 0;
    struct per_task_data* per_task_data;
    struct per_cpu_data* per_cpu_data;
    uint64_t now = bpf_ktime_get_ns();
    uint32_t ret;

    if (
        vec == NET_RX_SOFTIRQ                                                                                     &&
        likely((per_task_data = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, 0)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)
    ) {
        bpf_spin_lock(&per_task_data->lock);
        ret = event_stack_pop(&per_task_data->stack, EVENT_NET_RX_SOFTIRQ, per_cpu_data, now, NULL);
        bpf_spin_unlock(&per_task_data->lock);

        if (unlikely(ret == 0xFFFF))                    bpf_printk("tp_btf/softirq_exit: event stack was empty");
        else if (unlikely(ret != EVENT_NET_RX_SOFTIRQ)) bpf_printk("tp_btf/softirq_exit: popped unexpected event");
        else per_cpu_data->events[EVENT_NET_RX_SOFTIRQ].total_time += now - per_cpu_data->events[EVENT_NET_RX_SOFTIRQ].prev_ts;
    }

    return 0;
}

GENERIC_TRACE_EVENT("fentry/sock_sendmsg", send_msg_entry, "fexit/sock_sendmsg", send_msg_exit, BPF_LOCAL_STORAGE_GET_F_CREATE, EVENT_SOCK_SENDMSG)
GENERIC_TRACE_EVENT("fentry/napi_consume_skb", napi_consume_skb_entry, "fexit/napi_consume_skb", napi_consume_skb_exit, 0, EVENT_CONSUME_SKB)
GENERIC_TRACE_EVENT("fentry/__napi_poll", napi_poll_entry, "fexit/__napi_poll", napi_poll_exit, 0, EVENT_NAPI_POLL)
GENERIC_TRACE_EVENT("tp_btf/netif_receive_skb_entry", netif_receive_skb_entry, "tp_btf/netif_receive_skb_exit", netif_receive_skb_exit, 0, EVENT_NETIF_RECEIVE_SKB)
GENERIC_TRACE_EVENT("tp_btf/napi_gro_receive_entry", napi_gro_receive_entry, "tp_btf/napi_gro_receive_exit", napi_gro_receive_exit, 0, EVENT_NETIF_RECEIVE_SKB)
GENERIC_TRACE_EVENT("fentry/br_handle_frame", br_handle_frame_entry, "fexit/br_handle_frame", br_handle_frame_exit, 0, EVENT_BRIDGE)
GENERIC_TRACE_EVENT("fentry/ip_forward", ip_forward_entry, "fexit/ip_forward", ip_forward_exit, 0, EVENT_FORWARD)
GENERIC_TRACE_EVENT("fentry/ip_local_deliver", ip_local_deliver_entry, "fexit/ip_local_deliver", ip_local_deliver_exit, 0, EVENT_LOCAL_DELIVER)

SEC("tp_btf/sched_switch")
int BPF_PROG(tp_sched_switch, bool preempt, struct task_struct* prev, struct task_struct* next) {
    int zero = 0;
    struct per_task_data* prev_task_data, * next_task_data;
    struct per_cpu_data* per_cpu_data;
    uint32_t ret;
    int64_t now = bpf_ktime_get_ns();
    
    prev_task_data = bpf_task_storage_get(&traced_pids, prev, NULL, 0);
    next_task_data = bpf_task_storage_get(&traced_pids, next, NULL, 0);
    per_cpu_data   = bpf_map_lookup_elem(&per_cpu, &zero);

    if (likely(per_cpu_data != NULL)) {
        if (likely(prev_task_data != NULL)) {
            bpf_spin_lock(&prev_task_data->lock);
            ret = event_stack_push(&prev_task_data->stack, EVENT_DUMMY_TASK_SWITCH, per_cpu_data, now, NULL);
            bpf_spin_unlock(&prev_task_data->lock);

            if (unlikely(ret != 0)) bpf_printk("tp_btf/sched_switch: event stack full");
        }

        if (likely(next_task_data != NULL)) {
            ret = event_stack_pop(&next_task_data->stack, EVENT_DUMMY_TASK_SWITCH, per_cpu_data, now, NULL);

            if (unlikely(ret == 0xFFFF))                   bpf_printk("tp_btf/sched_switch: event stack was empty");
            else if (unlikely(ret != EVENT_DUMMY_TASK_SWITCH)) bpf_printk("tp_btf/sched_switch: popped unexpected event");
        }
    }
    
    return 0;
}
