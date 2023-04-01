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
        ret = event_stack_push(&per_task_data->stack, EVENT_NET_RX_SOFTIRQ, per_cpu_data, now);
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
        // bpf_spin_lock(&per_task_data->lock); // No need to acquire lock for softirq exit
        ret = event_stack_pop(&per_task_data->stack, EVENT_NET_RX_SOFTIRQ, per_cpu_data, now);
        // bpf_spin_unlock(&per_task_data->lock);

        if (unlikely(ret == 0xFFFFFFFF))                bpf_printk("tp_btf/softirq_exit: event stack was empty");
        else if (unlikely(ret != EVENT_NET_RX_SOFTIRQ)) bpf_printk("tp_btf/softirq_exit: popped unexpected event");
        else per_cpu_data->events[EVENT_NET_RX_SOFTIRQ].total_time += now - per_cpu_data->events[EVENT_NET_RX_SOFTIRQ].prev_ts;
    }

    return 0;
}

SEC("fentry/napi_consume_skb")
int BPF_PROG(napi_consume_skb_entry) {
    int zero = 0;
    struct per_task_data* per_task_data;
    struct per_cpu_data* per_cpu_data;
    uint64_t now = bpf_ktime_get_ns();
    uint32_t ret;

    if (
        likely((per_task_data = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, 0)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)
    ) {
        ret = event_stack_push(&per_task_data->stack, EVENT_CONSUME_SKB, per_cpu_data, now);

        if (unlikely(ret != 0)) bpf_printk("fentry/napi_consume_skb: event stack full");
        else per_cpu_data->events[EVENT_CONSUME_SKB].prev_ts = now;
    }

    return 0;
}

SEC("fexit/napi_consume_skb")
int BPF_PROG(napi_consume_skb_exit) {
    int zero = 0;
    struct per_task_data* per_task_data;
    struct per_cpu_data* per_cpu_data;
    uint64_t now = bpf_ktime_get_ns();
    uint32_t ret;

    if (
        likely((per_task_data = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, 0)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)
    ) {
        ret = event_stack_pop(&per_task_data->stack, EVENT_CONSUME_SKB, per_cpu_data, now);

        if (unlikely(ret == 0xFFFFFFFF))             bpf_printk("fexit/napi_consume_skb: event stack was empty");
        else if (unlikely(ret != EVENT_CONSUME_SKB)) bpf_printk("fexit/napi_consume_skb: popped unexpected event");
        else per_cpu_data->events[EVENT_CONSUME_SKB].total_time += now - per_cpu_data->events[EVENT_CONSUME_SKB].prev_ts;
    }

    return 0;
}

SEC("fentry/br_handle_frame")
int BPF_PROG(br_handle_frame_entry) {
    int zero = 0;
    struct per_task_data* per_task_data;
    struct per_cpu_data* per_cpu_data;
    uint64_t now = bpf_ktime_get_ns();
    uint32_t ret;

    if (
        likely((per_task_data = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, 0)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)
    ) {
        ret = event_stack_push(&per_task_data->stack, EVENT_BRIDGE, per_cpu_data, now);

        if (unlikely(ret != 0)) bpf_printk("fentry/br_handle_frame: event stack full");
        else per_cpu_data->events[EVENT_BRIDGE].prev_ts = now;
    }

    return 0;
}

SEC("fexit/br_handle_frame")
int BPF_PROG(br_handle_frame_exit) {
    int zero = 0;
    struct per_task_data* per_task_data;
    struct per_cpu_data* per_cpu_data;
    uint64_t now = bpf_ktime_get_ns();
    uint32_t ret;

    if (
        likely((per_task_data = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, 0)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)
    ) {
        ret = event_stack_pop(&per_task_data->stack, EVENT_BRIDGE, per_cpu_data, now);

        if (unlikely(ret == 0xFFFFFFFF))        bpf_printk("fexit/br_handle_frame: event stack was empty");
        else if (unlikely(ret != EVENT_BRIDGE)) bpf_printk("fexit/br_handle_frame: popped unexpected event");
        else per_cpu_data->events[EVENT_BRIDGE].total_time += now - per_cpu_data->events[EVENT_BRIDGE].prev_ts;
    }

    return 0;
}

SEC("fentry/ip_forward")
int BPF_PROG(ip_forward_entry) {
    int zero = 0;
    struct per_task_data* per_task_data;
    struct per_cpu_data* per_cpu_data;
    uint64_t now = bpf_ktime_get_ns();
    uint32_t ret;

    if (
        likely((per_task_data = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, 0)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)
    ) {
        ret = event_stack_push(&per_task_data->stack, EVENT_FORWARD, per_cpu_data, now);

        if (unlikely(ret != 0)) bpf_printk("fentry/ip_forward: event stack full");
        else per_cpu_data->events[EVENT_FORWARD].prev_ts = now;
    }

    return 0;
}

SEC("fexit/ip_forward")
int BPF_PROG(ip_forward_exit) {
    int zero = 0;
    struct per_task_data* per_task_data;
    struct per_cpu_data* per_cpu_data;
    uint64_t now = bpf_ktime_get_ns();
    uint32_t ret;

    if (
        likely((per_task_data = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, 0)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)
    ) {
        ret = event_stack_pop(&per_task_data->stack, EVENT_FORWARD, per_cpu_data, now);

        if (unlikely(ret == 0xFFFFFFFF))         bpf_printk("fexit/ip_forward: event stack was empty");
        else if (unlikely(ret != EVENT_FORWARD)) bpf_printk("fexit/ip_forward: popped unexpected event");
        else per_cpu_data->events[EVENT_FORWARD].total_time += now - per_cpu_data->events[EVENT_FORWARD].prev_ts;
    }

    return 0;
}

SEC("fentry/ip_local_deliver")
int BPF_PROG(ip_local_deliver_entry) {
    int zero = 0;
    struct per_task_data* per_task_data;
    struct per_cpu_data* per_cpu_data;
    uint64_t now = bpf_ktime_get_ns();
    uint32_t ret;

    if (
        likely((per_task_data = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, 0)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)
    ) {
        ret = event_stack_push(&per_task_data->stack, EVENT_LOCAL_DELIVER, per_cpu_data, now);

        if (unlikely(ret != 0)) bpf_printk("fentry/ip_local_deliver: event stack full");
        else per_cpu_data->events[EVENT_LOCAL_DELIVER].prev_ts = now;
    }

    return 0;
}

SEC("fexit/ip_local_deliver")
int BPF_PROG(ip_local_deliver_exit) {
    int zero = 0;
    struct per_task_data* per_task_data;
    struct per_cpu_data* per_cpu_data;
    uint64_t now = bpf_ktime_get_ns();
    uint32_t ret;

    if (
        likely((per_task_data = bpf_task_storage_get(&traced_pids, bpf_get_current_task_btf(), NULL, 0)) != NULL) &&
        likely((per_cpu_data = bpf_map_lookup_elem(&per_cpu, &zero)) != NULL)
    ) {
        ret = event_stack_pop(&per_task_data->stack, EVENT_LOCAL_DELIVER, per_cpu_data, now);

        if (unlikely(ret == 0xFFFFFFFF))               bpf_printk("fexit/ip_local_deliver: event stack was empty");
        else if (unlikely(ret != EVENT_LOCAL_DELIVER)) bpf_printk("fexit/ip_local_deliver: popped unexpected event");
        else per_cpu_data->events[EVENT_LOCAL_DELIVER].total_time += now - per_cpu_data->events[EVENT_LOCAL_DELIVER].prev_ts;
    }

    return 0;
}

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
            ret = event_stack_push(&prev_task_data->stack, EVENT_DUMMY_TASK_SWITCH, per_cpu_data, now);
            bpf_spin_unlock(&prev_task_data->lock);

            if (unlikely(ret != 0)) bpf_printk("tp_btf/sched_switch: event stack full");
        }

        if (likely(next_task_data != NULL)) {
            ret = event_stack_pop(&next_task_data->stack, EVENT_DUMMY_TASK_SWITCH, per_cpu_data, now);

            if (unlikely(ret == 0xFFFFFFFF))                   bpf_printk("tp_btf/sched_switch: event stack was empty");
            else if (unlikely(ret != EVENT_DUMMY_TASK_SWITCH)) bpf_printk("tp_btf/sched_switch: popped unexpected event");
        }
    }
    
    return 0;
}
