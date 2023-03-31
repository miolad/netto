#ifndef _EVENT_STACK_BPF_H_
#define _EVENT_STACK_BPF_H_

#include "vmlinux.h"
#include "prog.bpf.h"

/**
 * The size of the event stack determines the maximum depth of the events that are going to be traced
 */
#define EVENT_STACK_SIZE 4

/**
 * Shared bits represent nested events.
 * For example, TRACE_EVENT_CONSUME_SKB is a sub-event of TRACE_EVENT_NET_RX_SOFTIRQ,
 * meaning that it can only happen while in softirq context.
 */
enum {
    TRACE_EVENT_SOCK_SENDMSG   =                              (1 << 0),
    TRACE_EVENT_NET_RX_SOFTIRQ =                              (1 << 1),
    TRACE_EVENT_CONSUME_SKB    = TRACE_EVENT_NET_RX_SOFTIRQ | (1 << 2),
    TRACE_EVENT_BRIDGE         = TRACE_EVENT_NET_RX_SOFTIRQ | (1 << 3),
    TRACE_EVENT_FORWARD        = TRACE_EVENT_NET_RX_SOFTIRQ | (1 << 4),
    TRACE_EVENT_LOCAL_DELIVER  = TRACE_EVENT_NET_RX_SOFTIRQ | (1 << 5)
};

/** Checks if child is a sub-event of parent */
#define is_subevent_of(child, parent) ((child & parent) == parent)

/**
 * Contains a stack of the currently in-flight events for a given task
 */
struct event_stack {
    uint32_t stack[EVENT_STACK_SIZE];
    /// @brief Index of the first empty frame in the stack
    int8_t stack_ptr;
};

/**
 * Push a new event to the stack, eventually updating the timings for the previous base and sub events.
 * @returns zero on success
 */
inline uint32_t event_stack_push(struct event_stack* stack, uint32_t event, void* per_cpu_map) {
    int8_t i;
    uint32_t cur_event, prev_event = 0xFFFFFFFF;
    uint64_t now = bpf_ktime_get_ns();
    struct per_cpu_data* per_cpu_data;
    
    for (i = stack->stack_ptr - 1; i >= 0; --i) {
        cur_event = stack->stack[i];
        
        if (!is_subevent_of(event, cur_event) && is_subevent_of(prev_event, cur_event)) {
            if (per_cpu_data = bpf_map_lookup_elem(per_cpu_map, &cur_event)) {
                per_cpu_data->total += now - per_cpu_data->prev_ts;
            }
        } else break;

        prev_event = cur_event;
    }
    
    // TODO

    return 0;
}

/**
 * Pop the last event from the stack, eventually updating the timestamps for the previous base and sub events.
 * @returns the popped event, or zero if the stack was empty
 */
inline uint32_t event_stack_pop(struct event_stack* stack, struct per_cpu_data* per_cpu_data) {
    // TODO
}

#endif
