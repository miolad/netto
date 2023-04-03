#ifndef _EVENT_STACK_BPF_H_
#define _EVENT_STACK_BPF_H_

#include "vmlinux.h"
#include "prog.bpf.h"

/**
 * The size of the event stack determines the maximum depth of the events that are going to be traced
 */
#define EVENT_STACK_SIZE 8

enum {
    EVENT_SOCK_SENDMSG      = 0,
    EVENT_NET_RX_SOFTIRQ    = 1,
    EVENT_CONSUME_SKB       = 2,
    EVENT_NAPI_POLL         = 3,
    EVENT_NETIF_RECEIVE_SKB = 4,
    EVENT_BRIDGE            = 5,
    EVENT_FORWARD           = 6,
    EVENT_LOCAL_DELIVER     = 7,

    /// @brief Fictious event used to handle preemption/task switches
    EVENT_DUMMY_TASK_SWITCH = 8,
};

/**
 * Shared bits represent nested events.
 * For example, TRACE_EVENT_CONSUME_SKB is a sub-event of TRACE_EVENT_NET_RX_SOFTIRQ,
 * meaning that it can only happen while in softirq context.
 */
const uint16_t events[] = {
    (1 << EVENT_SOCK_SENDMSG)                                                                                          /** SOCK_SENDMSG      */,
    (1 << EVENT_NET_RX_SOFTIRQ)                                                                                        /** NET_RX_SOFTIRQ    */,
    (1 << EVENT_NET_RX_SOFTIRQ) | (1 << EVENT_CONSUME_SKB)                                                             /** CONSUME_SKB       */,
    (1 << EVENT_NET_RX_SOFTIRQ) | (1 << EVENT_NAPI_POLL)                                                               /** NAPI_POLL         */,
    (1 << EVENT_NET_RX_SOFTIRQ) | (1 << EVENT_NAPI_POLL) | (1 << EVENT_NETIF_RECEIVE_SKB)                              /** NETIF_RECEIVE_SKB */,
    (1 << EVENT_NET_RX_SOFTIRQ) | (1 << EVENT_NAPI_POLL) | (1 << EVENT_NETIF_RECEIVE_SKB) | (1 << EVENT_BRIDGE)        /** BRIDGE            */,
    (1 << EVENT_NET_RX_SOFTIRQ) | (1 << EVENT_NAPI_POLL) | (1 << EVENT_NETIF_RECEIVE_SKB) | (1 << EVENT_FORWARD)       /** FORWARD           */,
    (1 << EVENT_NET_RX_SOFTIRQ) | (1 << EVENT_NAPI_POLL) | (1 << EVENT_NETIF_RECEIVE_SKB) | (1 << EVENT_LOCAL_DELIVER) /** LOCAL_DELIVER     */,

    0                                                                                                                  /** DUMMY_TASK_SWITCH */
};

/** Checks if child is a sub-event of parent */
#define is_subevent_of(child, parent) ((child & parent) == parent)

/**
 * Contains a stack of the currently in-flight events for a given task
 */
struct event_stack {
    /// @brief Each element is an index into the events array
    uint16_t stack[EVENT_STACK_SIZE];
    /// @brief Index of the first empty frame in the stack
    uint16_t stack_ptr;
};

/**
 * Push a new event to the stack, eventually updating the timings for the previous base and sub events.
 * @returns zero on success
 */
static inline uint16_t event_stack_push(struct event_stack* stack, uint16_t event_idx, struct per_cpu_data* per_cpu_data, uint64_t now, uint32_t* nested) {
    uint16_t i, j;
    uint16_t cur_event_idx;
    uint16_t cur_event, prev_event = 0xFFFF, event = events[event_idx];
    
    if (likely(stack->stack_ptr < EVENT_STACK_SIZE)) {
        for (i = 0; i < stack->stack_ptr && i < EVENT_STACK_SIZE; ++i) { // Convoluted loop makes the verifier happy
            j = stack->stack_ptr - i - 1;
            if (likely(j < EVENT_STACK_SIZE)) { // Useless check makes the verifier happy
                cur_event_idx = stack->stack[j];
                
                if (likely(cur_event_idx < 9)) { // Useless check makes the verifier happy
                    cur_event = events[cur_event_idx];

                    if (nested && cur_event_idx == event_idx) *nested = 1;

                    if (
                        !is_subevent_of(event, cur_event) &&
                        (
                            is_subevent_of(prev_event, cur_event) ||
                            (
                                prev_event == events[EVENT_NETIF_RECEIVE_SKB] &&
                                cur_event_idx == EVENT_BRIDGE
                            )
                        )
                    ) {
                        per_cpu_data->events[cur_event_idx].total_time += now - per_cpu_data->events[cur_event_idx].prev_ts;
                        per_cpu_data->events[cur_event_idx].prev_ts = now; // Avoids multiple increments with nested events
                    }
                    else break;

                    prev_event = cur_event;
                }
            }
        }
        
        stack->stack[(stack->stack_ptr)++] = event_idx;

        return 0;
    }

    return 1;
}

/**
 * Pop the last event from the stack, eventually updating the timestamps for the previous base and sub events.
 * @returns the index of the popped event, or 0xFFFFFFFF if the stack was empty
 */
static inline uint16_t event_stack_pop(struct event_stack* stack, uint16_t event_idx, struct per_cpu_data* per_cpu_data, uint64_t now, uint32_t* nested) {
    uint16_t i, j;
    uint16_t cur_event_idx;
    uint16_t cur_event, prev_event = 0xFFFF, event = events[event_idx];
    uint16_t ret, index = stack->stack_ptr - 1;

    if (likely(stack->stack_ptr > 0) && likely(stack->stack_ptr <= EVENT_STACK_SIZE)) {
        ret = stack->stack[index];
        
        for (i = 0; (i < stack->stack_ptr - 1) && (i < EVENT_STACK_SIZE); ++i) { // Convoluted loop makes the verifier happy
            j = stack->stack_ptr - i - 2;
            if (likely(j < EVENT_STACK_SIZE)) { // Useless check makes the verifier happy
                cur_event_idx = stack->stack[j];
                
                if (likely(cur_event_idx < 9)) { // Useless check makes the verifier happy
                    cur_event = events[cur_event_idx];

                    if (nested && cur_event_idx == event_idx) *nested = 1;

                    if (
                        !is_subevent_of(event, cur_event) &&
                        (
                            is_subevent_of(prev_event, cur_event) ||
                            (
                                prev_event == events[EVENT_NETIF_RECEIVE_SKB] &&
                                cur_event_idx == EVENT_BRIDGE
                            )
                        )
                    ) per_cpu_data->events[cur_event_idx].prev_ts = now;
                    else break;

                    prev_event = cur_event;
                }
            }
        }
        
        stack->stack_ptr -= 1;
        return ret;

        // Identical things that are not accepted by the verifier for some reason:
        // 1)
            // uint16_t ret = 0, index = stack->stack_ptr - 1;
            // if (likely(index < EVENT_STACK_SIZE)) ret = stack->stack[index];
            // stack->stack_ptr -= 1;
            // return ret;

        // 2)
            // return stack->stack[--(stack->stack_ptr)]
    }

    return 0xFFFF;
}

#endif
