#ifndef _PROG_BPF_H_
#define _PROG_BPF_H_

#include "vmlinux.h"

enum event_types {
    EVENT_SOCK_SENDMSG   = 0,
    EVENT_NET_RX_SOFTIRQ = 1,

    EVENT_MAX            = 2
};

struct per_event_data {
    u64 prev_ts;
    u64 total_time;
};

struct per_cpu_data {
    /// @brief One for each possible event
    struct per_event_data events[EVENT_MAX];

    /// @brief When non-zero, stack traces by the perf event prog are enabled
    u8 enable_stack_trace;
};

#endif
