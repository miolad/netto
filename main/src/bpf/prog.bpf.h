#ifndef _PROG_BPF_H_
#define _PROG_BPF_H_

#include "vmlinux.h"

enum event_types {
    EVENT_SOCK_SENDMSG   = 0,
    EVENT_NET_TX_SOFTIRQ = 1,
    EVENT_NET_RX_SOFTIRQ = 2,

    EVENT_MAX            = 3
};

struct per_cpu_data {
    /// @brief Latest entry timestamp to any event in ns
    u64 entry_ts;

    /// @brief Total time in ns registered for each event
    u64 per_event_total_time[EVENT_MAX];

    /// @brief When non-zero, stack traces by the perf event prog are enabled
    u8 enable_stack_trace;
};

#endif
