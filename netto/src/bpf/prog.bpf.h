#ifndef _PROG_BPF_H_
#define _PROG_BPF_H_

#include "vmlinux.h"

enum event_types {
    EVENT_SOCK_SENDMSG   = 0,
    EVENT_SOCK_RECVMSG   = 1,
    EVENT_NET_TX_SOFTIRQ = 2,
    EVENT_NET_RX_SOFTIRQ = 3,
    EVENT_IO_WORKER      = 4,

    EVENT_MAX            = 5
};

struct per_cpu_data {
    /// @brief Latest entry timestamp to any event in ns
    u64 entry_ts;

    /// @brief Latest scheduler switch timestamp
    u64 sched_switch_ts;

    /// @brief Total CPU time accounted to various events since the last scheduler switch
    u64 sched_switch_accounted_time;

    /// @brief Total time in ns registered for each event
    u64 per_event_total_time[EVENT_MAX];

    /// @brief When non-zero, stack traces by the perf event prog are disabled
    u8 disable_stack_trace;
};

#endif
