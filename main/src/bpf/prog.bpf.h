#ifndef _PROG_BPF_H_
#define _PROG_BPF_H_

#include "vmlinux.h"

struct per_event_data {
    u64 prev_ts;
    u64 total_time;
};

struct per_cpu_data {
    /// @brief One for each possible event
    struct per_event_data events[9];
};

#endif
