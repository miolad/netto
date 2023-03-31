#ifndef _PROG_BPF_H_
#define _PROG_BPF_H_

#include "vmlinux.h"

struct per_event_data {
    uint64_t prev_ts;
    uint64_t total_time;
};

struct per_cpu_data {
    /// @brief One for each possible event
    struct per_event_data events[6];
};

#endif
