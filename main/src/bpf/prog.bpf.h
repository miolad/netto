#ifndef _PROG_BPF_H_
#define _PROG_BPF_H_

#include "vmlinux.h"

struct per_cpu_data {
    uint64_t prev_ts;
    uint64_t total_syscall;
    uint64_t total_softirq;
};

#endif
