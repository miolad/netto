#include "vmlinux.h"

struct per_cpu_data {
    uint64_t prev_ts;
    uint64_t total_time;
};
