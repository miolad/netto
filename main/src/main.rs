mod bpf {
    include!(concat!(env!("OUT_DIR"), "/prog.bpf.rs"));
}
#[allow(warnings)]
mod common;
mod tui;
mod ksyms;

use std::{time::{Duration, Instant}, thread};
use anyhow::anyhow;
use common::{event_types_EVENT_MAX, event_types_EVENT_SOCK_SENDMSG, event_types_EVENT_NET_RX_SOFTIRQ, event_types_EVENT_NET_TX_SOFTIRQ};
use ksyms::{KSyms, Counts};
use libbpf_rs::{MapFlags, num_possible_cpus};
use perf_event_open_sys::{bindings::{perf_event_attr, PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK}, perf_event_open};
use powercap::PowerCap;
use libc::{mmap, PROT_READ, MAP_SHARED, MAP_FAILED};
use tui::Tui;

fn main() -> anyhow::Result<()> {
    let open_skel = bpf::ProgSkelBuilder::default().open()?;
    let mut skel = open_skel.load()?;

    // Open the perf events (one for each CPU)
    let perf_event_fds = unsafe {
        (0..num_possible_cpus()?)
            .map(|cpuid| {
                let mut attrs = perf_event_attr {
                    size: std::mem::size_of::<perf_event_attr>() as _,
                    type_: PERF_TYPE_SOFTWARE,
                    config: PERF_COUNT_SW_CPU_CLOCK as _,
        
                    // Sampling frequency
                    __bindgen_anon_1: perf_event_open_sys::bindings::perf_event_attr__bindgen_ty_1 {
                        sample_freq: 1000
                    },
        
                    ..Default::default()
                };
        
                // Only count kernel-space events
                attrs.set_exclude_user(1);
        
                // Use frequency instead of period
                attrs.set_freq(1);
        
                perf_event_open(&mut attrs, -1, cpuid as _, -1, 0)
            })
            .collect::<Vec<_>>()
    };

    // Explicitly attach entry programs last (because the task-local storage can only be allocated by them)
    let _sched_switch_link = skel.progs_mut().tp_sched_switch().attach()?;
    let _sock_sendmsg_exit_link = skel.progs_mut().sock_sendmsg_exit().attach()?;
    let _net_rx_softirq_exit_link = skel.progs_mut().net_rx_softirq_exit().attach()?;

    // Also attach the "perf_event_prog" program to all the perf events
    let _perf_event_links = perf_event_fds
        .iter()
        .map(|&fd| {
            skel.progs_mut().perf_event_prog().attach_perf_event(fd).unwrap()
        })
        .collect::<Vec<_>>();

    let _sock_sendmsg_entry_link = skel.progs_mut().sock_sendmsg_entry().attach()?;
    let _net_rx_softirq_entry_link = skel.progs_mut().net_rx_softirq_entry().attach()?;

    // Mmap traces array
    let map_ptr = unsafe { mmap(
        std::ptr::null_mut(),
        std::mem::size_of::<u64>() * 128 * 20_000,
        PROT_READ,
        MAP_SHARED,
        skel.maps().stack_traces().fd(),
        0
    ) } as *const u64;
    if map_ptr as usize == MAP_FAILED as usize {
        eprintln!("mmap failed");
        return Err(std::io::Error::last_os_error().into());
    }

    let ksyms = KSyms::load()?;

    let rapl = PowerCap::try_default()
        .map_err(|_| anyhow!("RAPL: Failed to open powercap interface from /sys/class/powercap"))?
        .intel_rapl;

    let num_possible_cpus = num_possible_cpus()?;
    let mut prev_total_times = vec![vec![0u64; event_types_EVENT_MAX as usize]; num_possible_cpus];
    let mut counts = vec![Counts::default(); num_possible_cpus];
    let mut prev_instant = Instant::now();

    let mut prev_total_energy = 0;

    let (mut tui_runnable, mut tui) = Tui::init(num_possible_cpus);
    let mut tui_runner = tui_runnable.runner();

    while tui_runner.is_running() {
        thread::sleep(Duration::from_millis(500 - prev_instant.elapsed().as_millis().min(500) as u64));
        let current_instant = Instant::now();
        let delta_time = current_instant.duration_since(prev_instant);
        prev_instant = current_instant;

        let current_total_energy = rapl
            .sockets
            .values()
            .flat_map(|socket| socket.energy())
            .sum();
        let delta_energy = current_total_energy - prev_total_energy;
        prev_total_energy = current_total_energy;

        {
            // Swap buffer slots and get the number of stack traces in the previously active slot
            let slot_off = skel.bss().stack_traces_slot_off as usize;
            let num_traces_ref;
            (skel.bss().stack_traces_slot_off, num_traces_ref) = if slot_off > 0 {
                (0,      &mut skel.bss().stack_traces_count_slot_1)
            } else {
                (10_000, &mut skel.bss().stack_traces_count_slot_0)
            };

            // Make sure to read the count *after* swapping the slots
            let num_traces = *num_traces_ref;
            
            // Reset previous counts
            for count in &mut counts {
                *count = Default::default();
            }
            
            // Count symbols
            unsafe {
                for trace_ptr in (0..num_traces as usize).map(|trace_idx| map_ptr.add((slot_off + trace_idx) * 128)) {
                    // Get the cpuid
                    let (trace_size, cpuid) = {
                        let v = trace_ptr.read_volatile();

                        // Note that the trace size is encoded in bytes in the map, bu we care about number of u64s
                        (v >> 35, v & 0xFFFFFFFF)
                    };

                    counts[cpuid as usize].acc_trace(
                        &ksyms,
                        trace_ptr.add(1),
                        trace_size as _
                    );
                }
            }

            // Reset the stack traces index for this slot
            *num_traces_ref = 0;
        }

        if let Some(stats) = skel.maps().per_cpu().lookup_percpu(&0i32.to_le_bytes(), MapFlags::empty())? {
            let total_cpu_frac = stats
                .iter()
                .zip(prev_total_times.iter_mut())
                .enumerate()
                .map(|(cpuid, (cpu_stats, prev_total_cpu_times))| {
                    let mut cpu_times = unsafe {
                        &*(cpu_stats.as_ptr() as *const common::per_cpu_data)
                    }.events
                        .iter()
                        .zip(prev_total_cpu_times.iter_mut())
                        .map(|(common::per_event_data { total_time, .. }, prev_total_time)| {
                            let delta_cpu_time = total_time - *prev_total_time;
                            *prev_total_time = *total_time;
                            (delta_cpu_time as f64) / (delta_time.as_nanos() as f64)
                        })
                        .collect::<Vec<_>>();

                    for (event_idx, cpu_frac) in cpu_times.iter_mut().enumerate() {
                        #[allow(non_upper_case_globals)]
                        let metric_name = match event_idx as u32 {
                            event_types_EVENT_SOCK_SENDMSG   => "tx_syscalls",
                            event_types_EVENT_NET_TX_SOFTIRQ => "tx_softirq",
                            event_types_EVENT_NET_RX_SOFTIRQ => {
                                // Update sub-events
                                let denominator = counts[cpuid].net_rx_action.max(1) as f64;
                                
                                // Driver poll
                                let _ = tui.set_val(
                                    cpuid,
                                    "driver_poll",
                                    *cpu_frac * (counts[cpuid].__napi_poll - counts[cpuid].netif_receive_skb) as f64 / denominator
                                );

                                // XDP generic
                                let _ = tui.set_val(
                                    cpuid,
                                    "xdp_generic",
                                    *cpu_frac * counts[cpuid].do_xdp_generic as f64 / denominator
                                );

                                // TC classify
                                let _ = tui.set_val(
                                    cpuid,
                                    "tc_classify",
                                    *cpu_frac * counts[cpuid].tcf_classify as f64 / denominator
                                );

                                // NF ingress
                                let _ = tui.set_val(
                                    cpuid,
                                    "nf_ingress",
                                    *cpu_frac * counts[cpuid].nf_netdev_ingress as f64 / denominator
                                );

                                // Bridging
                                let _ = tui.set_val(
                                    cpuid,
                                    "bridging",
                                    *cpu_frac * (counts[cpuid].br_handle_frame - counts[cpuid].netif_receive_skb_sub_br) as f64 / denominator
                                );

                                // NF prerouting
                                let _ = tui.set_val(
                                    cpuid,
                                    "nf_prerouting_v4",
                                    *cpu_frac * counts[cpuid].nf_prerouting_v4 as f64 / denominator
                                );

                                let _ = tui.set_val(
                                    cpuid,
                                    "nf_prerouting_v6",
                                    *cpu_frac * counts[cpuid].nf_prerouting_v6 as f64 / denominator
                                );

                                // Forwarding
                                let _ = tui.set_val(
                                    cpuid,
                                    "forwarding_v4",
                                    *cpu_frac * counts[cpuid].ip_forward as f64 / denominator
                                );

                                let _ = tui.set_val(
                                    cpuid,
                                    "forwarding_v6",
                                    *cpu_frac * counts[cpuid].ip6_forward as f64 / denominator
                                );

                                // Local deliver
                                let _ = tui.set_val(
                                    cpuid,
                                    "local_deliver_v4",
                                    *cpu_frac * counts[cpuid].ip_local_deliver as f64 / denominator
                                );

                                let _ = tui.set_val(
                                    cpuid,
                                    "local_deliver_v6",
                                    *cpu_frac * counts[cpuid].ip6_input as f64 / denominator
                                );
                                
                                "rx_softirq"
                            },
                            _ => unreachable!()
                        };

                        let _ = tui.set_val(cpuid, metric_name, *cpu_frac);
                    }

                    let _ = tui.set_val(cpuid, "total", cpu_times.iter().sum());
                    cpu_times
                })
                .reduce(|mut acc, e| {
                    acc
                        .iter_mut()
                        .zip(e.iter())
                        .for_each(|(acc, e)| {
                            *acc += *e;
                        });

                    acc
                })
                .unwrap()
                .iter()
                .enumerate()
                .map(|(event_idx, e)| {
                    let cpu_frac = e / (num_possible_cpus as f64);
                    
                    #[allow(non_upper_case_globals)]
                    let metric_name = match event_idx as u32 {
                        event_types_EVENT_SOCK_SENDMSG   => "tx_syscalls",
                        event_types_EVENT_NET_TX_SOFTIRQ => "tx_softirq",
                        event_types_EVENT_NET_RX_SOFTIRQ => {
                            // Update sub-events
                            let total_counts = counts
                                .iter()
                                .cloned()
                                .sum::<Counts>();

                            let denominator = total_counts.net_rx_action.max(1) as f64;
                            
                            // Driver poll
                            let _ = tui.set_val(
                                num_possible_cpus,
                                "driver_poll",
                                cpu_frac * (total_counts.__napi_poll - total_counts.netif_receive_skb) as f64 / denominator
                            );

                            // XDP generic
                            let _ = tui.set_val(
                                num_possible_cpus,
                                "xdp_generic",
                                cpu_frac * total_counts.do_xdp_generic as f64 / denominator
                            );

                            // TC classify
                            let _ = tui.set_val(
                                num_possible_cpus,
                                "tc_classify",
                                cpu_frac * total_counts.tcf_classify as f64 / denominator
                            );

                            // NF ingress
                            let _ = tui.set_val(
                                num_possible_cpus,
                                "nf_ingress",
                                cpu_frac * total_counts.nf_netdev_ingress as f64 / denominator
                            );
                            
                            // Bridging
                            let _ = tui.set_val(
                                num_possible_cpus,
                                "bridging",
                                cpu_frac * (total_counts.br_handle_frame - total_counts.netif_receive_skb_sub_br) as f64 / denominator
                            );

                            // NF prerouting
                            let _ = tui.set_val(
                                num_possible_cpus,
                                "nf_prerouting_v4",
                                cpu_frac * total_counts.nf_prerouting_v4 as f64 / denominator
                            );

                            let _ = tui.set_val(
                                num_possible_cpus,
                                "nf_prerouting_v6",
                                cpu_frac * total_counts.nf_prerouting_v6 as f64 / denominator
                            );
                            
                            // Forwarding
                            let _ = tui.set_val(
                                num_possible_cpus,
                                "forwarding_v4",
                                cpu_frac * total_counts.ip_forward as f64 / denominator
                            );

                            let _ = tui.set_val(
                                num_possible_cpus,
                                "forwarding_v6",
                                cpu_frac * total_counts.ip6_forward as f64 / denominator
                            );

                            // Local deliver
                            let _ = tui.set_val(
                                num_possible_cpus,
                                "local_deliver_v4",
                                cpu_frac * total_counts.ip_local_deliver as f64 / denominator
                            );

                            let _ = tui.set_val(
                                num_possible_cpus,
                                "local_deliver_v6",
                                cpu_frac * total_counts.ip6_input as f64 / denominator
                            );
                            
                            "rx_softirq"
                        },
                        _ => unreachable!()
                    };

                    let _ = tui.set_val(num_possible_cpus, metric_name, cpu_frac);

                    cpu_frac
                })
                .sum::<f64>();

            let _ = tui.set_val(num_possible_cpus, "total", total_cpu_frac);
            tui.set_total_power(((delta_energy as f64) * total_cpu_frac) / (delta_time.as_secs_f64() * 1_000_000.0));
        }
        
        tui_runner.refresh();
        tui_runner.step();
    }

    Ok(())
}
