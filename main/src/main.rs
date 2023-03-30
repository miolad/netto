mod bpf {
    include!(concat!(env!("OUT_DIR"), "/prog.bpf.rs"));
}
mod common;
mod tui;

use std::{time::{Duration, Instant}, thread};
use anyhow::anyhow;
use libbpf_rs::{MapFlags, num_possible_cpus};
use powercap::PowerCap;
use tui::Tui;

fn main() -> anyhow::Result<()> {
    let open_skel = bpf::ProgSkelBuilder::default().open()?;
    let mut skel = open_skel.load()?;

    // Explicitly attach entry programs last (because the task-local storage can only be allocated by them)
    let _sched_switch_link = skel.progs_mut().tp_sched_switch().attach()?;
    let _sock_send_exit_link = skel.progs_mut().send_msg_exit().attach()?;
    let _net_rx_softirq_exit_link = skel.progs_mut().net_rx_softirq_exit().attach()?;
    let _sock_send_entry_link = skel.progs_mut().send_msg_entry().attach()?;
    let _net_rx_softirq_entry = skel.progs_mut().net_rx_softirq_entry().attach()?;

    // let _br_handle_frame_entry = skel.progs_mut().br_handle_frame_entry().attach()?;

    let maps = skel.maps();
    let per_cpu_map = maps.per_cpu();

    let rapl = PowerCap::try_default()
        .map_err(|_| anyhow!("RAPL: Failed to open powercap interface from /sys/class/powercap"))?
        .intel_rapl;

    let num_possible_cpus = num_possible_cpus()?;
    let mut prev_total_time = vec![0u64; num_possible_cpus];
    let mut prev_instant = Instant::now();

    let mut prev_total_energy = 0;

    let num_possible_cpus = num_possible_cpus;
    let (mut tui_runnable, mut tui) = Tui::init(num_possible_cpus);
    let mut tui_runner = tui_runnable.runner();

    while tui_runner.is_running() {
        thread::sleep(Duration::from_millis(500));
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

        if let Some(stats) = per_cpu_map.lookup_percpu(&0i32.to_le_bytes(), MapFlags::empty())? {
            let cumulative_cpu_fraction = stats
                .iter()
                .zip(prev_total_time.iter_mut())
                .enumerate()
                .map(|(cpuid, (cpu_stats, prev_total_cpu_time))| {
                    let total_cpu_time = unsafe {
                        &*(cpu_stats.as_ptr() as *const common::per_cpu_data)
                    }.total_time;
                    let delta_cpu_time = total_cpu_time - *prev_total_cpu_time;
                    *prev_total_cpu_time = total_cpu_time;
                    
                    let cpu_fraction = (delta_cpu_time as f64) / (delta_time.as_nanos() as f64);
                    let _ = tui.set_val(cpuid, "total", cpu_fraction);

                    cpu_fraction
                })
                .sum::<f64>() / (num_possible_cpus as f64);

            let _ = tui.set_val(num_possible_cpus, "total", cumulative_cpu_fraction);
            tui.set_total_power(((delta_energy as f64) * cumulative_cpu_fraction) / (delta_time.as_secs_f64() * 1_000_000.0));
        }
        
        tui_runner.refresh();
        tui_runner.step();
    }

    Ok(())
}
