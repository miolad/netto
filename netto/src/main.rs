mod bpf {
    include!(concat!(env!("OUT_DIR"), "/prog.bpf.rs"));
}
#[allow(warnings)]
mod common;
mod ksyms;
mod actors;

use std::path::PathBuf;
use actix::Actor;
use actix_files::Files;
use actix_web::{HttpServer, App, rt::System, web};
use actors::trace_analyzer::TraceAnalyzer;
use anyhow::anyhow;
use clap::Parser;
use libbpf_rs::num_possible_cpus;
use perf_event_open_sys::{bindings::{perf_event_attr, PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK}, perf_event_open};
use tokio::sync::{mpsc::channel, watch};
use crate::actors::{metrics_collector::MetricsCollector, websocket_client::ws_get, file_logger::FileLogger, prometheus_logger::{PrometheusLogger, prometheus_log_get}};

#[derive(Parser)]
#[command(name = "netto")]
#[command(author = "Davide Miola <davide.miola99@gmail.com>")]
#[command(about = "eBPF-based network diagnosis tool for Linux")]
#[command(version)]
struct Cli {
    /// Perf-event's sampling frequency in Hz for the NET_RX_SOFTIRQ cost breakdown
    #[arg(short, long, default_value_t = 1000)]
    frequency: u64,

    /// Bind address or hostname for the web frontend
    #[arg(short, long, default_value = "0.0.0.0")]
    address: String,

    /// Bind port for the web frontend
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// User-space controller update period in ms
    #[arg(long, default_value_t = 500)]
    user_period: u64,

    /// Path to a log file to which measurements are to be saved.
    /// If logging is enabled by providing this argument, any other form of web interface will be disabled.
    #[arg(short, long)]
    log_file: Option<PathBuf>,

    /// Enable Prometheus logging in place of the web interface.
    /// The Prometheus-compatible endpoint will be available at `http://address:port`
    #[arg(short = 'P', long, default_value_t = false)]
    prometheus: bool
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    System::new().block_on(async {
        let num_possible_cpus = num_possible_cpus()?;
        
        // Init BPF: open the libbpf skeleton, load the progs and attach them
        let mut open_skel = bpf::ProgSkelBuilder::default().open()?;

        let stack_traces_max_entries = (cli.frequency as f64 *
            num_possible_cpus as f64 *
            (cli.user_period as f64 / 1000.0) *
            1.1 // Add 10% margin to account for controller scheduling irregularities
        ).ceil() as u32 * 2;
        println!("Allocated memory for stack traces BPF map: {}B", stack_traces_max_entries * 128 * 8);
        open_skel.maps_mut().stack_traces().set_max_entries(stack_traces_max_entries)?;

        let mut skel = open_skel.load()?;

        // Explicitly attach entry programs last (because the task-local storage can only be allocated by them)
        #[cfg(not(feature = "save-traces"))]
        let _sched_switch_link = skel.progs_mut().tp_sched_switch().attach()?;
        #[cfg(not(feature = "save-traces"))]
        let _sock_sendmsg_exit_link = skel.progs_mut().sock_sendmsg_exit().attach()?;
        #[cfg(not(feature = "save-traces"))]
        let _sock_recvmsg_exit_link = skel.progs_mut().sock_recvmsg_exit().attach()?;
        #[cfg(not(feature = "save-traces"))]
        let _net_rx_softirq_exit_link = skel.progs_mut().net_rx_softirq_exit().attach()?;

        // Open and attach a perf-event program for each CPU
        let _perf_event_links = unsafe {
            let iter = (0..num_possible_cpus)
                .map(|cpuid| {
                    let mut attrs = perf_event_attr {
                        size: std::mem::size_of::<perf_event_attr>() as _,
                        type_: PERF_TYPE_SOFTWARE,
                        config: PERF_COUNT_SW_CPU_CLOCK as _,

                        // Sampling frequency
                        __bindgen_anon_1: perf_event_open_sys::bindings::perf_event_attr__bindgen_ty_1 {
                            sample_freq: cli.frequency
                        },

                        ..Default::default()
                    };

                    // Only count kernel-space events
                    attrs.set_exclude_user(1);

                    // Use frequency instead of period
                    attrs.set_freq(1);

                    (cpuid, attrs)
                });
            
            let mut v = Vec::with_capacity(num_possible_cpus);
            for (cpuid, mut attrs) in iter {
                // Open the perf-event
                let fd = perf_event_open(&mut attrs, -1, cpuid as _, -1, 0);
                if fd < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                
                // Attach to BPF prog
                v.push(skel.progs_mut().perf_event_prog().attach_perf_event(fd)?);
            }

            v
        };
        
        #[cfg(not(feature = "save-traces"))]
        let _sock_sendmsg_entry_link = skel.progs_mut().sock_sendmsg_entry().attach()?;
        #[cfg(not(feature = "save-traces"))]
        let _sock_recvmsg_entry_link = skel.progs_mut().sock_recvmsg_entry().attach()?;
        #[cfg(not(feature = "save-traces"))]
        let _net_rx_softirq_entry_link = skel.progs_mut().net_rx_softirq_entry().attach()?;

        // Init actors
        let (error_catcher_sender, mut error_catcher_receiver) =
            channel::<anyhow::Error>(1);

        let file_logger_addr = if let Some(path) = &cli.log_file {
            Some(FileLogger::new(path, cli.user_period)?.start())
        } else {
            None
        };
        let prometheus_logger_addr = if cli.prometheus {
            let (sender, receiver) = watch::channel(String::new());
            Some((receiver, PrometheusLogger::new(sender)?.start()))
        } else {
            None
        };

        let metrics_collector_actor_addr = MetricsCollector::new(
            num_possible_cpus,
            file_logger_addr,
            prometheus_logger_addr.as_ref().map(|(_, l)| l.to_owned())
        ).start();
        
        let _trace_analyzer_actor_addr = TraceAnalyzer::new(
            cli.user_period,
            skel,
            num_possible_cpus,
            stack_traces_max_entries,
            metrics_collector_actor_addr.clone(),
            error_catcher_sender
        )?.start();

        // Start HTTP server for frontend
        let server_future = async move {
            if cli.log_file.is_none() {
                HttpServer::new(move || {
                    let app = App::new();
                    
                    if let Some((receiver, _)) = &prometheus_logger_addr {
                        app
                            .app_data(web::Data::new(receiver.clone()))
                            .service(prometheus_log_get)
                    } else {
                        app
                            .app_data(web::Data::new(metrics_collector_actor_addr.clone()))
                            .service(ws_get)
                            .service(Files::new("/", "www").index_file("index.html"))
                    }
                })
                    .bind((cli.address, cli.port))?
                    .run()
                    .await
            } else {
                std::future::pending().await
            }
        };

        tokio::select! {
            ret = server_future => ret.map_err(|e| e.into()),
            msg = error_catcher_receiver.recv() => match msg {
                None => Err(anyhow!("Actors closed unexpectedly")),
                Some(e) => Err(e)
            },
            _ = tokio::signal::ctrl_c() => {
                println!("Exiting...");
                Ok(())
            }
        }
    })
}
