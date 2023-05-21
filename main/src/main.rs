mod bpf {
    include!(concat!(env!("OUT_DIR"), "/prog.bpf.rs"));
}
#[allow(warnings)]
mod common;
mod ksyms;
mod actors;

use actix::{Actor, Addr};
use actix_files::Files;
use actix_web::{HttpServer, App, rt::System, HttpRequest, web, HttpResponse};
use actix_web_actors::ws;
use actors::trace_analyzer::TraceAnalyzer;
use anyhow::anyhow;
use libbpf_rs::num_possible_cpus;
use perf_event_open_sys::{bindings::{perf_event_attr, PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK}, perf_event_open};
use tokio::sync::mpsc::channel;
use crate::actors::{metrics_collector::MetricsCollector, websocket_client::WebsocketClient};

#[actix_web::get("/ws/")]
async fn ws_get(
    req: HttpRequest,
    stream: web::Payload,
    collector: web::Data<Addr<MetricsCollector>>
) -> Result<HttpResponse, actix_web::Error> {
    ws::start(WebsocketClient::new(collector.get_ref().clone()), &req, stream)
}

fn main() -> anyhow::Result<()> {
    System::new().block_on(async {
        // Init BPF: open the libbpf skeleton, load the progs and attach them
        let open_skel = bpf::ProgSkelBuilder::default().open()?;
        let mut skel = open_skel.load()?;
        let num_possible_cpus = num_possible_cpus()?;

        // Explicitly attach entry programs last (because the task-local storage can only be allocated by them)
        let _sched_switch_link = skel.progs_mut().tp_sched_switch().attach()?;
        let _sock_sendmsg_exit_link = skel.progs_mut().sock_sendmsg_exit().attach()?;
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
                            sample_freq: 1000
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
        
        let _sock_sendmsg_entry_link = skel.progs_mut().sock_sendmsg_entry().attach()?;
        let _net_rx_softirq_entry_link = skel.progs_mut().net_rx_softirq_entry().attach()?;

        // Init actors
        let (error_catcher_sender, mut error_catcher_receiver) =
            channel::<anyhow::Error>(1);

        let metrics_collector_actor_addr = MetricsCollector::new(num_possible_cpus)
            .start();
        
        let _trace_analyzer_actor_addr = TraceAnalyzer::new(
            skel,
            num_possible_cpus,
            metrics_collector_actor_addr.clone(),
            error_catcher_sender
        )?.start();

        // Start HTTP server for frontend
        let server_future = HttpServer::new(move || App::new()
            .app_data(web::Data::new(metrics_collector_actor_addr.clone()))
            .service(ws_get)
            .service(Files::new("/", "www").index_file("index.html"))
        )
            .bind(("127.0.0.1", 8080))?
            .run();

        tokio::select! {
            ret = server_future => ret.map_err(|e| e.into()),
            msg = error_catcher_receiver.recv() => match msg {
                None => Err(anyhow!("Actors closed unexpectedly")),
                Some(e) => Err(e)
            }
        }
    })
}
