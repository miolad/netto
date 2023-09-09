use std::collections::HashMap;
use actix::{Actor, Context, Handler};
use actix_web::web;
use prometheus::{Registry, GaugeVec, Gauge, Opts, TextEncoder};
use tokio::sync::watch::{Sender, Receiver};
use super::{MetricUpdate, SubmitUpdate};

#[actix_web::get("/")]
async fn prometheus_log_get(
    receiver: web::Data<Receiver<String>>
) -> String {
    receiver.borrow().clone()
}

pub struct PrometheusLogger {
    registry: Registry,
    encoder: TextEncoder,
    
    metrics: HashMap<String, GaugeVec>,
    procfs_metrics: GaugeVec,
    net_power_w: Gauge,
    user_space_overhead: Gauge,

    watch_sender: Sender<String>
}

impl Handler<MetricUpdate> for PrometheusLogger {
    type Result = ();

    fn handle(&mut self, msg: MetricUpdate, _ctx: &mut Self::Context) -> Self::Result {
        let name = msg.name
            .to_ascii_lowercase()
            .replace(' ', "_")
            .replace('/', "__");
        
        self.metrics.entry(name.clone())
            .or_insert_with(|| {
                let g = GaugeVec::new(Opts::new(name, msg.name), &["cpu"]).unwrap();
                self.registry.register(Box::new(g.clone())).unwrap();
                g
            })
            .with_label_values(&[&format!("{}", msg.cpuid)])
            .set(msg.cpu_frac);
    }
}

impl Handler<SubmitUpdate> for PrometheusLogger {
    type Result = ();

    fn handle(&mut self, msg: SubmitUpdate, _ctx: &mut Self::Context) -> Self::Result {
        for (index, m) in msg.procfs_metrics.iter().enumerate() {
            self.procfs_metrics.with_label_values(&[&format!("{index}")]).set(*m);
        }
        self.net_power_w.set(msg.net_power_w.unwrap_or(-1.0));
        self.user_space_overhead.set(msg.user_space_overhead);

        self.watch_sender.send_modify(|buf| {
            buf.clear();
            let _ = self.encoder.encode_utf8(&self.registry.gather(), buf);
        });
    }
}

impl PrometheusLogger {
    pub fn new(watch_sender: Sender<String>) -> anyhow::Result<Self> {
        let registry = Registry::new();
        let encoder = TextEncoder::new();
        
        let metrics = HashMap::new();
        let procfs_metrics = GaugeVec::new(Opts::new(
            "procfs_metric",
            "Collection of overall CPU metrics from /proc/stat"
        ), &["index"])?;
        let net_power_w = Gauge::new(
            "net_power",
            "Total amount of power (in W) consumed by networking. Negative if unavailable"
        )?;
        let user_space_overhead = Gauge::new(
            "user_space_overhead",
            "Fraction of CPU time used by Netto in the userspace to analyze stack traces"
        )?;

        registry.register(Box::new(procfs_metrics.clone()))?;
        registry.register(Box::new(net_power_w.clone()))?;
        registry.register(Box::new(user_space_overhead.clone()))?;
        
        Ok(Self {
            registry,
            encoder,
            metrics,
            procfs_metrics,
            net_power_w,
            user_space_overhead,
            watch_sender
        })
    }
}

impl Actor for PrometheusLogger {
    type Context = Context<Self>;
}
