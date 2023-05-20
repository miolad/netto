use std::collections::HashSet;
use actix::{Addr, Actor, Context, Handler};
use metrics_common::{Metric, MetricsWrapper};
use super::{websocket_client::WebsocketClient, MetricUpdate, SubmitUpdate, EncodedUpdate, ClientConnected, ClientDisconnected};

pub struct MetricsCollector {
    metrics_root: Metric,
    clients: HashSet<Addr<WebsocketClient>>,
    num_possible_cpus: usize
}

impl Actor for MetricsCollector {
    type Context = Context<Self>;
}

impl Handler<MetricUpdate> for MetricsCollector {
    type Result = ();

    fn handle(&mut self, msg: MetricUpdate, _: &mut Self::Context) -> Self::Result {
        let mut target = &mut self.metrics_root;

        for segment in msg.name.split('/') {
            let sub_metric_index = target.sub_metrics
                .iter()
                .enumerate()
                .find_map(|(i, e)| (e.name == segment).then_some(i))
                .unwrap_or_else(|| {
                    target.sub_metrics.push(Metric {
                        name: segment.to_string(),
                        cpu_fracs: vec![],
                        sub_metrics: vec![]
                    });
                    target.sub_metrics.len() - 1
                });
            
            target = &mut target.sub_metrics[sub_metric_index];
        }

        target.cpu_fracs.resize(self.num_possible_cpus, 0.0);
        target.cpu_fracs[msg.cpuid] = msg.cpu_frac;
    }
}

impl Handler<SubmitUpdate> for MetricsCollector {
    type Result = ();

    fn handle(&mut self, msg: SubmitUpdate, _: &mut Self::Context) -> Self::Result {
        let json = MetricsWrapper::to_json(
            &self.metrics_root.sub_metrics,
            msg.net_power_w,
            msg.user_space_overhead,
            self.num_possible_cpus
        );

        for addr in &self.clients {
            addr.do_send(EncodedUpdate { inner: json.clone() });
        }
    }
}

impl Handler<ClientConnected> for MetricsCollector {
    type Result = ();

    fn handle(&mut self, msg: ClientConnected, _: &mut Self::Context) -> Self::Result {
        self.clients.insert(msg.addr);
    }
}

impl Handler<ClientDisconnected> for MetricsCollector {
    type Result = ();

    fn handle(&mut self, msg: ClientDisconnected, _: &mut Self::Context) -> Self::Result {
        self.clients.remove(&msg.addr);
    }
}

impl MetricsCollector {
    pub fn new(num_possible_cpus: usize) -> Self {
        Self {
            metrics_root: Metric {
                name: "/".to_string(),
                cpu_fracs: vec![],
                sub_metrics: vec![]
            },
            clients: HashSet::new(),
            num_possible_cpus
        }
    }
}
