pub mod trace_analyzer;
pub mod metrics_collector;
pub mod websocket_client;

use actix::{Message, Addr};
use self::websocket_client::WebsocketClient;

/// Signal new client connected to the `MetricsCollector` actor
#[derive(Message)]
#[rtype("()")]
struct ClientConnected {
    addr: Addr<WebsocketClient>
}

/// Signal client disconnected to the `MetricsCollector` actor
#[derive(Message)]
#[rtype("()")]
struct ClientDisconnected {
    addr: Addr<WebsocketClient>
}

/// Represents an update for a single metric on a single CPU
/// from the `TraceAnalyzer` actor.
#[derive(Message)]
#[rtype("()")]
struct MetricUpdate {
    /// This is the hierarchical name of the metric.
    /// For example, "RX softirq/Bridging".
    name: &'static str,

    /// CPU index this metric update is for
    cpuid: usize,

    /// Fraction of CPU time in the [0, 1] range
    cpu_frac: f64
}

/// Used to inform the `MetricsCollector` about the power draw
/// for the current update cycle.
/// 
/// Upon receiving this message, the `MetricsCollector` will
/// trigger the send on every websocket client.
#[derive(Message)]
#[rtype("()")]
struct PowerUpdate {
    /// Power drawn by the CPU in the networking stack
    /// as measured
    net_power_w: f64
}

/// Wrapper around a JSON String to send to websocket clients.
/// This struct exists solely because String can't implement Message.
#[derive(Message)]
#[rtype("()")]
struct EncodedUpdate {
    inner: String
}
