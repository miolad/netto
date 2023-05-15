//! Defines the means to exchange data between the server -
//! where metrics are collected - and the client, which displays
//! these metrics.

use serde::{Serialize, Deserialize};
use serde_json::json;

/// Represents a single metric, possibly with
/// a list of submetrics.
/// 
/// A metric is indexed by its hierarchical name,
/// for example: "RX Softirq/Bridging".
#[derive(Serialize, Deserialize)]
pub struct Metric {
    /// Name of this metric
    pub name: String,

    /// Fraction of the CPU time in [0, 1] for each CPU
    pub cpu_fracs: Vec<f64>,

    /// List of sub-metrics
    pub sub_metrics: Vec<Metric>
}

/// Wraps the top-level metrics with the total power
/// for the networking stack.
#[derive(Serialize, Deserialize)]
pub struct MetricsWrapper {
    /// Top-level metrics
    pub top_level_metrics: Vec<Metric>,

    /// Power for the networking stack in W
    pub net_power_w: f64,

    /// Number of CPUs
    pub num_possible_cpus: usize
}

impl MetricsWrapper {
    /// Serialize this wrapper into a JSON string from the raw parts
    pub fn to_json(
        top_level_metrics: &Vec<Metric>,
        net_power_w: f64,
        num_possible_cpus: usize
    ) -> String {
        json!({
            "top_level_metrics": top_level_metrics,
            "net_power_w": net_power_w,
            "num_possible_cpus": num_possible_cpus
        }).to_string()
    }

    /// Deserialize from a JSON string
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }
}
