//! Defines the means to exchange data between the server -
//! where metrics are collected - and the client, which displays
//! these metrics.

use serde::{Serialize, Deserialize};

/// Represents a single metric, possibly with
/// a list of submetrics.
/// 
/// A metric is indexed by its hierarchical name,
/// for example: "RX Softirq/Bridging".
#[derive(Serialize, Deserialize, Clone)]
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

    /// Power for the networking stack in W.
    /// It's None if the RAPL interface isn't available.
    pub net_power_w: Option<f64>,

    /// Fraction of the CPU time spent by the user-space tool
    pub user_space_overhead: f64,

    /// Number of CPUs
    pub num_possible_cpus: usize,

    /// Metrics acquired from /proc/stat for validation
    pub procfs_metrics: Vec<f64>
}

impl MetricsWrapper {
    /// Serialize this wrapper into a MessagePack buffer from the raw parts
    pub fn to_mp(
        top_level_metrics: &[Metric],
        net_power_w: Option<f64>,
        user_space_overhead: f64,
        num_possible_cpus: usize,
        procfs_metrics: Vec<f64>
    ) -> Vec<u8> {
        let wrapper = Self {
            top_level_metrics: top_level_metrics.to_vec(),
            net_power_w,
            user_space_overhead,
            num_possible_cpus,
            procfs_metrics
        };

        rmp_serde::to_vec(&wrapper).unwrap()
    }

    /// Deserialize from a MessagePack slice
    pub fn from_mp(mp: &[u8]) -> Result<Self, rmp_serde::decode::Error> {
        rmp_serde::from_slice(mp)
    }
}
