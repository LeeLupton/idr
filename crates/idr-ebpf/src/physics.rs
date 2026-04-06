//! Routing physics anomaly detection.
//!
//! Cross-references observed TTL and RTT values against physically plausible
//! ranges for WAN destinations. A TTL of 63 (one hop) or RTT < 5ms to a
//! global IP like Google is physically impossible — it indicates a local
//! MoCA/router sinkhole intercepting traffic.

use idr_common::config::KernelConfig;
use idr_common::events::{EventKind, EventSource, IdrEvent, Severity};
use idr_common::reputation::{ReputationDb, TrustLevel};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use tracing::warn;

/// Baseline RTT expectations for different geographic regions
struct RttBaseline {
    /// Minimum physically plausible RTT for global IPs (ms)
    min_global_rtt_ms: f64,
    /// Suspicious TTL value (suggests single hop)
    suspicious_ttl: u8,
}

/// Tracks ongoing physics observations per destination IP
pub struct PhysicsMonitor {
    config: KernelConfig,
    reputation: ReputationDb,
    baseline: RttBaseline,
    /// Rolling statistics per destination
    observations: HashMap<Ipv4Addr, PhysicsStats>,
}

struct PhysicsStats {
    rtt_samples: Vec<f64>,
    ttl_values: Vec<u8>,
    anomaly_count: u32,
}

impl PhysicsMonitor {
    pub fn new(config: &KernelConfig, reputation: ReputationDb) -> Self {
        Self {
            config: config.clone(),
            reputation,
            baseline: RttBaseline {
                min_global_rtt_ms: config.suspicious_rtt_ms,
                suspicious_ttl: config.suspicious_ttl,
            },
            observations: HashMap::new(),
        }
    }

    /// Process a physics event from eBPF. Returns an alert if anomaly detected.
    pub fn process(&mut self, event: &IdrEvent) -> Option<IdrEvent> {
        let (dst_ip_str, observed_ttl, rtt_ms) = match &event.kind {
            EventKind::PhysicsAnomaly {
                dst_ip,
                observed_ttl,
                rtt_ms,
                ..
            } => (dst_ip.clone(), *observed_ttl, *rtt_ms),
            _ => return None,
        };

        let dst_ip: Ipv4Addr = dst_ip_str.parse().ok()?;
        let trust = self.reputation.classify_ip(&dst_ip);

        // Only alert on high-trust IPs with physics violations
        if trust != TrustLevel::HighTrust {
            return None;
        }

        let stats = self
            .observations
            .entry(dst_ip)
            .or_insert_with(|| PhysicsStats {
                rtt_samples: Vec::new(),
                ttl_values: Vec::new(),
                anomaly_count: 0,
            });

        stats.rtt_samples.push(rtt_ms);
        stats.ttl_values.push(observed_ttl);

        let mut reasons = Vec::new();

        // Check TTL anomaly: TTL=63 means single hop from a /64 start
        if observed_ttl == self.baseline.suspicious_ttl {
            reasons.push(format!(
                "TTL={} indicates single-hop intercept (expected 48-58 for {})",
                observed_ttl, dst_ip_str
            ));
        }

        // Check RTT anomaly: sub-5ms to a global IP is physically impossible
        if rtt_ms < self.baseline.min_global_rtt_ms && rtt_ms > 0.0 {
            reasons.push(format!(
                "RTT={:.2}ms to {} is below physical minimum for WAN (speed of light)",
                rtt_ms, dst_ip_str
            ));
        }

        if reasons.is_empty() {
            return None;
        }

        stats.anomaly_count += 1;
        let reason = reasons.join("; ");

        warn!(
            dst_ip = %dst_ip_str,
            ttl = observed_ttl,
            rtt_ms = rtt_ms,
            anomaly_count = stats.anomaly_count,
            "PHYSICAL INTERCEPT ALERT: {}", reason
        );

        Some(IdrEvent::new(
            EventSource::SentinelCorrelation,
            Severity::Critical,
            EventKind::PhysicsAnomaly {
                dst_ip: dst_ip_str,
                expected_ttl_range: (48, 58),
                observed_ttl,
                rtt_ms,
                reason,
            },
        ))
    }

    /// Get the anomaly count for a specific destination
    pub fn anomaly_count(&self, ip: &Ipv4Addr) -> u32 {
        self.observations
            .get(ip)
            .map(|s| s.anomaly_count)
            .unwrap_or(0)
    }
}
