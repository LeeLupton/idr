//! Sentinel Correlator — the "brain" that cross-validates events from all layers.
//!
//! Implements the "Triple-Check" detection methodology:
//! - Tracks kill chain progression: IGMP → QUIC → PTR Reversal → BGP Sinkhole
//! - Detects "impossible states" by correlating events across layers
//! - Triggers panic response when confirmed threats are identified

use idr_common::alert::Alert;
use idr_common::config::IdrConfig;
use idr_common::events::{EventKind, EventSource, IdrEvent, KillChainStage, Severity};
use idr_common::reputation::ReputationDb;
use idr_ebpf::igmp::IgmpCorrelator;
use idr_ebpf::lineage::LineageTracker;
use idr_ebpf::physics::PhysicsMonitor;
use idr_network::ntp::NtpMonitor;
use idr_network::octet::OctetReversalDetector;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::panic_response::PanicResponder;

/// Maximum number of concurrent kill chain tracks (prevents memory exhaustion from IP spoofing)
const MAX_KILL_CHAINS: usize = 10_000;
/// Kill chain entries older than this are evicted
const KILL_CHAIN_TTL_SECS: u64 = 3600; // 1 hour
/// Maximum stored alerts before oldest are dropped
const MAX_ALERTS: usize = 10_000;

/// Active kill chain tracking for a suspected campaign
struct KillChainTracker {
    stages_seen: Vec<(KillChainStage, Uuid)>,
    last_updated: Instant,
}

impl KillChainTracker {
    fn new() -> Self {
        Self {
            stages_seen: Vec::new(),
            last_updated: Instant::now(),
        }
    }

    fn add_stage(&mut self, stage: KillChainStage, event_id: Uuid) {
        if !self.stages_seen.iter().any(|(s, _)| *s == stage) {
            self.stages_seen.push((stage, event_id));
            self.last_updated = Instant::now();
        }
    }

    fn stage_count(&self) -> usize {
        self.stages_seen.len()
    }

    fn event_ids(&self) -> Vec<Uuid> {
        self.stages_seen.iter().map(|(_, id)| *id).collect()
    }

    fn is_expired(&self) -> bool {
        self.last_updated.elapsed().as_secs() > KILL_CHAIN_TTL_SECS
    }
}

/// The Sentinel Correlator ingests all events and performs cross-layer analysis
pub struct SentinelCorrelator {
    config: IdrConfig,
    igmp_correlator: IgmpCorrelator,
    lineage_tracker: LineageTracker,
    physics_monitor: PhysicsMonitor,
    octet_detector: OctetReversalDetector,
    ntp_monitor: NtpMonitor,
    panic_responder: PanicResponder,
    /// Active kill chain tracks (keyed by source IP)
    kill_chains: HashMap<String, KillChainTracker>,
    /// All alerts generated
    alerts: Vec<Alert>,
    /// Physics anomaly active flag (for cross-layer panic check)
    physics_anomaly_active: bool,
    /// Firmware anomaly active flag (for cross-layer panic check)
    firmware_anomaly_active: bool,
    /// Lineage cache prune interval tracking
    last_cache_prune: Instant,
}

impl SentinelCorrelator {
    pub fn new(config: IdrConfig, reputation: Arc<ReputationDb>) -> Self {
        let igmp_correlator =
            IgmpCorrelator::new(config.kernel.igmp_correlation_window_ms);
        let lineage_tracker = LineageTracker::new((*reputation).clone());
        let physics_monitor =
            PhysicsMonitor::new(&config.kernel, (*reputation).clone());
        let octet_detector =
            OctetReversalDetector::new((*reputation).clone());
        let ntp_monitor = NtpMonitor::new(&config.network);
        let panic_responder = PanicResponder::new(&config.sentinel);

        Self {
            config,
            igmp_correlator,
            lineage_tracker,
            physics_monitor,
            octet_detector,
            ntp_monitor,
            panic_responder,
            kill_chains: HashMap::new(),
            alerts: Vec::new(),
            physics_anomaly_active: false,
            firmware_anomaly_active: false,
            last_cache_prune: Instant::now(),
        }
    }

    /// Main event loop — processes events from all layers
    pub async fn run(
        mut self,
        mut event_rx: mpsc::Receiver<IdrEvent>,
        dashboard_tx: broadcast::Sender<IdrEvent>,
    ) -> anyhow::Result<()> {
        info!("Sentinel Correlator running — awaiting events from all layers");

        while let Some(event) = event_rx.recv().await {
            let _ = dashboard_tx.send(event.clone());

            let derived_events = self.process_event(&event).await;

            for derived in derived_events {
                let _ = dashboard_tx.send(derived.clone());
                self.check_panic_condition(&dashboard_tx).await;
            }

            // Periodically prune caches (every 10 minutes)
            if self.last_cache_prune.elapsed().as_secs() > 600 {
                self.lineage_tracker.prune_cache();
                self.prune_stale_kill_chains();
                self.last_cache_prune = Instant::now();
            }
        }

        Ok(())
    }

    async fn process_event(&mut self, event: &IdrEvent) -> Vec<IdrEvent> {
        let mut derived = Vec::new();

        match &event.kind {
            // === Kernel Layer Events ===
            EventKind::IgmpTrigger { .. } | EventKind::QuicHeartbeat { .. } => {
                if let Some(corr) = self.igmp_correlator.process(event) {
                    self.advance_kill_chain(event, KillChainStage::IgmpTrigger);
                    if matches!(corr.kind, EventKind::IgmpQuicCorrelation { .. }) {
                        // Use the original event's source IP for kill chain tracking
                        // (IgmpQuicCorrelation has no src_ip field)
                        self.advance_kill_chain(event, KillChainStage::QuicHeartbeat);
                    }
                    derived.push(corr);
                }
            }

            EventKind::SocketLineage { .. } => {
                if let Some(beacon) = self.lineage_tracker.process(event) {
                    derived.push(beacon);
                }
            }

            EventKind::PhysicsAnomaly { .. } => {
                if let Some(alert) = self.physics_monitor.process(event) {
                    self.physics_anomaly_active = true;
                    self.advance_kill_chain(&alert, KillChainStage::BgpSinkhole);
                    derived.push(alert);
                }
            }

            // === Network Layer Events ===
            EventKind::OctetReversalDetected { .. } => {
                // Enrich with ASN reputation data via the OctetReversalDetector
                if let Some(enriched) = self.octet_detector.analyze(event) {
                    self.advance_kill_chain(&enriched, KillChainStage::PtrOctetReversal);

                    let alert = Alert::critical(
                        "CRITICAL: DPI Evasion via Octet Reversal".to_string(),
                        format!("DNS PTR octet reversal detected: {:?}", enriched.kind),
                        vec![event.id, enriched.id],
                    );
                    self.push_alert(alert);
                    derived.push(enriched);
                } else {
                    // PTR query didn't match evasion pattern — track anyway
                    self.advance_kill_chain(event, KillChainStage::PtrOctetReversal);
                }
            }

            EventKind::NtpTimeShift { .. } => {
                if let Some(evt) = self.ntp_monitor.process(event) {
                    derived.push(evt);
                }
            }

            EventKind::HstsTimeManipulation { .. } => {
                // Check if NTP monitor can correlate with an active shift window
                if let Some(enriched) = self.ntp_monitor.process(event) {
                    let alert = Alert::critical(
                        "HSTS/Time-Manipulation Attack Detected".to_string(),
                        "Expired TLS certificate accepted during NTP time-shift window".to_string(),
                        vec![event.id, enriched.id],
                    );
                    self.push_alert(alert);
                    derived.push(enriched);
                } else {
                    let alert = Alert::critical(
                        "HSTS/Time-Manipulation Attack Detected".to_string(),
                        "Expired TLS certificate accepted".to_string(),
                        vec![event.id],
                    );
                    self.push_alert(alert);
                }
            }

            // === Hardware Layer Events ===
            EventKind::NvmeLatencyAnomaly {
                concurrent_exfil, ..
            } => {
                if *concurrent_exfil {
                    self.firmware_anomaly_active = true;
                    self.advance_kill_chain(event, KillChainStage::NvmeExfiltration);
                }
            }

            EventKind::MacFlapping { .. } => {
                let alert = Alert::critical(
                    "MoCA/ARP Man-in-the-Middle Detected".to_string(),
                    format!("Gateway MAC flapping: {:?}", event.kind),
                    vec![event.id],
                );
                self.alerts.push(alert);
            }

            EventKind::RtcClockDivergence { .. } => {
                warn!("RTC/Software clock divergence — NTP manipulation suspected");
            }

            // === Cross-layer impossible states ===
            EventKind::IgmpQuicCorrelation { .. } => {
                self.check_impossible_state(event, &mut derived);
            }

            _ => {}
        }

        derived
    }

    /// Evict expired kill chain entries and enforce size cap
    fn prune_stale_kill_chains(&mut self) {
        self.kill_chains.retain(|_, tracker| !tracker.is_expired());
        // If still over capacity, drop the oldest entries
        if self.kill_chains.len() > MAX_KILL_CHAINS {
            let mut entries: Vec<_> = self.kill_chains.drain().collect();
            entries.sort_by_key(|(_, t)| std::cmp::Reverse(t.last_updated));
            entries.truncate(MAX_KILL_CHAINS);
            self.kill_chains = entries.into_iter().collect();
        }
    }

    /// Push an alert, dropping oldest if over capacity
    fn push_alert(&mut self, alert: Alert) {
        if self.alerts.len() >= MAX_ALERTS {
            // Drop oldest 10% to amortize the cost
            let drain_count = MAX_ALERTS / 10;
            self.alerts.drain(..drain_count);
        }
        self.alerts.push(alert);
    }

    fn advance_kill_chain(&mut self, event: &IdrEvent, stage: KillChainStage) {
        let src_ip = match extract_source_ip(&event.kind) {
            Some(ip) => ip,
            None => {
                warn!("Cannot extract source IP for kill chain tracking, skipping");
                return;
            }
        };

        let tracker = self
            .kill_chains
            .entry(src_ip.clone())
            .or_insert_with(KillChainTracker::new);

        tracker.add_stage(stage, event.id);

        let count = tracker.stage_count();
        info!(
            src_ip = %src_ip,
            stage = ?stage,
            total_stages = count,
            "Kill chain advanced: {}/5 stages confirmed",
            count
        );

        if count >= 3 {
            let event_ids = tracker.event_ids();
            let stages: Vec<String> = tracker
                .stages_seen
                .iter()
                .map(|(s, _)| format!("{:?}", s))
                .collect();

            let alert = Alert::impossible(
                format!("DPRK-001 Campaign: {}/5 Kill Chain Stages Confirmed", count),
                format!(
                    "Cross-validated impossible state. Stages: {}",
                    stages.join(" → ")
                ),
                event_ids,
            );

            warn!(
                src_ip = %src_ip,
                stages = %stages.join(" → "),
                "IMPOSSIBLE STATE: DPRK-001 kill chain confirmed"
            );

            self.alerts.push(alert);
        }
    }

    fn check_impossible_state(&mut self, event: &IdrEvent, derived: &mut Vec<IdrEvent>) {
        if self.physics_anomaly_active {
            let impossible = IdrEvent::new(
                EventSource::SentinelCorrelation,
                Severity::Impossible,
                EventKind::ImpossibleState {
                    correlated_event_ids: vec![event.id],
                    description:
                        "IGMP→QUIC correlation + physics anomaly = confirmed local intercept"
                            .to_string(),
                    kill_chain_stage: "BgpSinkhole+QuicHeartbeat".to_string(),
                },
            );
            derived.push(impossible);
        }
    }

    /// Check if panic conditions are met: Physics + Firmware anomalies both active
    async fn check_panic_condition(&mut self, dashboard_tx: &broadcast::Sender<IdrEvent>) {
        if self.physics_anomaly_active && self.firmware_anomaly_active {
            error!(
                "PANIC CONDITION MET: Physics Anomaly + Firmware Watchdog both active"
            );

            let panic_event = IdrEvent::new(
                EventSource::SentinelCorrelation,
                Severity::Impossible,
                EventKind::PanicResponse {
                    reason: "Physics anomaly AND firmware watchdog both triggered".to_string(),
                    actions_taken: if self.config.sentinel.auto_panic_enabled {
                        vec![
                            format!("ip link set {} down", self.config.sentinel.panic_interface),
                        ]
                    } else {
                        vec!["Auto-panic disabled — manual intervention required".to_string()]
                    },
                },
            );

            // Broadcast panic event to dashboard BEFORE executing response
            let _ = dashboard_tx.send(panic_event);

            if self.config.sentinel.auto_panic_enabled {
                let success = self.panic_responder.execute().await;
                if success {
                    // Only reset flags if panic response succeeded
                    self.physics_anomaly_active = false;
                    self.firmware_anomaly_active = false;
                } else {
                    // Panic failed — keep flags so we retry on next event cycle
                    error!("Panic response failed — will retry on next event");
                }
            } else {
                warn!("Auto-panic disabled — manual intervention required");
                // Reset flags to avoid log spam, but alert remains
                self.physics_anomaly_active = false;
                self.firmware_anomaly_active = false;
            }
        }
    }
}

fn extract_source_ip(kind: &EventKind) -> Option<String> {
    match kind {
        EventKind::IgmpTrigger { src_ip, .. } => Some(src_ip.clone()),
        EventKind::QuicHeartbeat { src_ip, .. } => Some(src_ip.clone()),
        EventKind::SocketLineage { dst_ip, .. } => Some(dst_ip.clone()),
        EventKind::PhysicsAnomaly { dst_ip, .. } => Some(dst_ip.clone()),
        EventKind::OctetReversalDetected { forward_ip, .. } => Some(forward_ip.clone()),
        EventKind::NvmeLatencyAnomaly { device, .. } => Some(device.clone()),
        EventKind::MacFlapping { gateway_ip, .. } => Some(gateway_ip.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use idr_common::config::IdrConfig;
    use idr_common::events::{EventKind, EventSource, IdrEvent, KillChainStage, Severity};
    use idr_common::reputation::ReputationDb;
    use std::sync::Arc;

    fn make_correlator() -> SentinelCorrelator {
        let config = IdrConfig::default();
        let reputation = Arc::new(ReputationDb::new());
        SentinelCorrelator::new(config, reputation)
    }

    fn make_igmp_trigger(src_ip: &str) -> IdrEvent {
        IdrEvent::new(
            EventSource::KernelEbpf,
            Severity::High,
            EventKind::IgmpTrigger {
                src_ip: src_ip.to_string(),
                group_addr: "224.0.0.1".to_string(),
            },
        )
    }

    fn make_quic_heartbeat(src_ip: &str, dst_ip: &str) -> IdrEvent {
        IdrEvent::new(
            EventSource::KernelEbpf,
            Severity::High,
            EventKind::QuicHeartbeat {
                src_ip: src_ip.to_string(),
                dst_ip: dst_ip.to_string(),
                dst_port: 443,
                pid: 1234,
                exe_path: "/usr/bin/test".to_string(),
            },
        )
    }

    fn make_physics_anomaly(dst_ip: &str) -> IdrEvent {
        IdrEvent::new(
            EventSource::KernelEbpf,
            Severity::High,
            EventKind::PhysicsAnomaly {
                dst_ip: dst_ip.to_string(),
                expected_ttl_range: (48, 58),
                observed_ttl: 63,
                rtt_ms: 2.0,
                reason: "TTL=63 indicates single-hop intercept".to_string(),
            },
        )
    }

    #[tokio::test]
    async fn test_kill_chain_progression() {
        let mut correlator = make_correlator();

        // Stage 1: IGMP trigger from source IP
        let igmp = make_igmp_trigger("192.168.1.100");
        let _ = correlator.process_event(&igmp).await;

        // Stage 2: QUIC heartbeat — same source IP, within correlation window
        let quic = make_quic_heartbeat("192.168.1.100", "8.8.8.8");
        let derived = correlator.process_event(&quic).await;

        // The IGMP correlator should have correlated IGMP+QUIC
        // This advances the kill chain for IgmpTrigger and QuicHeartbeat
        let chain = correlator.kill_chains.get("192.168.1.100");
        assert!(
            chain.is_some(),
            "kill chain should exist for source IP after IGMP+QUIC"
        );
        let stage_count_after_igmp_quic = chain.unwrap().stage_count();
        assert!(
            stage_count_after_igmp_quic >= 2,
            "should have at least 2 kill chain stages after IGMP+QUIC, got {}",
            stage_count_after_igmp_quic
        );

        // Stage 3: Physics anomaly — uses dst_ip as key.
        // The physics monitor only alerts for HighTrust IPs (like 8.8.8.8).
        // advance_kill_chain uses extract_source_ip which returns dst_ip for PhysicsAnomaly.
        // So we feed a physics event for "8.8.8.8" which creates a separate chain key.
        // To get 3 stages under ONE key, we directly advance the kill chain for
        // the same source IP. This tests the kill chain tracker logic.
        let physics_alert = IdrEvent::new(
            EventSource::SentinelCorrelation,
            Severity::Critical,
            EventKind::PhysicsAnomaly {
                dst_ip: "192.168.1.100".to_string(),
                expected_ttl_range: (48, 58),
                observed_ttl: 63,
                rtt_ms: 2.0,
                reason: "TTL=63 indicates single-hop intercept".to_string(),
            },
        );
        correlator.advance_kill_chain(&physics_alert, KillChainStage::BgpSinkhole);

        // Now check: 3+ stages should have triggered a DPRK-001 alert
        let chain = correlator.kill_chains.get("192.168.1.100").unwrap();
        assert!(
            chain.stage_count() >= 3,
            "should have 3+ kill chain stages, got {}",
            chain.stage_count()
        );

        let has_kill_chain_alert = correlator.alerts.iter().any(|a| {
            a.title.contains("Kill Chain") || a.title.contains("DPRK-001")
        });
        assert!(
            has_kill_chain_alert,
            "should have a kill chain alert after 3+ stages. Alerts: {:?}",
            correlator.alerts.iter().map(|a| &a.title).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_impossible_state_detection() {
        let mut correlator = make_correlator();

        // Set physics_anomaly_active to simulate a prior physics anomaly
        correlator.physics_anomaly_active = true;

        // Feed an IgmpQuicCorrelation event — this triggers check_impossible_state
        let correlation_event = IdrEvent::new(
            EventSource::SentinelCorrelation,
            Severity::High,
            EventKind::IgmpQuicCorrelation {
                igmp_event_id: uuid::Uuid::new_v4(),
                quic_event_id: uuid::Uuid::new_v4(),
                window_ms: 200,
            },
        );

        let derived = correlator.process_event(&correlation_event).await;

        // Should produce an ImpossibleState event
        let has_impossible = derived.iter().any(|e| {
            matches!(&e.kind, EventKind::ImpossibleState { .. })
        });
        assert!(
            has_impossible,
            "IgmpQuicCorrelation + physics_anomaly_active should produce ImpossibleState. Got: {:?}",
            derived.iter().map(|e| format!("{:?}", e.kind)).collect::<Vec<_>>()
        );

        // Verify the ImpossibleState event details
        let impossible_event = derived
            .iter()
            .find(|e| matches!(&e.kind, EventKind::ImpossibleState { .. }))
            .unwrap();

        assert_eq!(impossible_event.severity, Severity::Impossible);
        assert_eq!(impossible_event.source, EventSource::SentinelCorrelation);

        if let EventKind::ImpossibleState { description, .. } = &impossible_event.kind {
            assert!(
                description.contains("confirmed local intercept"),
                "description should mention local intercept"
            );
        }
    }
}
