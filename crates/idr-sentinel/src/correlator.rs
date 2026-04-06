//! Sentinel Correlator — the "brain" that cross-validates events from all layers.
//!
//! Implements the "Triple-Check" detection methodology:
//! - Tracks kill chain progression: IGMP → QUIC → PTR Reversal → BGP Sinkhole
//! - Detects "impossible states" by correlating events across layers
//! - Triggers panic response when confirmed threats are identified

use idr_common::alert::{Alert, PanicAction};
use idr_common::config::IdrConfig;
use idr_common::events::{EventKind, EventSource, IdrEvent, KillChainStage, Severity};
use idr_common::reputation::ReputationDb;
use idr_ebpf::igmp::IgmpCorrelator;
use idr_ebpf::lineage::LineageTracker;
use idr_ebpf::physics::PhysicsMonitor;
use idr_network::octet::OctetReversalDetector;
use idr_network::ntp::NtpMonitor;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::panic_response::PanicResponder;

/// Active kill chain tracking for a suspected campaign
struct KillChainTracker {
    stages_seen: Vec<(KillChainStage, Uuid)>,
    first_seen: chrono::DateTime<chrono::Utc>,
    last_updated: chrono::DateTime<chrono::Utc>,
}

impl KillChainTracker {
    fn new() -> Self {
        let now = chrono::Utc::now();
        Self {
            stages_seen: Vec::new(),
            first_seen: now,
            last_updated: now,
        }
    }

    fn add_stage(&mut self, stage: KillChainStage, event_id: Uuid) {
        if !self.stages_seen.iter().any(|(s, _)| *s == stage) {
            self.stages_seen.push((stage, event_id));
            self.last_updated = chrono::Utc::now();
        }
    }

    fn stage_count(&self) -> usize {
        self.stages_seen.len()
    }

    fn event_ids(&self) -> Vec<Uuid> {
        self.stages_seen.iter().map(|(_, id)| *id).collect()
    }

    fn has_stage(&self, stage: KillChainStage) -> bool {
        self.stages_seen.iter().any(|(s, _)| *s == stage)
    }
}

/// The Sentinel Correlator ingests all events and performs cross-layer analysis
pub struct SentinelCorrelator {
    config: IdrConfig,
    reputation: Arc<ReputationDb>,
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
            reputation,
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
            // Forward raw event to dashboard
            let _ = dashboard_tx.send(event.clone());

            // Process through all correlators
            let derived_events = self.process_event(&event).await;

            // Forward derived events to dashboard and re-process for cascading
            for derived in derived_events {
                let _ = dashboard_tx.send(derived.clone());

                // Check for panic condition after each derived event
                self.check_panic_condition(&derived).await;
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
                    self.advance_kill_chain(&event, KillChainStage::IgmpTrigger);
                    if matches!(corr.kind, EventKind::IgmpQuicCorrelation { .. }) {
                        self.advance_kill_chain(&corr, KillChainStage::QuicHeartbeat);
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
                self.advance_kill_chain(event, KillChainStage::PtrOctetReversal);

                let alert = Alert::critical(
                    "CRITICAL: DPI Evasion via Octet Reversal".to_string(),
                    format!("DNS PTR octet reversal detected: {:?}", event.kind),
                    vec![event.id],
                );
                self.alerts.push(alert);
            }

            EventKind::NtpTimeShift { .. } => {
                if let Some(evt) = self.ntp_monitor.process(event) {
                    derived.push(evt);
                }
            }

            EventKind::HstsTimeManipulation { .. } => {
                let alert = Alert::critical(
                    "HSTS/Time-Manipulation Attack Detected".to_string(),
                    "Expired TLS certificate accepted during NTP time-shift window".to_string(),
                    vec![event.id],
                );
                self.alerts.push(alert);
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

    /// Advance the kill chain tracker for a source IP
    fn advance_kill_chain(&mut self, event: &IdrEvent, stage: KillChainStage) {
        // Extract source IP from event (simplified — uses first IP found)
        let src_ip = extract_source_ip(&event.kind).unwrap_or_else(|| "unknown".to_string());

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

        // If 3+ stages confirmed, generate impossible state alert
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
        // An IGMP→QUIC correlation that also has physics anomalies = impossible state
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
    async fn check_panic_condition(&mut self, event: &IdrEvent) {
        if self.physics_anomaly_active && self.firmware_anomaly_active {
            error!(
                "PANIC CONDITION MET: Physics Anomaly + Firmware Watchdog both active"
            );

            let event_ids: Vec<Uuid> = self.alerts.iter().map(|a| a.id).collect();

            let panic_event = IdrEvent::new(
                EventSource::SentinelCorrelation,
                Severity::Impossible,
                EventKind::PanicResponse {
                    reason: "Physics anomaly AND firmware watchdog both triggered".to_string(),
                    actions_taken: vec![],
                },
            );

            // Execute panic response
            if self.config.sentinel.auto_panic_enabled {
                self.panic_responder.execute().await;
            } else {
                warn!("Auto-panic disabled — manual intervention required");
            }
        }
    }
}

/// Extract source IP from various event kinds
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
