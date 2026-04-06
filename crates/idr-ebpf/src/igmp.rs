//! IGMP → QUIC correlation module.
//!
//! Implements the 500ms sliding window: when an IGMP v3 trigger is detected,
//! any outbound QUIC (UDP 443) heartbeat within the next 500ms is flagged
//! as a correlated C2 wake/beacon pattern.

use idr_common::events::{EventKind, EventSource, IdrEvent, Severity};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tracing::{info, warn};
use uuid::Uuid;

const CORRELATION_WINDOW: Duration = Duration::from_millis(500);

struct IgmpTrigger {
    event_id: Uuid,
    timestamp: Instant,
}

/// Correlates IGMP triggers with subsequent QUIC heartbeats
pub struct IgmpCorrelator {
    /// Recent IGMP triggers within the correlation window
    active_triggers: VecDeque<IgmpTrigger>,
    /// Configuration: window size
    window: Duration,
}

impl IgmpCorrelator {
    pub fn new(window_ms: u64) -> Self {
        Self {
            active_triggers: VecDeque::new(),
            window: Duration::from_millis(window_ms),
        }
    }

    /// Process an incoming event. Returns a correlation event if IGMP→QUIC pattern matches.
    pub fn process(&mut self, event: &IdrEvent) -> Option<IdrEvent> {
        // Prune expired triggers
        let now = Instant::now();
        while let Some(front) = self.active_triggers.front() {
            if now.duration_since(front.timestamp) > self.window {
                self.active_triggers.pop_front();
            } else {
                break;
            }
        }

        match &event.kind {
            EventKind::IgmpTrigger { src_ip, group_addr } => {
                info!(
                    src_ip = %src_ip,
                    group_addr = %group_addr,
                    "IGMP v3 trigger detected — opening {}ms correlation window",
                    self.window.as_millis()
                );
                self.active_triggers.push_back(IgmpTrigger {
                    event_id: event.id,
                    timestamp: now,
                });
                None
            }
            EventKind::QuicHeartbeat {
                dst_ip, dst_port, ..
            } => {
                // Check if any active IGMP trigger correlates
                if let Some(trigger) = self.active_triggers.front() {
                    let elapsed = now.duration_since(trigger.timestamp);
                    warn!(
                        dst_ip = %dst_ip,
                        dst_port = dst_port,
                        elapsed_ms = elapsed.as_millis() as u64,
                        "QUIC heartbeat within IGMP correlation window — CRITICAL"
                    );

                    Some(IdrEvent::new(
                        EventSource::SentinelCorrelation,
                        Severity::Critical,
                        EventKind::IgmpQuicCorrelation {
                            igmp_event_id: trigger.event_id,
                            quic_event_id: event.id,
                            window_ms: elapsed.as_millis() as u64,
                        },
                    ))
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl Default for IgmpCorrelator {
    fn default() -> Self {
        Self::new(CORRELATION_WINDOW.as_millis() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_igmp_quic_correlation() {
        let mut correlator = IgmpCorrelator::new(500);

        // Simulate IGMP trigger
        let igmp_event = IdrEvent::new(
            EventSource::KernelEbpf,
            Severity::High,
            EventKind::IgmpTrigger {
                src_ip: "192.168.1.100".to_string(),
                group_addr: "224.0.0.1".to_string(),
            },
        );

        // Should not produce correlation on IGMP alone
        assert!(correlator.process(&igmp_event).is_none());

        // Simulate QUIC heartbeat within window
        let quic_event = IdrEvent::new(
            EventSource::KernelEbpf,
            Severity::Warning,
            EventKind::QuicHeartbeat {
                src_ip: "192.168.1.100".to_string(),
                dst_ip: "142.250.80.46".to_string(),
                dst_port: 443,
                pid: 1234,
                exe_path: "/usr/bin/unknown".to_string(),
            },
        );

        let result = correlator.process(&quic_event);
        assert!(result.is_some());

        if let Some(event) = result {
            assert_eq!(event.severity, Severity::Critical);
            matches!(event.kind, EventKind::IgmpQuicCorrelation { .. });
        }
    }
}
