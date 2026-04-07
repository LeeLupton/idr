//! NTP/TLS Integrity Monitor.
//!
//! Tracks NTP time shifts and correlates them with TLS certificate acceptance.
//! If an NTP shift > 5 minutes occurs, the next 10 TLS handshakes are flagged.
//! If any of those handshakes accept an expired certificate, it triggers an
//! HSTS/Time-Manipulation alert.

use idr_common::config::NetworkConfig;
use idr_common::events::{EventKind, EventSource, IdrEvent, Severity};
use std::collections::VecDeque;
use tracing::warn;

/// Maximum concurrent NTP shift windows tracked (prevents flood DoS)
const MAX_SHIFT_WINDOWS: usize = 100;

struct NtpShiftWindow {
    offset_seconds: f64,
    ntp_server: String,
    tls_handshakes_remaining: usize,
}

pub struct NtpMonitor {
    /// Active NTP shift windows (multiple shifts can be tracked)
    active_shifts: VecDeque<NtpShiftWindow>,
    /// How many TLS handshakes to flag after each shift
    flag_count: usize,
    /// NTP shift threshold in seconds
    threshold_secs: f64,
}

impl NtpMonitor {
    pub fn new(config: &NetworkConfig) -> Self {
        Self {
            active_shifts: VecDeque::new(),
            flag_count: config.tls_flag_count_after_ntp,
            threshold_secs: config.ntp_shift_threshold_secs,
        }
    }

    /// Process an NTP or TLS event.
    /// Returns a time-manipulation alert if expired cert accepted during shift.
    pub fn process(&mut self, event: &IdrEvent) -> Option<IdrEvent> {
        match &event.kind {
            EventKind::NtpTimeShift {
                offset_seconds,
                ntp_server,
            } => {
                if *offset_seconds > self.threshold_secs {
                    warn!(
                        offset = offset_seconds,
                        server = %ntp_server,
                        "NTP time shift exceeds threshold — flagging next {} TLS handshakes",
                        self.flag_count
                    );

                    // Evict oldest window if at capacity
                    if self.active_shifts.len() >= MAX_SHIFT_WINDOWS {
                        self.active_shifts.pop_front();
                    }
                    self.active_shifts.push_back(NtpShiftWindow {
                        offset_seconds: *offset_seconds,
                        ntp_server: ntp_server.clone(),
                        tls_handshakes_remaining: self.flag_count,
                    });
                }
                None
            }

            EventKind::HstsTimeManipulation {
                domain,
                cert_expiry,
                ..
            } => {
                // Check if this TLS event falls within any active NTP shift window
                let mut matched_shift = None;

                for shift in &mut self.active_shifts {
                    if shift.tls_handshakes_remaining > 0 {
                        shift.tls_handshakes_remaining -= 1;
                        matched_shift = Some((shift.offset_seconds, shift.ntp_server.clone()));
                        break;
                    }
                }

                // Clean up exhausted windows
                self.active_shifts
                    .retain(|s| s.tls_handshakes_remaining > 0);

                if let Some((offset, server)) = matched_shift {
                    warn!(
                        domain = %domain,
                        cert_expiry = %cert_expiry,
                        ntp_offset = offset,
                        ntp_server = %server,
                        "HSTS/Time-Manipulation Attack: expired cert accepted during NTP shift"
                    );

                    return Some(IdrEvent::new(
                        EventSource::NetworkZeek,
                        Severity::Critical,
                        EventKind::HstsTimeManipulation {
                            domain: domain.clone(),
                            cert_expiry: cert_expiry.clone(),
                            ntp_shift_seconds: offset,
                        },
                    ));
                }

                None
            }

            _ => None,
        }
    }

    /// Check if any NTP shift windows are currently active
    pub fn has_active_shifts(&self) -> bool {
        !self.active_shifts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use idr_common::config::NetworkConfig;
    use idr_common::events::{EventKind, EventSource, IdrEvent, Severity};

    fn make_ntp_shift(offset: f64) -> IdrEvent {
        IdrEvent::new(
            EventSource::NetworkZeek,
            Severity::High,
            EventKind::NtpTimeShift {
                offset_seconds: offset,
                ntp_server: "pool.ntp.org".to_string(),
            },
        )
    }

    fn make_hsts_event(domain: &str, cert_expiry: &str) -> IdrEvent {
        IdrEvent::new(
            EventSource::NetworkZeek,
            Severity::High,
            EventKind::HstsTimeManipulation {
                domain: domain.to_string(),
                cert_expiry: cert_expiry.to_string(),
                ntp_shift_seconds: 0.0,
            },
        )
    }

    #[test]
    fn test_ntp_shift_opens_window() {
        let config = NetworkConfig::default();
        let mut monitor = NtpMonitor::new(&config);

        assert!(!monitor.has_active_shifts());

        // NTP shift > 300s should create an active window
        let event = make_ntp_shift(600.0);
        let result = monitor.process(&event);

        // NTP shift itself returns None (no alert yet)
        assert!(result.is_none());
        // But a window should now be active
        assert!(monitor.has_active_shifts());
    }

    #[test]
    fn test_hsts_during_shift() {
        let config = NetworkConfig::default();
        let mut monitor = NtpMonitor::new(&config);

        // First, create an NTP shift window
        let shift = make_ntp_shift(600.0);
        monitor.process(&shift);
        assert!(monitor.has_active_shifts());

        // Now an expired cert event during the shift should trigger an alert
        let hsts = make_hsts_event("example.com", "2024-01-01T00:00:00Z");
        let result = monitor.process(&hsts);

        assert!(result.is_some(), "expired cert during shift should alert");
        let alert = result.unwrap();
        assert_eq!(alert.severity, Severity::Critical);
        if let EventKind::HstsTimeManipulation {
            ntp_shift_seconds, ..
        } = &alert.kind
        {
            assert_eq!(*ntp_shift_seconds, 600.0);
        } else {
            panic!("expected HstsTimeManipulation event kind");
        }
    }

    #[test]
    fn test_hsts_without_shift() {
        let config = NetworkConfig::default();
        let mut monitor = NtpMonitor::new(&config);

        // No NTP shift window active
        assert!(!monitor.has_active_shifts());

        // Expired cert without active shift should return None
        let hsts = make_hsts_event("example.com", "2024-01-01T00:00:00Z");
        let result = monitor.process(&hsts);
        assert!(result.is_none(), "expired cert without shift should not alert");
    }

    #[test]
    fn test_window_exhaustion() {
        let mut config = NetworkConfig::default();
        config.tls_flag_count_after_ntp = 3; // Small count for testing
        let mut monitor = NtpMonitor::new(&config);

        // Create shift window with flag_count=3
        let shift = make_ntp_shift(600.0);
        monitor.process(&shift);
        assert!(monitor.has_active_shifts());

        // First 3 handshakes should consume the window
        for i in 0..3 {
            let hsts = make_hsts_event(
                &format!("example{}.com", i),
                "2024-01-01T00:00:00Z",
            );
            let result = monitor.process(&hsts);
            assert!(
                result.is_some(),
                "handshake {} should still be within window",
                i
            );
        }

        // Window should now be exhausted
        assert!(
            !monitor.has_active_shifts(),
            "window should be exhausted after flag_count handshakes"
        );

        // 4th handshake should NOT trigger
        let hsts = make_hsts_event("example-extra.com", "2024-01-01T00:00:00Z");
        let result = monitor.process(&hsts);
        assert!(result.is_none(), "handshake after exhaustion should not alert");
    }
}
