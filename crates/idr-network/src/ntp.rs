//! NTP/TLS Integrity Monitor.
//!
//! Tracks NTP time shifts and correlates them with TLS certificate acceptance.
//! If an NTP shift > 5 minutes occurs, the next 10 TLS handshakes are flagged.
//! If any of those handshakes accept an expired certificate, it triggers an
//! HSTS/Time-Manipulation alert.

use idr_common::config::NetworkConfig;
use idr_common::events::{EventKind, EventSource, IdrEvent, Severity};
use std::collections::VecDeque;
use std::time::Instant;
use tracing::{info, warn};

struct NtpShiftWindow {
    shift_time: Instant,
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

                    self.active_shifts.push_back(NtpShiftWindow {
                        shift_time: Instant::now(),
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
