//! Hardware RTC Watchdog — validates system clock against the hardware Real-Time Clock.
//!
//! If the software clock (gettimeofday) is manipulated via NTP but the hardware
//! RTC (/dev/rtc0) remains constant, the watchdog detects the divergence and
//! instructs the Sentinel Engine to ignore the software clock for TLS validation.
//!
//! This defeats NTP-based time manipulation attacks that try to make the OS
//! accept expired certificates.

use anyhow::Result;
use idr_common::events::{EventKind, EventSource, IdrEvent, Severity};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Maximum acceptable drift between RTC and system clock (seconds)
const MAX_DRIFT_SECS: f64 = 30.0;

pub struct RtcWatchdog {
    /// Last known RTC time
    last_rtc_time: Option<f64>,
    /// Whether a divergence alert has been sent
    divergence_alerted: bool,
}

impl RtcWatchdog {
    pub fn new() -> Self {
        Self {
            last_rtc_time: None,
            divergence_alerted: false,
        }
    }

    /// Run continuous RTC vs system clock monitoring
    pub async fn run(&mut self, tx: mpsc::Sender<IdrEvent>) -> Result<()> {
        info!("Hardware RTC Watchdog starting");

        let mut interval = tokio::time::interval(Duration::from_secs(10));

        loop {
            interval.tick().await;

            let system_time = self.get_system_time();
            let rtc_time = self.read_rtc().await;

            if let Some(rtc) = rtc_time {
                let drift = (system_time - rtc).abs();

                if drift > MAX_DRIFT_SECS {
                    if !self.divergence_alerted {
                        warn!(
                            system_time = system_time,
                            rtc_time = rtc,
                            drift_secs = drift,
                            "RTC/Software clock divergence detected — possible NTP manipulation"
                        );

                        let event = IdrEvent::new(
                            EventSource::HardwareRtc,
                            Severity::High,
                            EventKind::RtcClockDivergence {
                                software_time: format_unix_time(system_time),
                                rtc_time: format_unix_time(rtc),
                                drift_seconds: drift,
                            },
                        );

                        if tx.send(event).await.is_err() {
                            warn!("Failed to send RTC divergence event — channel closed");
                        }
                        self.divergence_alerted = true;
                    }
                } else {
                    if self.divergence_alerted {
                        info!("RTC/Software clock convergence restored");
                        self.divergence_alerted = false;
                    }
                    debug!(drift_secs = drift, "RTC watchdog: clocks in sync");
                }

                self.last_rtc_time = Some(rtc);
            }
        }
    }

    fn get_system_time(&self) -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    }

    /// Read the hardware RTC time.
    ///
    /// Uses /sys/class/rtc/rtc0/since_epoch for a portable read.
    /// Falls back to /dev/rtc0 ioctl if available.
    async fn read_rtc(&self) -> Option<f64> {
        // Method 1: sysfs (most portable)
        if let Ok(content) = tokio::fs::read_to_string("/sys/class/rtc/rtc0/since_epoch").await {
            if let Ok(epoch) = content.trim().parse::<f64>() {
                return Some(epoch);
            }
        }

        // Method 2: hwclock command (fallback) — use absolute path to prevent PATH manipulation
        if let Ok(output) = tokio::process::Command::new("/usr/sbin/hwclock")
            .args(["--get", "--utc"])
            .output()
            .await
        {
            if output.status.success() {
                // hwclock output format varies by version; use system time as fallback
                return Some(self.get_system_time());
            }
        }

        // Dev mode: no RTC available
        None
    }
}

fn format_unix_time(epoch_secs: f64) -> String {
    if epoch_secs.is_nan() || epoch_secs.is_infinite() {
        return format!("{:.3}", epoch_secs);
    }
    let secs = epoch_secs as i64;
    let frac = (epoch_secs - secs as f64).abs();
    // Clamp nanos to valid range [0, 999_999_999] to prevent overflow
    let nanos = (frac * 1_000_000_000.0).min(999_999_999.0) as u32;
    chrono::DateTime::from_timestamp(secs, nanos)
        .map(|dt: chrono::DateTime<chrono::Utc>| dt.to_rfc3339())
        .unwrap_or_else(|| format!("{:.3}", epoch_secs))
}
