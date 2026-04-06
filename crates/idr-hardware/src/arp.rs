//! ARP/MAC Flapping Monitor — detects MoCA/Link Layer Man-in-the-Middle.
//!
//! Monitors the ARP table for the gateway IP. If the MAC address changes
//! rapidly (flapping), it indicates a MoCA-layer MitM attack where a
//! compromised device is impersonating the router.

use anyhow::Result;
use idr_common::config::HardwareConfig;
use idr_common::events::{EventKind, EventSource, IdrEvent, Severity};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

struct MacChange {
    old_mac: String,
    new_mac: String,
    timestamp: Instant,
}

pub struct ArpMonitor {
    gateway_ip: String,
    flap_threshold: u32,
    flap_window_secs: u64,
    last_known_mac: Option<String>,
    recent_changes: VecDeque<MacChange>,
}

impl ArpMonitor {
    pub fn new(config: &HardwareConfig) -> Self {
        Self {
            gateway_ip: config.gateway_ip.clone(),
            flap_threshold: config.mac_flap_threshold,
            flap_window_secs: config.mac_flap_window_secs,
            last_known_mac: None,
            recent_changes: VecDeque::new(),
        }
    }

    /// Run continuous ARP table monitoring
    pub async fn run(&mut self, tx: mpsc::Sender<IdrEvent>) -> Result<()> {
        info!(
            gateway = %self.gateway_ip,
            threshold = self.flap_threshold,
            window = self.flap_window_secs,
            "ARP/MAC Flapping Monitor starting"
        );

        let mut interval = tokio::time::interval(Duration::from_secs(2));

        loop {
            interval.tick().await;

            match self.read_arp_entry().await {
                Some(current_mac) => {
                    let mac_changed = self
                        .last_known_mac
                        .as_ref()
                        .map(|last| *last != current_mac)
                        .unwrap_or(false);

                    if mac_changed {
                        let old_mac = self.last_known_mac.clone().unwrap_or_default();

                        let change = MacChange {
                            old_mac: old_mac.clone(),
                            new_mac: current_mac.clone(),
                            timestamp: Instant::now(),
                        };

                        warn!(
                            gateway = %self.gateway_ip,
                            old_mac = %old_mac,
                            new_mac = %current_mac,
                            "Gateway MAC address changed"
                        );

                        self.recent_changes.push_back(change);
                        self.prune_old_changes();

                        let flap_count = self.recent_changes.len() as u32;

                        if flap_count >= self.flap_threshold {
                            let event = IdrEvent::new(
                                EventSource::HardwareMoca,
                                Severity::Critical,
                                EventKind::MacFlapping {
                                    gateway_ip: self.gateway_ip.clone(),
                                    old_mac: old_mac.clone(),
                                    new_mac: current_mac.clone(),
                                    flap_count,
                                    window_seconds: self.flap_window_secs,
                                },
                            );

                            tx.send(event).await.ok();
                        }
                    }
                    self.last_known_mac = Some(current_mac);
                }
                None => {
                    debug!(
                        gateway = %self.gateway_ip,
                        "Gateway not found in ARP table"
                    );
                }
            }
        }
    }

    /// Read the current MAC address for the gateway from /proc/net/arp
    async fn read_arp_entry(&self) -> Option<String> {
        let content = tokio::fs::read_to_string("/proc/net/arp").await.ok()?;

        for line in content.lines().skip(1) {
            // Format: IP HW_type Flags MAC Mask Device
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 && parts[0] == self.gateway_ip {
                return Some(parts[3].to_string());
            }
        }

        None
    }

    fn prune_old_changes(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(self.flap_window_secs);
        while let Some(front) = self.recent_changes.front() {
            if front.timestamp < cutoff {
                self.recent_changes.pop_front();
            } else {
                break;
            }
        }
    }
}
