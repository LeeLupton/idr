//! Panic Response — automated threat response when impossible states are confirmed.
//!
//! When both Physics Anomaly and Firmware Watchdog fire simultaneously:
//! 1. Immediately `ip link set [interface] down` — kill network
//! 2. Optionally `nvme format --ses=2` — cryptographic erase (if user-toggled)

use idr_common::config::{is_valid_device_path, SentinelConfig};
use tracing::{error, info, warn};

pub struct PanicResponder {
    interface: String,
    nvme_device: String,
    allow_nvme_erase: bool,
    auto_enabled: bool,
}

impl PanicResponder {
    pub fn new(config: &SentinelConfig) -> Self {
        Self {
            interface: config.panic_interface.clone(),
            nvme_device: String::from("/dev/nvme0n1"),
            allow_nvme_erase: config.allow_nvme_erase,
            auto_enabled: config.auto_panic_enabled,
        }
    }

    /// Set the NVMe device path from hardware config
    #[allow(dead_code)]
    pub fn with_nvme_device(mut self, device: &str) -> Self {
        if is_valid_device_path(device) {
            self.nvme_device = device.to_string();
        } else {
            error!(device = %device, "Invalid NVMe device path, keeping default");
        }
        self
    }

    /// Execute the panic response sequence.
    /// Returns true if the critical network kill succeeded, false otherwise.
    pub async fn execute(&self) -> bool {
        if !self.auto_enabled {
            warn!("Panic response requested but auto-panic is disabled");
            return false;
        }

        error!("=== PANIC RESPONSE EXECUTING ===");

        let network_killed = self.kill_network().await;

        if self.allow_nvme_erase {
            self.nvme_crypto_erase().await;
        }

        if network_killed {
            error!("=== PANIC RESPONSE COMPLETE ===");
        } else {
            error!("=== PANIC RESPONSE FAILED — network kill unsuccessful ===");
        }

        network_killed
    }

    async fn kill_network(&self) -> bool {
        error!(interface = %self.interface, "PANIC: Disabling network interface");

        // Use absolute path to prevent PATH manipulation
        let result = tokio::process::Command::new("/usr/sbin/ip")
            .args(["link", "set", &self.interface, "down"])
            .output()
            .await;

        match result {
            Ok(output) if output.status.success() => {
                info!(interface = %self.interface, "Network interface disabled");
                true
            }
            Ok(output) => {
                error!(
                    interface = %self.interface,
                    stderr = %String::from_utf8_lossy(&output.stderr),
                    "Failed to disable network interface"
                );
                false
            }
            Err(e) => {
                error!(
                    interface = %self.interface,
                    error = %e,
                    "Failed to execute ip command"
                );
                false
            }
        }
    }

    async fn nvme_crypto_erase(&self) {
        error!(device = %self.nvme_device, "PANIC: Initiating NVMe cryptographic erase (ses=2)");

        let result = tokio::process::Command::new("nvme")
            .args(["format", &self.nvme_device, "--ses=2"])
            .output()
            .await;

        match result {
            Ok(output) if output.status.success() => {
                info!("NVMe cryptographic erase completed");
            }
            Ok(output) => {
                error!(
                    stderr = %String::from_utf8_lossy(&output.stderr),
                    "NVMe crypto-erase failed"
                );
            }
            Err(e) => {
                error!(error = %e, "Failed to execute nvme command");
            }
        }
    }
}
