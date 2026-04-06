//! Panic Response — automated threat response when impossible states are confirmed.
//!
//! When both Physics Anomaly and Firmware Watchdog fire simultaneously:
//! 1. Immediately `ip link set [interface] down` — kill network
//! 2. Optionally `nvme format --ses=2` — cryptographic erase (if user-toggled)

use idr_common::config::SentinelConfig;
use tracing::{error, info, warn};

pub struct PanicResponder {
    interface: String,
    allow_nvme_erase: bool,
    auto_enabled: bool,
}

impl PanicResponder {
    pub fn new(config: &SentinelConfig) -> Self {
        Self {
            interface: config.panic_interface.clone(),
            allow_nvme_erase: config.allow_nvme_erase,
            auto_enabled: config.auto_panic_enabled,
        }
    }

    /// Execute the panic response sequence
    pub async fn execute(&self) {
        if !self.auto_enabled {
            warn!("Panic response requested but auto-panic is disabled");
            return;
        }

        error!("=== PANIC RESPONSE EXECUTING ===");

        // Step 1: Kill network interface immediately
        self.kill_network().await;

        // Step 2: NVMe crypto-erase if enabled
        if self.allow_nvme_erase {
            self.nvme_crypto_erase().await;
        }

        error!("=== PANIC RESPONSE COMPLETE ===");
    }

    async fn kill_network(&self) {
        error!(interface = %self.interface, "PANIC: Disabling network interface");

        let result = tokio::process::Command::new("ip")
            .args(["link", "set", &self.interface, "down"])
            .output()
            .await;

        match result {
            Ok(output) if output.status.success() => {
                info!(interface = %self.interface, "Network interface disabled");
            }
            Ok(output) => {
                error!(
                    interface = %self.interface,
                    stderr = %String::from_utf8_lossy(&output.stderr),
                    "Failed to disable network interface"
                );
            }
            Err(e) => {
                error!(
                    interface = %self.interface,
                    error = %e,
                    "Failed to execute ip command"
                );
            }
        }
    }

    async fn nvme_crypto_erase(&self) {
        error!("PANIC: Initiating NVMe cryptographic erase (ses=2)");

        // This is intentionally destructive — only runs if user explicitly enabled
        let result = tokio::process::Command::new("nvme")
            .args(["format", "/dev/nvme0n1", "--ses=2"])
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
