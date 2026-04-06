//! IDR Sentinel Engine — main entry point.
//!
//! Orchestrates all detection layers:
//! 1. Loads eBPF programs (Kernel Layer)
//! 2. Connects to Zeek socket (Network Layer)
//! 3. Starts hardware monitors (Hardware Layer)
//! 4. Runs the cross-validation correlator
//! 5. Serves WebSocket feed for the dashboard

use anyhow::Result;
use idr_common::config::IdrConfig;
use idr_common::events::IdrEvent;
use idr_common::reputation::ReputationDb;
use idr_hardware::arp::ArpMonitor;
use idr_hardware::nvme::NvmeWatchdog;
use idr_hardware::rtc::RtcWatchdog;
use idr_network::zeek::ZeekIngestor;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};

mod correlator;
mod panic_response;
mod websocket;

use correlator::SentinelCorrelator;
use websocket::DashboardServer;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "idr_sentinel=info,idr_ebpf=info,idr_network=info,idr_hardware=info".into()),
        )
        .json()
        .init();

    info!("IDR Sentinel Engine starting — DPRK-001 campaign detection active");

    let config = load_config()?;
    let reputation = Arc::new(ReputationDb::new());

    let (event_tx, event_rx) = mpsc::channel::<IdrEvent>(4096);
    let (dashboard_tx, _) = broadcast::channel::<IdrEvent>(1024);
    let dashboard_tx_clone = dashboard_tx.clone();

    apply_sysctl_hardening();

    // === Layer 1: Kernel (eBPF) ===
    let kernel_tx = event_tx.clone();
    let kernel_config = config.kernel.clone();
    tokio::spawn(async move {
        info!("Starting Kernel Layer (eBPF)...");
        match idr_ebpf::loader::EbpfLoader::load(&kernel_config, "").await {
            Ok(mut loader) => {
                if let Err(e) = loader.poll_events(kernel_tx).await {
                    error!("eBPF event polling failed: {}", e);
                }
            }
            Err(e) => {
                warn!("eBPF loader failed (expected in dev mode): {}", e);
            }
        }
    });

    // === Layer 2: Network (Zeek + Suricata) ===
    let network_tx = event_tx.clone();
    let network_config = config.network.clone();
    tokio::spawn(async move {
        info!("Starting Network Layer (Zeek ingestor)...");
        let mut ingestor = ZeekIngestor::new(&network_config.zeek_socket_path);
        if let Err(e) = ingestor.run(network_tx).await {
            warn!("Zeek ingestor failed (expected if Zeek not running): {}", e);
        }
    });

    // === Layer 3: Hardware ===
    let hw_tx = event_tx.clone();
    let hw_config = config.hardware.clone();
    tokio::spawn(async move {
        info!("Starting Hardware Layer...");

        let nvme_tx = hw_tx.clone();
        let arp_tx = hw_tx.clone();
        let rtc_tx = hw_tx;

        let nvme_config = hw_config.clone();
        let arp_config = hw_config.clone();

        tokio::spawn(async move {
            let mut watchdog = NvmeWatchdog::new(&nvme_config);
            if let Err(e) = watchdog.run(nvme_tx).await {
                warn!("NVMe watchdog error: {}", e);
            }
        });

        tokio::spawn(async move {
            let mut monitor = ArpMonitor::new(&arp_config);
            if let Err(e) = monitor.run(arp_tx).await {
                warn!("ARP monitor error: {}", e);
            }
        });

        tokio::spawn(async move {
            let mut rtc = RtcWatchdog::new();
            if let Err(e) = rtc.run(rtc_tx).await {
                warn!("RTC watchdog error: {}", e);
            }
        });
    });

    // === Dashboard WebSocket Server ===
    let ws_addr = config.sentinel.ws_listen_addr.clone();
    tokio::spawn(async move {
        let server = DashboardServer::new(&ws_addr, dashboard_tx_clone);
        if let Err(e) = server.run().await {
            error!("Dashboard WebSocket server failed: {}", e);
        }
    });

    // === Sentinel Correlator (main event loop) ===
    let correlator = SentinelCorrelator::new(config, reputation);
    correlator.run(event_rx, dashboard_tx).await?;

    Ok(())
}

fn load_config() -> Result<IdrConfig> {
    let config_path = std::env::var("IDR_CONFIG")
        .unwrap_or_else(|_| "/etc/idr/config.json".to_string());

    match std::fs::read_to_string(&config_path) {
        Ok(contents) => {
            let config: IdrConfig = serde_json::from_str(&contents)?;
            info!(path = %config_path, "Loaded configuration");
            Ok(config)
        }
        Err(_) => {
            info!("Using default configuration (no config file found)");
            Ok(IdrConfig::default())
        }
    }
}

fn apply_sysctl_hardening() {
    let sysctls = [
        ("net.core.bpf_jit_harden", "2"),
        ("kernel.unprivileged_bpf_disabled", "1"),
    ];

    for (key, value) in &sysctls {
        let path = format!("/proc/sys/{}", key.replace('.', "/"));
        match std::fs::write(&path, value) {
            Ok(()) => info!(key = key, value = value, "sysctl hardened"),
            Err(e) => warn!(key = key, error = %e, "Failed to set sysctl (requires root)"),
        }
    }
}
