//! IDR Event Simulator — generates synthetic kill chain events for testing
//! the full detection pipeline without requiring root, eBPF, or real hardware.
//!
//! Usage:
//!   idr-sim                    # Run full kill chain simulation
//!   idr-sim --scenario igmp    # Run specific scenario
//!   idr-sim --output file.json # Write events to file instead of stdout

use std::io::Write;
use std::time::Duration;

mod scenarios;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("idr_sim=info")
        .init();

    let scenario = std::env::args().nth(1).unwrap_or_default();

    let events = match scenario.as_str() {
        "--scenario" => {
            let name = std::env::args().nth(2).unwrap_or_default();
            match name.as_str() {
                "igmp" => scenarios::igmp_quic_scenario(),
                "octet" => scenarios::octet_reversal_scenario(),
                "physics" => scenarios::physics_anomaly_scenario(),
                "ntp" => scenarios::ntp_manipulation_scenario(),
                "nvme" => scenarios::nvme_exfil_scenario(),
                "mac" => scenarios::mac_flapping_scenario(),
                _ => {
                    eprintln!("Unknown scenario: {name}");
                    eprintln!("Available: igmp, octet, physics, ntp, nvme, mac");
                    std::process::exit(1);
                }
            }
        }
        _ => scenarios::full_kill_chain(),
    };

    let output_file = std::env::args()
        .position(|a| a == "--output")
        .and_then(|i| std::env::args().nth(i + 1));

    let mut writer: Box<dyn Write> = match output_file {
        Some(path) => Box::new(std::fs::File::create(&path).expect("Failed to create output file")),
        None => Box::new(std::io::stdout()),
    };

    for (delay, event) in &events {
        if *delay > Duration::ZERO {
            tokio::time::sleep(*delay).await;
        }
        let json = serde_json::to_string(event).unwrap();
        writeln!(writer, "{json}").unwrap();
    }

    eprintln!("Simulated {} events", events.len());
}
