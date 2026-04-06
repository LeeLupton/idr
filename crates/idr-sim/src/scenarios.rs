//! Predefined attack scenarios for simulation.

use idr_common::events::{EventKind, EventSource, IdrEvent, Severity};
use std::time::Duration;

type EventSequence = Vec<(Duration, IdrEvent)>;

/// Full DPRK-001 kill chain: IGMP → QUIC → Octet Reversal → Physics → NVMe
pub fn full_kill_chain() -> EventSequence {
    let mut events = Vec::new();
    events.extend(igmp_quic_scenario());
    events.extend(octet_reversal_scenario());
    events.extend(physics_anomaly_scenario());
    events.extend(ntp_manipulation_scenario());
    events.extend(nvme_exfil_scenario());
    events.extend(mac_flapping_scenario());
    events
}

/// Stage 1-2: IGMP multicast trigger followed by QUIC heartbeat within 500ms
pub fn igmp_quic_scenario() -> EventSequence {
    vec![
        (
            Duration::ZERO,
            IdrEvent::new(
                EventSource::KernelEbpf,
                Severity::High,
                EventKind::IgmpTrigger {
                    src_ip: "192.168.1.100".into(),
                    group_addr: "224.0.0.1".into(),
                },
            ),
        ),
        (
            Duration::from_millis(200),
            IdrEvent::new(
                EventSource::KernelEbpf,
                Severity::Warning,
                EventKind::QuicHeartbeat {
                    src_ip: "192.168.1.100".into(),
                    dst_ip: "142.250.80.46".into(),
                    dst_port: 443,
                    pid: 31337,
                    exe_path: "/tmp/.hidden/beacon".into(),
                },
            ),
        ),
        (
            Duration::from_millis(50),
            IdrEvent::new(
                EventSource::KernelEbpf,
                Severity::Info,
                EventKind::SocketLineage {
                    pid: 31337,
                    tgid: 31337,
                    exe_path: "/tmp/.hidden/beacon".into(),
                    exe_sha256: "a1b2c3d4e5f6".into(),
                    dst_ip: "142.250.80.46".into(),
                    dst_port: 443,
                    is_signed: false,
                },
            ),
        ),
    ]
}

/// Stage 3: DNS PTR octet reversal — high-trust forward, residential reversed
pub fn octet_reversal_scenario() -> EventSequence {
    vec![(
        Duration::from_millis(500),
        IdrEvent::new(
            EventSource::NetworkZeek,
            Severity::Info,
            EventKind::OctetReversalDetected {
                forward_ip: "142.250.80.46".into(),
                reversed_ip: "46.80.250.142".into(),
                forward_asn: "AS15169".into(),
                reversed_asn: "AS3320".into(),
                ptr_query: "46.80.250.142.in-addr.arpa".into(),
            },
        ),
    )]
}

/// Stage 4: Routing physics violation — impossible TTL/RTT to Google
pub fn physics_anomaly_scenario() -> EventSequence {
    vec![
        (
            Duration::from_millis(300),
            IdrEvent::new(
                EventSource::KernelEbpf,
                Severity::Critical,
                EventKind::PhysicsAnomaly {
                    dst_ip: "142.250.80.46".into(),
                    expected_ttl_range: (48, 58),
                    observed_ttl: 63,
                    rtt_ms: 2.1,
                    reason: "TTL=63 to 142.250.80.46 suggests single-hop local intercept; RTT=2.10ms is physically impossible for WAN".into(),
                },
            ),
        ),
    ]
}

/// NTP time-shift + expired certificate acceptance
pub fn ntp_manipulation_scenario() -> EventSequence {
    vec![
        (
            Duration::from_millis(400),
            IdrEvent::new(
                EventSource::NetworkZeek,
                Severity::High,
                EventKind::NtpTimeShift {
                    offset_seconds: 7200.0,
                    ntp_server: "evil.ntp.example.com".into(),
                },
            ),
        ),
        (
            Duration::from_millis(100),
            IdrEvent::new(
                EventSource::NetworkZeek,
                Severity::High,
                EventKind::HstsTimeManipulation {
                    domain: "accounts.google.com".into(),
                    cert_expiry: "2024-01-15T00:00:00Z".into(),
                    ntp_shift_seconds: 7200.0,
                },
            ),
        ),
        (
            Duration::from_millis(50),
            IdrEvent::new(
                EventSource::HardwareRtc,
                Severity::High,
                EventKind::RtcClockDivergence {
                    software_time: "2024-01-10T00:00:00Z".into(),
                    rtc_time: "2026-04-06T07:00:00Z".into(),
                    drift_seconds: 7200.0,
                },
            ),
        ),
    ]
}

/// Stage 5: NVMe I/O latency spike during exfiltration
pub fn nvme_exfil_scenario() -> EventSequence {
    vec![(
        Duration::from_millis(300),
        IdrEvent::new(
            EventSource::HardwareNvme,
            Severity::Critical,
            EventKind::NvmeLatencyAnomaly {
                device: "/dev/nvme0".into(),
                baseline_us: 100,
                observed_us: 450,
                deviation_pct: 350.0,
                concurrent_exfil: true,
            },
        ),
    )]
}

/// MoCA/ARP man-in-the-middle — gateway MAC flapping
pub fn mac_flapping_scenario() -> EventSequence {
    vec![(
        Duration::from_millis(200),
        IdrEvent::new(
            EventSource::HardwareMoca,
            Severity::Critical,
            EventKind::MacFlapping {
                gateway_ip: "192.168.1.1".into(),
                old_mac: "aa:bb:cc:dd:ee:ff".into(),
                new_mac: "11:22:33:44:55:66".into(),
                flap_count: 5,
                window_seconds: 30,
            },
        ),
    )]
}
