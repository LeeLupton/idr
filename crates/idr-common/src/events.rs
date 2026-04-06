use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Severity levels for the detection pipeline
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Info,
    Warning,
    High,
    Critical,
    /// Impossible state detected — cross-layer anomaly confirmed
    Impossible,
}

/// Source layer that generated the event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    KernelEbpf,
    NetworkZeek,
    NetworkSuricata,
    HardwareNvme,
    HardwareMoca,
    HardwareRtc,
    SentinelCorrelation,
}

/// Canonical event envelope for all telemetry flowing through the IDR pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdrEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub source: EventSource,
    pub severity: Severity,
    pub kind: EventKind,
    /// Free-form metadata for layer-specific details
    pub metadata: serde_json::Value,
}

impl IdrEvent {
    pub fn new(source: EventSource, severity: Severity, kind: EventKind) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source,
            severity,
            kind,
            metadata: serde_json::Value::Null,
        }
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Discriminated union of all event types in the detection pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    // === Kernel Layer (eBPF) ===
    /// IGMP v3 multicast detected on 224.0.0.1
    IgmpTrigger {
        src_ip: String,
        group_addr: String,
    },
    /// QUIC heartbeat (UDP 443) detected within IGMP correlation window
    QuicHeartbeat {
        src_ip: String,
        dst_ip: String,
        dst_port: u16,
        pid: u32,
        exe_path: String,
    },
    /// IGMP → QUIC correlation confirmed within 500ms window
    IgmpQuicCorrelation {
        igmp_event_id: Uuid,
        quic_event_id: Uuid,
        window_ms: u64,
    },
    /// Socket opened by a process — lineage tracking
    SocketLineage {
        pid: u32,
        tgid: u32,
        exe_path: String,
        exe_sha256: String,
        dst_ip: String,
        dst_port: u16,
        is_signed: bool,
    },
    /// Unsigned/non-standard binary beaconing to high-trust IP
    SuspiciousBeacon {
        pid: u32,
        exe_path: String,
        exe_sha256: String,
        dst_ip: String,
        asn_owner: String,
    },
    /// TTL or RTT anomaly indicating physical intercept
    PhysicsAnomaly {
        dst_ip: String,
        expected_ttl_range: (u8, u8),
        observed_ttl: u8,
        rtt_ms: f64,
        reason: String,
    },

    // === Network Layer (Zeek/Suricata) ===
    /// DNS PTR query with octet reversal detected
    OctetReversalDetected {
        forward_ip: String,
        reversed_ip: String,
        forward_asn: String,
        reversed_asn: String,
        ptr_query: String,
    },
    /// NTP time shift exceeds threshold
    NtpTimeShift {
        offset_seconds: f64,
        ntp_server: String,
    },
    /// Expired TLS certificate accepted during NTP time-shift window
    HstsTimeManipulation {
        domain: String,
        cert_expiry: String,
        ntp_shift_seconds: f64,
    },

    // === Hardware & Bus Layer ===
    /// NVMe I/O latency deviation from baseline
    NvmeLatencyAnomaly {
        device: String,
        baseline_us: u64,
        observed_us: u64,
        deviation_pct: f64,
        concurrent_exfil: bool,
    },
    /// Gateway MAC address flapping (MoCA/ARP MitM indicator)
    MacFlapping {
        gateway_ip: String,
        old_mac: String,
        new_mac: String,
        flap_count: u32,
        window_seconds: u64,
    },
    /// Software clock diverged from hardware RTC
    RtcClockDivergence {
        software_time: String,
        rtc_time: String,
        drift_seconds: f64,
    },

    // === Sentinel Engine ===
    /// Cross-layer correlation — "impossible state" detected
    ImpossibleState {
        correlated_event_ids: Vec<Uuid>,
        description: String,
        kill_chain_stage: String,
    },
    /// Panic response triggered
    PanicResponse {
        reason: String,
        actions_taken: Vec<String>,
    },
}

/// Kill chain stages for the DPRK-001 campaign
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KillChainStage {
    /// Stage 1: IGMP multicast trigger for C2 wake
    IgmpTrigger,
    /// Stage 2: QUIC heartbeat beacon to C2
    QuicHeartbeat,
    /// Stage 3: DNS PTR octet reversal for DPI evasion
    PtrOctetReversal,
    /// Stage 4: BGP adjacency sinkhole
    BgpSinkhole,
    /// Stage 5: Data exfiltration via NVMe controller
    NvmeExfiltration,
}
