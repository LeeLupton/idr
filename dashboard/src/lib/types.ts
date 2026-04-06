/** Severity levels matching the Rust IdrEvent types */
export type Severity = "INFO" | "WARNING" | "HIGH" | "CRITICAL" | "IMPOSSIBLE";

/** Source layer that generated the event */
export type EventSource =
  | "kernel_ebpf"
  | "network_zeek"
  | "network_suricata"
  | "hardware_nvme"
  | "hardware_moca"
  | "hardware_rtc"
  | "sentinel_correlation";

/** Kill chain stages for the DPRK-001 campaign */
export type KillChainStage =
  | "IgmpTrigger"
  | "QuicHeartbeat"
  | "PtrOctetReversal"
  | "BgpSinkhole"
  | "NvmeExfiltration";

/** Canonical event from the Sentinel Engine WebSocket */
export interface IdrEvent {
  id: string;
  timestamp: string;
  source: EventSource;
  severity: Severity;
  kind: EventKind;
  metadata: unknown;
}

/** Discriminated union of all event kinds */
export type EventKind =
  | { type: "igmp_trigger"; src_ip: string; group_addr: string }
  | {
      type: "quic_heartbeat";
      src_ip: string;
      dst_ip: string;
      dst_port: number;
      pid: number;
      exe_path: string;
    }
  | {
      type: "igmp_quic_correlation";
      igmp_event_id: string;
      quic_event_id: string;
      window_ms: number;
    }
  | {
      type: "socket_lineage";
      pid: number;
      tgid: number;
      exe_path: string;
      exe_sha256: string;
      dst_ip: string;
      dst_port: number;
      is_signed: boolean;
    }
  | {
      type: "suspicious_beacon";
      pid: number;
      exe_path: string;
      exe_sha256: string;
      dst_ip: string;
      asn_owner: string;
    }
  | {
      type: "physics_anomaly";
      dst_ip: string;
      expected_ttl_range: [number, number];
      observed_ttl: number;
      rtt_ms: number;
      reason: string;
    }
  | {
      type: "octet_reversal_detected";
      forward_ip: string;
      reversed_ip: string;
      forward_asn: string;
      reversed_asn: string;
      ptr_query: string;
    }
  | { type: "ntp_time_shift"; offset_seconds: number; ntp_server: string }
  | {
      type: "hsts_time_manipulation";
      domain: string;
      cert_expiry: string;
      ntp_shift_seconds: number;
    }
  | {
      type: "nvme_latency_anomaly";
      device: string;
      baseline_us: number;
      observed_us: number;
      deviation_pct: number;
      concurrent_exfil: boolean;
    }
  | {
      type: "mac_flapping";
      gateway_ip: string;
      old_mac: string;
      new_mac: string;
      flap_count: number;
      window_seconds: number;
    }
  | {
      type: "rtc_clock_divergence";
      software_time: string;
      rtc_time: string;
      drift_seconds: number;
    }
  | {
      type: "impossible_state";
      correlated_event_ids: string[];
      description: string;
      kill_chain_stage: string;
    }
  | { type: "panic_response"; reason: string; actions_taken: string[] };

/** Alert from the Sentinel Engine */
export interface Alert {
  id: string;
  timestamp: string;
  severity: Severity;
  title: string;
  description: string;
  source_events: string[];
  state: "active" | "acknowledged" | "resolved" | "panic_triggered";
  response?: PanicAction;
}

export type PanicAction =
  | { type: "network_kill"; interface: string }
  | { type: "nvme_crypto_erase"; device: string }
  | { type: "full_panic"; interface: string; nvme_device: string };

/** Kill chain visualization node */
export interface KillChainNode {
  stage: KillChainStage;
  label: string;
  active: boolean;
  event_id?: string;
  timestamp?: string;
}
