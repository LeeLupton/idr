"use client";

import type { IdrEvent, Severity } from "@/lib/types";

interface Props {
  events: IdrEvent[];
}

const SEVERITY_COLORS: Record<Severity, string> = {
  INFO: "#4488aa",
  WARNING: "#ffaa00",
  HIGH: "#ff6600",
  CRITICAL: "#ff2244",
  IMPOSSIBLE: "#ff0000",
};

function eventSummary(event: IdrEvent): string {
  switch (event.kind.type) {
    case "igmp_trigger":
      return `IGMP v3: ${event.kind.src_ip} → ${event.kind.group_addr}`;
    case "quic_heartbeat":
      return `QUIC: ${event.kind.src_ip} → ${event.kind.dst_ip}:${event.kind.dst_port} (PID ${event.kind.pid})`;
    case "igmp_quic_correlation":
      return `IGMP→QUIC correlation within ${event.kind.window_ms}ms`;
    case "socket_lineage":
      return `Socket: PID ${event.kind.pid} → ${event.kind.dst_ip}:${event.kind.dst_port} [${event.kind.exe_path}]`;
    case "suspicious_beacon":
      return `Beacon: ${event.kind.exe_path} → ${event.kind.dst_ip} (${event.kind.asn_owner})`;
    case "physics_anomaly":
      return `Physics: ${event.kind.dst_ip} TTL=${event.kind.observed_ttl} RTT=${event.kind.rtt_ms.toFixed(2)}ms`;
    case "octet_reversal_detected":
      return `Octet Reversal: ${event.kind.forward_ip} ↔ ${event.kind.reversed_ip} [${event.kind.forward_asn}→${event.kind.reversed_asn}]`;
    case "ntp_time_shift":
      return `NTP Shift: ${event.kind.offset_seconds.toFixed(1)}s from ${event.kind.ntp_server}`;
    case "hsts_time_manipulation":
      return `HSTS Attack: ${event.kind.domain} cert expired ${event.kind.cert_expiry}`;
    case "nvme_latency_anomaly":
      return `NVMe: ${event.kind.device} ${event.kind.deviation_pct.toFixed(1)}% deviation${event.kind.concurrent_exfil ? " [EXFIL]" : ""}`;
    case "mac_flapping":
      return `MAC Flap: ${event.kind.gateway_ip} ${event.kind.old_mac}→${event.kind.new_mac} (${event.kind.flap_count}x)`;
    case "rtc_clock_divergence":
      return `RTC Drift: ${event.kind.drift_seconds.toFixed(1)}s divergence`;
    case "impossible_state":
      return `IMPOSSIBLE: ${event.kind.description}`;
    case "panic_response":
      return `PANIC: ${event.kind.reason}`;
    default:
      return "Unknown event";
  }
}

export function EventFeed({ events }: Props) {
  return (
    <div
      style={{
        backgroundColor: "#0d0d1a",
        borderRadius: "8px",
        border: "1px solid #1a1a2e",
        maxHeight: "500px",
        overflowY: "auto",
      }}
    >
      {events.length === 0 ? (
        <div
          style={{
            padding: "40px",
            textAlign: "center",
            color: "#444",
            fontSize: "13px",
          }}
        >
          Awaiting events from Sentinel Engine...
          <br />
          <span style={{ fontSize: "11px" }}>
            Connect to ws://127.0.0.1:9700/ws/events
          </span>
        </div>
      ) : (
        events.map((event) => (
          <div
            key={event.id}
            style={{
              padding: "10px 14px",
              borderBottom: "1px solid #111122",
              display: "flex",
              alignItems: "flex-start",
              gap: "10px",
              fontSize: "12px",
              backgroundColor:
                event.severity === "IMPOSSIBLE"
                  ? "#1a0008"
                  : event.severity === "CRITICAL"
                    ? "#180005"
                    : "transparent",
            }}
          >
            {/* Severity badge */}
            <span
              style={{
                padding: "2px 6px",
                borderRadius: "3px",
                backgroundColor: `${SEVERITY_COLORS[event.severity]}22`,
                color: SEVERITY_COLORS[event.severity],
                fontSize: "10px",
                fontWeight: "bold",
                minWidth: "70px",
                textAlign: "center",
                flexShrink: 0,
              }}
            >
              {event.severity}
            </span>

            {/* Timestamp */}
            <span style={{ color: "#555", flexShrink: 0, fontSize: "11px" }}>
              {new Date(event.timestamp).toLocaleTimeString()}
            </span>

            {/* Source */}
            <span
              style={{
                color: "#666",
                flexShrink: 0,
                fontSize: "10px",
                minWidth: "80px",
              }}
            >
              [{event.source.replace("_", "/")}]
            </span>

            {/* Event summary */}
            <span style={{ color: "#ccc", wordBreak: "break-all" }}>
              {eventSummary(event)}
            </span>
          </div>
        ))
      )}
    </div>
  );
}
