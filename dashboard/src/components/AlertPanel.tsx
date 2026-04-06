"use client";

import type { IdrEvent, Severity } from "@/lib/types";

interface Props {
  events: IdrEvent[];
}

const SEVERITY_BORDER: Record<Severity, string> = {
  INFO: "#4488aa",
  WARNING: "#ffaa00",
  HIGH: "#ff6600",
  CRITICAL: "#ff2244",
  IMPOSSIBLE: "#ff0000",
};

function alertTitle(event: IdrEvent): string {
  switch (event.kind.type) {
    case "igmp_quic_correlation":
      return "IGMP → QUIC Correlation (C2 Wake Pattern)";
    case "suspicious_beacon":
      return "Unsigned Binary Beaconing to High-Trust IP";
    case "physics_anomaly":
      return "Physical Intercept Alert (Routing Physics Violation)";
    case "octet_reversal_detected":
      return "DPI Evasion: Octet Reversal Detected";
    case "hsts_time_manipulation":
      return "HSTS/Time-Manipulation Attack";
    case "nvme_latency_anomaly":
      return "NVMe Controller Hijack Suspected";
    case "mac_flapping":
      return "MoCA/ARP Man-in-the-Middle";
    case "impossible_state":
      return "IMPOSSIBLE STATE: Cross-Layer Anomaly";
    case "panic_response":
      return "PANIC RESPONSE TRIGGERED";
    default:
      return `Alert: ${event.kind.type}`;
  }
}

export function AlertPanel({ events }: Props) {
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
          No high-severity alerts
        </div>
      ) : (
        events.map((event) => (
          <div
            key={event.id}
            style={{
              padding: "14px",
              borderBottom: "1px solid #111122",
              borderLeft: `3px solid ${SEVERITY_BORDER[event.severity]}`,
              backgroundColor:
                event.severity === "IMPOSSIBLE" ? "#1a000a" : "transparent",
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                marginBottom: "6px",
              }}
            >
              <span
                style={{
                  color: SEVERITY_BORDER[event.severity],
                  fontWeight: "bold",
                  fontSize: "13px",
                }}
              >
                {alertTitle(event)}
              </span>
              <span style={{ color: "#555", fontSize: "11px" }}>
                {new Date(event.timestamp).toLocaleTimeString()}
              </span>
            </div>

            <div style={{ fontSize: "12px", color: "#888", lineHeight: "1.5" }}>
              {event.kind.type === "physics_anomaly" && (
                <>
                  Destination: {event.kind.dst_ip}
                  <br />
                  TTL: {event.kind.observed_ttl} (expected:{" "}
                  {event.kind.expected_ttl_range[0]}-
                  {event.kind.expected_ttl_range[1]})
                  <br />
                  RTT: {event.kind.rtt_ms.toFixed(2)}ms
                  <br />
                  {event.kind.reason}
                </>
              )}

              {event.kind.type === "octet_reversal_detected" && (
                <>
                  Forward: {event.kind.forward_ip} ({event.kind.forward_asn})
                  <br />
                  Reversed: {event.kind.reversed_ip} ({event.kind.reversed_asn})
                  <br />
                  PTR Query: {event.kind.ptr_query}
                </>
              )}

              {event.kind.type === "impossible_state" && (
                <>
                  {event.kind.description}
                  <br />
                  Kill Chain Stage: {event.kind.kill_chain_stage}
                  <br />
                  Correlated Events: {event.kind.correlated_event_ids.length}
                </>
              )}

              {event.kind.type === "panic_response" && (
                <div style={{ color: "#ff0000" }}>
                  {event.kind.reason}
                  <br />
                  Actions:{" "}
                  {event.kind.actions_taken.join(", ") || "Awaiting execution"}
                </div>
              )}

              {event.kind.type === "nvme_latency_anomaly" && (
                <>
                  Device: {event.kind.device}
                  <br />
                  Baseline: {event.kind.baseline_us}us | Observed:{" "}
                  {event.kind.observed_us}us
                  <br />
                  Deviation: {event.kind.deviation_pct.toFixed(1)}%
                  {event.kind.concurrent_exfil && (
                    <span style={{ color: "#ff0000" }}>
                      {" "}
                      — CONCURRENT EXFILTRATION
                    </span>
                  )}
                </>
              )}

              {event.kind.type === "mac_flapping" && (
                <>
                  Gateway: {event.kind.gateway_ip}
                  <br />
                  MAC: {event.kind.old_mac} → {event.kind.new_mac}
                  <br />
                  Flaps: {event.kind.flap_count} in {event.kind.window_seconds}s
                </>
              )}
            </div>
          </div>
        ))
      )}
    </div>
  );
}
