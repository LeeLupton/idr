"use client";

import type { Severity } from "@/lib/types";

interface Props {
  connected: boolean;
  alertCount: Record<Severity, number>;
}

export function SystemStatus({ connected, alertCount }: Props) {
  const totalCritical =
    (alertCount.CRITICAL || 0) + (alertCount.IMPOSSIBLE || 0);

  return (
    <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
      {/* Alert counters */}
      <div style={{ display: "flex", gap: "8px", fontSize: "11px" }}>
        {totalCritical > 0 && (
          <span
            style={{
              padding: "3px 8px",
              borderRadius: "4px",
              backgroundColor: "#ff004422",
              color: "#ff0044",
              fontWeight: "bold",
            }}
          >
            CRIT: {totalCritical}
          </span>
        )}
        {alertCount.HIGH > 0 && (
          <span
            style={{
              padding: "3px 8px",
              borderRadius: "4px",
              backgroundColor: "#ff660022",
              color: "#ff6600",
            }}
          >
            HIGH: {alertCount.HIGH}
          </span>
        )}
        {alertCount.WARNING > 0 && (
          <span
            style={{
              padding: "3px 8px",
              borderRadius: "4px",
              backgroundColor: "#ffaa0022",
              color: "#ffaa00",
            }}
          >
            WARN: {alertCount.WARNING}
          </span>
        )}
      </div>

      {/* Connection status */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "6px",
          fontSize: "12px",
        }}
      >
        <div
          style={{
            width: "8px",
            height: "8px",
            borderRadius: "50%",
            backgroundColor: connected ? "#00ff88" : "#ff4444",
            boxShadow: connected ? "0 0 8px #00ff88" : "0 0 8px #ff4444",
          }}
        />
        <span style={{ color: connected ? "#00ff88" : "#ff4444" }}>
          {connected ? "SENTINEL LINK" : "DISCONNECTED"}
        </span>
      </div>
    </div>
  );
}
