"use client";

import type { KillChainNode } from "@/lib/types";

interface Props {
  nodes: KillChainNode[];
}

const STAGE_COLORS: Record<string, string> = {
  IgmpTrigger: "#ffaa00",
  QuicHeartbeat: "#ff6600",
  PtrOctetReversal: "#ff3300",
  BgpSinkhole: "#ff0044",
  NvmeExfiltration: "#ff0000",
};

export function KillChainVisualization({ nodes }: Props) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "8px",
        padding: "16px",
        backgroundColor: "#0d0d1a",
        borderRadius: "8px",
        border: "1px solid #1a1a2e",
        overflow: "auto",
      }}
    >
      {nodes.map((node, i) => (
        <div key={node.stage} style={{ display: "flex", alignItems: "center" }}>
          {/* Stage Node */}
          <div
            style={{
              padding: "12px 20px",
              borderRadius: "6px",
              border: `2px solid ${
                node.active ? STAGE_COLORS[node.stage] || "#ff0000" : "#2a2a3e"
              }`,
              backgroundColor: node.active
                ? `${STAGE_COLORS[node.stage]}15`
                : "#0a0a14",
              minWidth: "150px",
              textAlign: "center",
              transition: "all 0.3s ease",
              boxShadow: node.active
                ? `0 0 20px ${STAGE_COLORS[node.stage]}33`
                : "none",
            }}
          >
            <div
              style={{
                fontSize: "10px",
                color: node.active
                  ? STAGE_COLORS[node.stage] || "#ff0000"
                  : "#444",
                marginBottom: "4px",
                fontWeight: "bold",
                letterSpacing: "1px",
              }}
            >
              STAGE {i + 1}
            </div>
            <div
              style={{
                fontSize: "13px",
                color: node.active ? "#fff" : "#555",
                fontWeight: node.active ? "bold" : "normal",
              }}
            >
              {node.label}
            </div>
            {node.active && node.timestamp && (
              <div
                style={{
                  fontSize: "10px",
                  color: "#666",
                  marginTop: "4px",
                }}
              >
                {new Date(node.timestamp).toLocaleTimeString()}
              </div>
            )}
            {/* Status indicator */}
            <div
              style={{
                width: "8px",
                height: "8px",
                borderRadius: "50%",
                backgroundColor: node.active
                  ? STAGE_COLORS[node.stage] || "#ff0000"
                  : "#333",
                margin: "8px auto 0",
                boxShadow: node.active
                  ? `0 0 8px ${STAGE_COLORS[node.stage]}`
                  : "none",
              }}
            />
          </div>

          {/* Arrow connector */}
          {i < nodes.length - 1 && (
            <div
              style={{
                width: "40px",
                height: "2px",
                backgroundColor:
                  node.active && nodes[i + 1]?.active ? "#ff4444" : "#1a1a2e",
                position: "relative",
              }}
            >
              <div
                style={{
                  position: "absolute",
                  right: "-4px",
                  top: "-4px",
                  width: 0,
                  height: 0,
                  borderTop: "5px solid transparent",
                  borderBottom: "5px solid transparent",
                  borderLeft: `8px solid ${
                    node.active && nodes[i + 1]?.active ? "#ff4444" : "#1a1a2e"
                  }`,
                }}
              />
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
