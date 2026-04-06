"use client";

import { useEffect, useReducer, useCallback, useRef } from "react";
import type {
  IdrEvent,
  KillChainNode,
  KillChainStage,
  Severity,
} from "@/lib/types";
import { SentinelWebSocket } from "@/lib/websocket";
import { KillChainVisualization } from "@/components/KillChain";
import { EventFeed } from "@/components/EventFeed";
import { AlertPanel } from "@/components/AlertPanel";
import { SystemStatus } from "@/components/SystemStatus";

interface DashboardState {
  connected: boolean;
  events: IdrEvent[];
  killChain: KillChainNode[];
  alertCount: Record<Severity, number>;
  panicMode: boolean;
}

type Action =
  | { type: "SET_CONNECTED"; connected: boolean }
  | { type: "ADD_EVENT"; event: IdrEvent }
  | { type: "SET_PANIC" };

const INITIAL_KILL_CHAIN: KillChainNode[] = [
  { stage: "IgmpTrigger", label: "IGMP v3 Trigger", active: false },
  { stage: "QuicHeartbeat", label: "QUIC Heartbeat", active: false },
  { stage: "PtrOctetReversal", label: "PTR Octet Reversal", active: false },
  { stage: "BgpSinkhole", label: "BGP Sinkhole", active: false },
  { stage: "NvmeExfiltration", label: "NVMe Exfiltration", active: false },
];

function getKillChainStage(event: IdrEvent): KillChainStage | null {
  switch (event.kind.type) {
    case "igmp_trigger":
      return "IgmpTrigger";
    case "quic_heartbeat":
    case "igmp_quic_correlation":
      return "QuicHeartbeat";
    case "octet_reversal_detected":
      return "PtrOctetReversal";
    case "physics_anomaly":
      return "BgpSinkhole";
    case "nvme_latency_anomaly":
      return "NvmeExfiltration";
    default:
      return null;
  }
}

function reducer(state: DashboardState, action: Action): DashboardState {
  switch (action.type) {
    case "SET_CONNECTED":
      return { ...state, connected: action.connected };

    case "ADD_EVENT": {
      const events = [action.event, ...state.events].slice(0, 500);

      // Update alert counts
      const alertCount = { ...state.alertCount };
      alertCount[action.event.severity] =
        (alertCount[action.event.severity] || 0) + 1;

      // Update kill chain
      const stage = getKillChainStage(action.event);
      let killChain = state.killChain;
      if (stage) {
        killChain = killChain.map((node) =>
          node.stage === stage
            ? {
                ...node,
                active: true,
                event_id: action.event.id,
                timestamp: action.event.timestamp,
              }
            : node
        );
      }

      // Check for panic
      const panicMode =
        state.panicMode || action.event.kind.type === "panic_response";

      return { ...state, events, alertCount, killChain, panicMode };
    }

    case "SET_PANIC":
      return { ...state, panicMode: true };

    default:
      return state;
  }
}

export default function Dashboard() {
  const [state, dispatch] = useReducer(reducer, {
    connected: false,
    events: [],
    killChain: INITIAL_KILL_CHAIN,
    alertCount: {
      INFO: 0,
      WARNING: 0,
      HIGH: 0,
      CRITICAL: 0,
      IMPOSSIBLE: 0,
    },
    panicMode: false,
  });

  const wsRef = useRef<SentinelWebSocket | null>(null);

  useEffect(() => {
    const ws = new SentinelWebSocket();
    wsRef.current = ws;

    ws.onConnection((connected) =>
      dispatch({ type: "SET_CONNECTED", connected })
    );

    ws.onEvent((event) => dispatch({ type: "ADD_EVENT", event }));

    ws.connect();

    return () => ws.disconnect();
  }, []);

  const activeStages = state.killChain.filter((n) => n.active).length;

  return (
    <div style={{ padding: "20px", maxWidth: "1600px", margin: "0 auto" }}>
      {/* Header */}
      <header
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "24px",
          borderBottom: "1px solid #1a1a2e",
          paddingBottom: "16px",
        }}
      >
        <div>
          <h1
            style={{
              margin: 0,
              fontSize: "24px",
              color: state.panicMode ? "#ff0040" : "#00ff88",
            }}
          >
            {state.panicMode
              ? "[ PANIC MODE ACTIVE ]"
              : "IDR SENTINEL ENGINE"}
          </h1>
          <p style={{ margin: "4px 0 0", fontSize: "12px", color: "#666" }}>
            DPRK-001 Campaign Detection — Triple-Check Pipeline
          </p>
        </div>
        <SystemStatus
          connected={state.connected}
          alertCount={state.alertCount}
        />
      </header>

      {/* Kill Chain Visualization */}
      <section style={{ marginBottom: "24px" }}>
        <h2
          style={{
            fontSize: "14px",
            color: "#888",
            marginBottom: "12px",
            textTransform: "uppercase",
            letterSpacing: "2px",
          }}
        >
          Kill Chain Progress — {activeStages}/5 Stages
        </h2>
        <KillChainVisualization nodes={state.killChain} />
      </section>

      {/* Main Grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "20px",
        }}
      >
        {/* Event Feed */}
        <section>
          <h2
            style={{
              fontSize: "14px",
              color: "#888",
              marginBottom: "12px",
              textTransform: "uppercase",
              letterSpacing: "2px",
            }}
          >
            Live Event Feed ({state.events.length})
          </h2>
          <EventFeed events={state.events} />
        </section>

        {/* Alert Panel */}
        <section>
          <h2
            style={{
              fontSize: "14px",
              color: "#888",
              marginBottom: "12px",
              textTransform: "uppercase",
              letterSpacing: "2px",
            }}
          >
            Alerts &amp; Correlations
          </h2>
          <AlertPanel
            events={state.events.filter(
              (e) =>
                e.severity === "CRITICAL" ||
                e.severity === "IMPOSSIBLE" ||
                e.severity === "HIGH"
            )}
          />
        </section>
      </div>
    </div>
  );
}
