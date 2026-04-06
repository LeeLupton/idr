import type { IdrEvent } from "./types";

const WS_URL =
  process.env.NEXT_PUBLIC_WS_URL || "ws://127.0.0.1:9700/ws/events";

export type EventHandler = (event: IdrEvent) => void;
export type ConnectionHandler = (connected: boolean) => void;

/**
 * WebSocket client for real-time event streaming from the Sentinel Engine.
 * Handles automatic reconnection with exponential backoff.
 */
export class SentinelWebSocket {
  private ws: WebSocket | null = null;
  private eventHandlers: EventHandler[] = [];
  private connectionHandlers: ConnectionHandler[] = [];
  private reconnectDelay = 1000;
  private maxReconnectDelay = 30000;
  private shouldReconnect = true;

  connect(): void {
    try {
      this.ws = new WebSocket(WS_URL);

      this.ws.onopen = () => {
        this.reconnectDelay = 1000;
        this.connectionHandlers.forEach((h) => h(true));
      };

      this.ws.onmessage = (msg) => {
        try {
          const event: IdrEvent = JSON.parse(msg.data);
          this.eventHandlers.forEach((h) => h(event));
        } catch {
          console.error("Failed to parse Sentinel event:", msg.data);
        }
      };

      this.ws.onclose = () => {
        this.connectionHandlers.forEach((h) => h(false));
        if (this.shouldReconnect) {
          setTimeout(() => this.connect(), this.reconnectDelay);
          this.reconnectDelay = Math.min(
            this.reconnectDelay * 2,
            this.maxReconnectDelay
          );
        }
      };

      this.ws.onerror = () => {
        this.ws?.close();
      };
    } catch {
      if (this.shouldReconnect) {
        setTimeout(() => this.connect(), this.reconnectDelay);
      }
    }
  }

  disconnect(): void {
    this.shouldReconnect = false;
    this.ws?.close();
  }

  onEvent(handler: EventHandler): () => void {
    this.eventHandlers.push(handler);
    return () => {
      this.eventHandlers = this.eventHandlers.filter((h) => h !== handler);
    };
  }

  onConnection(handler: ConnectionHandler): () => void {
    this.connectionHandlers.push(handler);
    return () => {
      this.connectionHandlers = this.connectionHandlers.filter(
        (h) => h !== handler
      );
    };
  }
}
