//! WebSocket server for real-time event streaming to the dashboard.
//!
//! Provides a WebSocket endpoint at /ws/events that streams all IdrEvents
//! as JSON to connected dashboard clients.

use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::State,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use idr_common::events::IdrEvent;
use std::sync::Arc;
use tokio::sync::broadcast;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{error, info, warn};
use url::Url;

pub struct DashboardServer {
    addr: String,
    event_tx: broadcast::Sender<IdrEvent>,
}

impl DashboardServer {
    pub fn new(addr: &str, event_tx: broadcast::Sender<IdrEvent>) -> Self {
        Self {
            addr: addr.to_string(),
            event_tx,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let state = Arc::new(AppState {
            event_tx: self.event_tx,
        });

        // Restrict CORS to localhost origins only — parse host to prevent prefix bypass
        // (e.g. "http://localhost.evil.com" must NOT pass)
        let cors = CorsLayer::new()
            .allow_origin(AllowOrigin::predicate(|origin, _| {
                let origin_str = match origin.to_str() {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                match Url::parse(origin_str) {
                    Ok(url) => match url.host_str() {
                        Some(host) => {
                            host == "127.0.0.1" || host == "localhost" || host == "[::1]" || host == "::1"
                        }
                        None => false,
                    },
                    Err(_) => false,
                }
            }))
            .allow_methods([http::Method::GET]);

        let app = Router::new()
            .route("/ws/events", get(ws_handler))
            .route("/api/health", get(health_handler))
            .route("/api/alerts", get(alerts_handler))
            .layer(cors)
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(&self.addr).await?;
        info!(addr = %self.addr, "Dashboard WebSocket server listening");

        axum::serve(listener, app).await?;
        Ok(())
    }
}

struct AppState {
    event_tx: broadcast::Sender<IdrEvent>,
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let rx = state.event_tx.subscribe();
    ws.on_upgrade(move |socket| handle_ws(socket, rx))
}

async fn handle_ws(mut socket: WebSocket, mut rx: broadcast::Receiver<IdrEvent>) {
    info!("Dashboard client connected via WebSocket");
    let mut serialize_errors: u32 = 0;

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(event) => {
                        match serde_json::to_string(&event) {
                            Ok(json) => {
                                serialize_errors = 0;
                                if socket.send(Message::Text(json.into())).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                serialize_errors += 1;
                                error!("Failed to serialize event: {}", e);
                                if serialize_errors > 10 {
                                    error!("Too many serialization errors, disconnecting client");
                                    break;
                                }
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "Dashboard client lagged, skipped {} events", n);
                        // Continue — client will catch up from current position
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
            Some(Ok(Message::Close(_))) = socket.recv() => {
                break;
            }
            else => break,
        }
    }

    info!("Dashboard client disconnected");
}

async fn health_handler() -> &'static str {
    "IDR Sentinel Engine — operational"
}

async fn alerts_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "message": "Alert query endpoint — connect via WebSocket for real-time events"
    }))
}
