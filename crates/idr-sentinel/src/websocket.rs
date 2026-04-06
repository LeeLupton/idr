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
use tracing::{error, info};

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

        // Restrict CORS to localhost origins only
        let cors = CorsLayer::new()
            .allow_origin(AllowOrigin::predicate(|origin, _| {
                origin.as_bytes().starts_with(b"http://127.0.0.1")
                    || origin.as_bytes().starts_with(b"http://localhost")
                    || origin.as_bytes().starts_with(b"http://[::1]")
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

    loop {
        tokio::select! {
            Ok(event) = rx.recv() => {
                match serde_json::to_string(&event) {
                    Ok(json) => {
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Failed to serialize event: {}", e);
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
