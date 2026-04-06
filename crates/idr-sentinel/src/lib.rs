//! IDR Sentinel Engine — the core cross-validation and correlation brain.
//!
//! Ingests events from all three layers (Kernel, Network, Hardware),
//! detects "impossible states" through cross-referencing, and triggers
//! automated panic responses when confirmed threats are identified.

pub mod correlator;
pub mod panic_response;
pub mod websocket;
