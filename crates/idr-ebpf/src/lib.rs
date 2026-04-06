//! IDR eBPF — Kernel-layer telemetry via eBPF (Aya framework)
//!
//! This crate contains the userspace loader and event processing for:
//! - IGMP v3 multicast correlation (XDP)
//! - Socket-to-process lineage tracking (kprobe)
//! - TTL/RTT routing physics anomaly detection (tracepoint)

pub mod loader;
pub mod igmp;
pub mod lineage;
pub mod physics;
pub mod ring_events;
