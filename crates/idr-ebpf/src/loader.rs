//! eBPF program loader using Aya.
//!
//! Loads XDP, kprobe, and tracepoint programs from compiled .o files
//! and sets up ring buffer polling for the Sentinel Engine.

use anyhow::Result;
use aya::Ebpf;
use idr_common::config::KernelConfig;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::ring_events::*;

/// Handle to all loaded eBPF programs
pub struct EbpfLoader {
    _bpf: Ebpf,
    config: KernelConfig,
}

impl EbpfLoader {
    /// Load all eBPF programs and attach to the specified interface.
    ///
    /// In production, pass the path to the compiled eBPF .o file.
    /// For development without a real kernel, this returns a stub.
    ///
    /// Production loading (requires root + BPF capabilities):
    /// ```ignore
    /// let mut bpf = Ebpf::load_file(ebpf_obj_path)?;
    /// let xdp: &mut Xdp = bpf.program_mut("idr_xdp").unwrap().try_into()?;
    /// xdp.load()?;
    /// xdp.attach(&config.xdp_interface, XdpFlags::default())?;
    /// // ... kprobes, tracepoints similarly
    /// ```
    pub async fn load(
        config: &KernelConfig,
        _ebpf_obj_path: &str,
    ) -> Result<Self> {
        info!(
            interface = %config.xdp_interface,
            "Loading eBPF programs (stub mode — real loader requires root + BPF)"
        );

        let bpf = Ebpf::load(&[])?;

        Ok(Self {
            _bpf: bpf,
            config: config.clone(),
        })
    }

    /// Poll the eBPF ring buffer and dispatch events to the Sentinel Engine.
    ///
    /// This is the hot path — runs in a dedicated Tokio task.
    ///
    /// Production polling reads from the shared ring buffer map:
    /// ```ignore
    /// let ring_buf = RingBuf::try_from(self.bpf.map_mut("EVENTS").unwrap())?;
    /// loop {
    ///     if let Some(data) = ring_buf.next() {
    ///         let event_type = u32::from_ne_bytes(data[..4].try_into()?);
    ///         match event_type {
    ///             1 => self.handle_igmp(&data[4..], &tx).await?,
    ///             2 => self.handle_quic(&data[4..], &tx).await?,
    ///             3 => self.handle_socket(&data[4..], &tx).await?,
    ///             4 => self.handle_physics(&data[4..], &tx).await?,
    ///             _ => warn!(event_type, "Unknown ring buffer event"),
    ///         }
    ///     }
    ///     tokio::task::yield_now().await;
    /// }
    /// ```
    pub async fn poll_events(
        &mut self,
        _tx: mpsc::Sender<idr_common::events::IdrEvent>,
    ) -> Result<()> {
        info!("Starting eBPF ring buffer polling (stub mode)");

        // Stub: wait forever (no real ring buffer in dev mode)
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }

    /// Parse and dispatch an IGMP event from the eBPF ring buffer.
    ///
    /// # Safety
    /// Caller must ensure `payload` is at least `size_of::<RawIgmpEvent>()` bytes
    /// and originates from the kernel ring buffer (trusted source).
    #[allow(dead_code)]
    async fn handle_igmp(
        &self,
        payload: &[u8],
        tx: &mpsc::Sender<idr_common::events::IdrEvent>,
    ) -> Result<()> {
        if payload.len() < std::mem::size_of::<RawIgmpEvent>() {
            return Ok(());
        }
        // SAFETY: bounds-checked above, data sourced from kernel ring buffer
        let raw: RawIgmpEvent = unsafe { std::ptr::read_unaligned(payload.as_ptr().cast()) };

        let event = idr_common::events::IdrEvent::new(
            idr_common::events::EventSource::KernelEbpf,
            idr_common::events::Severity::High,
            idr_common::events::EventKind::IgmpTrigger {
                src_ip: ip_to_string(raw.src_ip),
                group_addr: ip_to_string(raw.group_addr),
            },
        );

        if tx.send(event).await.is_err() {
            warn!("Failed to send IGMP event — channel closed");
        }
        Ok(())
    }

    #[allow(dead_code)]
    async fn handle_quic(
        &self,
        payload: &[u8],
        tx: &mpsc::Sender<idr_common::events::IdrEvent>,
    ) -> Result<()> {
        if payload.len() < std::mem::size_of::<RawQuicEvent>() {
            return Ok(());
        }
        // SAFETY: bounds-checked above, data sourced from kernel ring buffer
        let raw: RawQuicEvent = unsafe { std::ptr::read_unaligned(payload.as_ptr().cast()) };

        let event = idr_common::events::IdrEvent::new(
            idr_common::events::EventSource::KernelEbpf,
            idr_common::events::Severity::Warning,
            idr_common::events::EventKind::QuicHeartbeat {
                src_ip: ip_to_string(raw.src_ip),
                dst_ip: ip_to_string(raw.dst_ip),
                dst_port: raw.dst_port,
                pid: raw.pid,
                exe_path: String::new(),
            },
        );

        if tx.send(event).await.is_err() {
            warn!("Failed to send QUIC event — channel closed");
        }
        Ok(())
    }

    #[allow(dead_code)]
    async fn handle_socket(
        &self,
        payload: &[u8],
        tx: &mpsc::Sender<idr_common::events::IdrEvent>,
    ) -> Result<()> {
        if payload.len() < std::mem::size_of::<RawSocketEvent>() {
            return Ok(());
        }
        // SAFETY: bounds-checked above, data sourced from kernel ring buffer
        let raw: RawSocketEvent = unsafe { std::ptr::read_unaligned(payload.as_ptr().cast()) };

        let exe_path = String::from_utf8_lossy(
            &raw.exe_path[..raw.exe_path.iter().position(|&b| b == 0).unwrap_or(64)],
        )
        .to_string();

        let event = idr_common::events::IdrEvent::new(
            idr_common::events::EventSource::KernelEbpf,
            idr_common::events::Severity::Info,
            idr_common::events::EventKind::SocketLineage {
                pid: raw.pid,
                tgid: raw.tgid,
                exe_path,
                exe_sha256: String::new(),
                dst_ip: ip_to_string(raw.dst_ip),
                dst_port: raw.dst_port,
                is_signed: false,
            },
        );

        if tx.send(event).await.is_err() {
            warn!("Failed to send socket lineage event — channel closed");
        }
        Ok(())
    }

    #[allow(dead_code)]
    async fn handle_physics(
        &self,
        payload: &[u8],
        tx: &mpsc::Sender<idr_common::events::IdrEvent>,
    ) -> Result<()> {
        if payload.len() < std::mem::size_of::<RawPhysicsEvent>() {
            return Ok(());
        }
        // SAFETY: bounds-checked above, data sourced from kernel ring buffer
        let raw: RawPhysicsEvent = unsafe { std::ptr::read_unaligned(payload.as_ptr().cast()) };

        let rtt_ms = raw.rtt_us as f64 / 1000.0;
        let dst_ip_str = ip_to_string(raw.dst_ip);

        if raw.ttl == self.config.suspicious_ttl || rtt_ms < self.config.suspicious_rtt_ms {
            let reason = if raw.ttl == self.config.suspicious_ttl {
                format!(
                    "TTL={} to {} suggests single-hop local intercept",
                    raw.ttl, dst_ip_str
                )
            } else {
                format!(
                    "RTT={:.2}ms to {} is physically impossible for WAN",
                    rtt_ms, dst_ip_str
                )
            };

            let event = idr_common::events::IdrEvent::new(
                idr_common::events::EventSource::KernelEbpf,
                idr_common::events::Severity::Critical,
                idr_common::events::EventKind::PhysicsAnomaly {
                    dst_ip: dst_ip_str,
                    expected_ttl_range: (48, 58),
                    observed_ttl: raw.ttl,
                    rtt_ms,
                    reason,
                },
            );

            if tx.send(event).await.is_err() {
                warn!("Failed to send physics anomaly event — channel closed");
            }
        }

        Ok(())
    }
}
