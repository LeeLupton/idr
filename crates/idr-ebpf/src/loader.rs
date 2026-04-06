//! eBPF program loader using Aya.
//!
//! Loads XDP, kprobe, and tracepoint programs from compiled .o files
//! and sets up ring buffer polling for the Sentinel Engine.

use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::{KProbe, TracePoint, Xdp, XdpFlags};
use aya::Ebpf;
use idr_common::config::KernelConfig;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

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
    pub async fn load(
        config: &KernelConfig,
        _ebpf_obj_path: &str,
    ) -> Result<Self> {
        info!(
            interface = %config.xdp_interface,
            "Loading eBPF programs (stub mode — real loader requires root + BPF)"
        );

        // NOTE: In production with a real eBPF object:
        //
        // let mut bpf = Ebpf::load_file(ebpf_obj_path)
        //     .context("Failed to load eBPF object")?;
        //
        // // Attach XDP for IGMP + QUIC detection
        // let xdp: &mut Xdp = bpf.program_mut("idr_xdp")
        //     .unwrap().try_into()?;
        // xdp.load()?;
        // xdp.attach(&config.xdp_interface, XdpFlags::default())?;
        //
        // // Attach kprobes for socket lineage
        // let tcp_probe: &mut KProbe = bpf.program_mut("idr_tcp_connect")
        //     .unwrap().try_into()?;
        // tcp_probe.load()?;
        // tcp_probe.attach("tcp_v4_connect", 0)?;
        //
        // let udp_probe: &mut KProbe = bpf.program_mut("idr_udp_sendmsg")
        //     .unwrap().try_into()?;
        // udp_probe.load()?;
        // udp_probe.attach("udp_sendmsg", 0)?;
        //
        // // Attach tracepoint for physics monitoring
        // let tp: &mut TracePoint = bpf.program_mut("idr_tcp_probe")
        //     .unwrap().try_into()?;
        // tp.load()?;
        // tp.attach("tcp", "tcp_probe")?;
        //
        // info!("All eBPF programs loaded and attached");

        // Stub: create empty Ebpf instance for compilation
        // Real deployment replaces this with the load above
        let bpf = Ebpf::load(&[])?;

        Ok(Self {
            _bpf: bpf,
            config: config.clone(),
        })
    }

    /// Poll the eBPF ring buffer and dispatch events to the Sentinel Engine.
    ///
    /// This is the hot path — runs in a dedicated Tokio task.
    pub async fn poll_events(
        &mut self,
        tx: mpsc::Sender<idr_common::events::IdrEvent>,
    ) -> Result<()> {
        info!("Starting eBPF ring buffer polling (stub mode)");

        // NOTE: Production ring buffer polling:
        //
        // let ring_buf = RingBuf::try_from(self.bpf.map_mut("EVENTS").unwrap())?;
        //
        // loop {
        //     if let Some(data) = ring_buf.next() {
        //         let bytes = data.as_ref();
        //         if bytes.len() < 4 { continue; }
        //
        //         let event_type = u32::from_ne_bytes(bytes[..4].try_into().unwrap());
        //         let payload = &bytes[4..];
        //
        //         match event_type {
        //             1 => self.handle_igmp(payload, &tx).await?,
        //             2 => self.handle_quic(payload, &tx).await?,
        //             3 => self.handle_socket(payload, &tx).await?,
        //             4 => self.handle_physics(payload, &tx).await?,
        //             _ => warn!(event_type, "Unknown ring buffer event type"),
        //         }
        //     }
        //     tokio::task::yield_now().await;
        // }

        // Stub: wait forever (no real ring buffer in dev mode)
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }

    #[allow(dead_code)]
    async fn handle_igmp(
        &self,
        payload: &[u8],
        tx: &mpsc::Sender<idr_common::events::IdrEvent>,
    ) -> Result<()> {
        if payload.len() < std::mem::size_of::<RawIgmpEvent>() {
            return Ok(());
        }
        let raw: RawIgmpEvent = unsafe { std::ptr::read_unaligned(payload.as_ptr().cast()) };

        let event = idr_common::events::IdrEvent::new(
            idr_common::events::EventSource::KernelEbpf,
            idr_common::events::Severity::High,
            idr_common::events::EventKind::IgmpTrigger {
                src_ip: ip_to_string(raw.src_ip),
                group_addr: ip_to_string(raw.group_addr),
            },
        );

        tx.send(event).await.ok();
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
        let raw: RawQuicEvent = unsafe { std::ptr::read_unaligned(payload.as_ptr().cast()) };

        let event = idr_common::events::IdrEvent::new(
            idr_common::events::EventSource::KernelEbpf,
            idr_common::events::Severity::Warning,
            idr_common::events::EventKind::QuicHeartbeat {
                src_ip: ip_to_string(raw.src_ip),
                dst_ip: ip_to_string(raw.dst_ip),
                dst_port: raw.dst_port,
                pid: raw.pid,
                exe_path: String::new(), // Resolved by lineage correlator
            },
        );

        tx.send(event).await.ok();
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
                exe_sha256: String::new(), // Computed by lineage module
                dst_ip: ip_to_string(raw.dst_ip),
                dst_port: raw.dst_port,
                is_signed: false, // Checked by lineage module
            },
        );

        tx.send(event).await.ok();
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
        let raw: RawPhysicsEvent = unsafe { std::ptr::read_unaligned(payload.as_ptr().cast()) };

        let rtt_ms = raw.rtt_us as f64 / 1000.0;
        let dst_ip_str = ip_to_string(raw.dst_ip);

        // Physics anomaly check: suspicious TTL or impossibly low RTT
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

            tx.send(event).await.ok();
        }

        Ok(())
    }
}
