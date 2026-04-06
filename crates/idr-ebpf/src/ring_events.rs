//! Shared event structures between eBPF programs and userspace.
//!
//! These are the raw C-compatible structs that flow through eBPF ring buffers.
//! The userspace loader converts them into `IdrEvent` for the Sentinel Engine.

/// Raw IGMP event from XDP program
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawIgmpEvent {
    pub timestamp_ns: u64,
    pub src_ip: u32,
    pub group_addr: u32,
    pub igmp_type: u8,
    pub _pad: [u8; 3],
}

/// Raw QUIC (UDP 443) heartbeat event from XDP program
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawQuicEvent {
    pub timestamp_ns: u64,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub pid: u32,
}

/// Raw socket creation event from kprobe on inet_csk_accept / tcp_v4_connect
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawSocketEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub dst_ip: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: u8,
    /// First 64 bytes of exe_path (null-terminated)
    pub exe_path: [u8; 64],
}

/// Raw TTL/RTT observation from tracepoint
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawPhysicsEvent {
    pub timestamp_ns: u64,
    pub dst_ip: u32,
    pub ttl: u8,
    pub _pad: [u8; 3],
    /// RTT in microseconds from TCP
    pub rtt_us: u32,
}

/// Event tag for the multiplexed ring buffer
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingEventType {
    Igmp = 1,
    Quic = 2,
    Socket = 3,
    Physics = 4,
}

/// Wire format: 4-byte tag + payload
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RingEventHeader {
    pub event_type: u32,
}

// Helper to convert u32 IP to dotted string
pub fn ip_to_string(ip: u32) -> String {
    let bytes = ip.to_be_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}
