//! eBPF tracepoint program for TTL/RTT routing physics monitoring.
//!
//! Attaches to:
//! - `tracepoint/tcp/tcp_probe` — captures RTT for TCP connections
//! - `tracepoint/net/netif_receive_skb` — captures incoming TTL values
//!
//! Detection logic (userspace):
//! - If connection to a "Global" IP (Google/Meta) returns TTL=63 → suspect
//!   local MoCA/router sinkhole (real Google TTL should be ~50-55)
//! - If RTT < 5ms to a global IP → physically impossible without local intercept
//!
//! These "routing physics" violations indicate a BGP adjacency hijack where
//! a local device is answering on behalf of the real destination.
//
// #![no_std]
// #![no_main]
//
// use aya_ebpf::{
//     macros::{map, tracepoint},
//     maps::RingBuf,
//     programs::TracePointContext,
//     helpers::bpf_ktime_get_ns,
// };
//
// #[repr(C)]
// struct PhysicsEvent {
//     timestamp_ns: u64,
//     dst_ip: u32,
//     ttl: u8,
//     _pad: [u8; 3],
//     rtt_us: u32,
// }
//
// #[repr(C)]
// struct RingHeader {
//     event_type: u32,
// }
//
// #[map]
// static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
//
// /// Tracepoint: tcp/tcp_probe
// /// This fires for established TCP connections and provides RTT data.
// #[tracepoint]
// pub fn idr_tcp_probe(ctx: TracePointContext) -> u32 {
//     match handle_tcp_probe(&ctx) {
//         Ok(()) => 0,
//         Err(_) => 0,
//     }
// }
//
// fn handle_tcp_probe(ctx: &TracePointContext) -> Result<(), ()> {
//     // tcp_probe tracepoint format:
//     // field:__u8 saddr[4];     offset:8
//     // field:__u8 daddr[4];     offset:12
//     // field:__u32 srtt;        offset:64 (smoothed RTT in us)
//
//     let dst_ip: u32 = unsafe { ctx.read_at(12) }.map_err(|_| ())?;
//     let srtt: u32 = unsafe { ctx.read_at(64) }.map_err(|_| ())?;
//
//     // Only emit for WAN IPs (skip private ranges)
//     if is_private_ip(dst_ip) {
//         return Ok(());
//     }
//
//     if let Some(mut buf) = EVENTS.reserve::<RingHeader + PhysicsEvent>(0) {
//         let header = RingHeader { event_type: 4 }; // Physics
//         let event = PhysicsEvent {
//             timestamp_ns: bpf_ktime_get_ns(),
//             dst_ip,
//             ttl: 0, // TTL comes from the skb tracepoint
//             _pad: [0; 3],
//             rtt_us: srtt,
//         };
//         buf.write(header, event);
//         buf.submit(0);
//     }
//
//     Ok(())
// }
//
// fn is_private_ip(ip: u32) -> bool {
//     let bytes = ip.to_be_bytes();
//     // 10.x.x.x
//     if bytes[0] == 10 { return true; }
//     // 172.16-31.x.x
//     if bytes[0] == 172 && (bytes[1] >= 16 && bytes[1] <= 31) { return true; }
//     // 192.168.x.x
//     if bytes[0] == 192 && bytes[1] == 168 { return true; }
//     // 127.x.x.x
//     if bytes[0] == 127 { return true; }
//     false
// }
//
// #[panic_handler]
// fn panic(_info: &core::panic::PanicInfo) -> ! {
//     loop {}
// }

pub const PROGRAM_NAME: &str = "idr_tcp_probe";
