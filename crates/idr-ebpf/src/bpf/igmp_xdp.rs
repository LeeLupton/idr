//! eBPF XDP program for IGMP v3 detection and QUIC heartbeat capture.
//!
//! This is the **eBPF-side** program that runs in the kernel. It is compiled
//! separately with `bpf-linker` and loaded by the userspace loader via Aya.
//!
//! Detection logic:
//! 1. Parse incoming packets at XDP layer (before any netfilter/iptables)
//! 2. If IGMP v3 to 224.0.0.1 → emit RawIgmpEvent to ring buffer
//! 3. If outbound UDP port 443 (QUIC) → emit RawQuicEvent to ring buffer
//!
//! The userspace correlator checks if QUIC events fall within the 500ms
//! window after an IGMP trigger.
//!
//! NOTE: This file documents the eBPF program logic. The actual eBPF binary
//! must be compiled with `cargo +nightly build --target bpfel-unknown-none -Z build-std=core`
//! or via aya-tool. Below is the Rust-style pseudocode matching the BPF verifier
//! constraints.

// === eBPF Program Source (requires aya-ebpf crate, bpfel target) ===
//
// #![no_std]
// #![no_main]
//
// use aya_ebpf::{
//     bindings::xdp_action,
//     macros::{map, xdp},
//     maps::RingBuf,
//     programs::XdpContext,
// };
// use core::mem;
//
// const ETH_P_IP: u16 = 0x0800;
// const IPPROTO_IGMP: u8 = 2;
// const IPPROTO_UDP: u8 = 17;
// const IGMP_V3_REPORT: u8 = 0x22;
// const QUIC_PORT: u16 = 443;
// const MULTICAST_ALL_HOSTS: u32 = 0xE0000001; // 224.0.0.1
//
// #[repr(C)]
// struct EthHdr {
//     dst_mac: [u8; 6],
//     src_mac: [u8; 6],
//     eth_type: u16,
// }
//
// #[repr(C)]
// struct IpHdr {
//     ver_ihl: u8,
//     tos: u8,
//     tot_len: u16,
//     id: u16,
//     frag_off: u16,
//     ttl: u8,
//     protocol: u8,
//     check: u16,
//     saddr: u32,
//     daddr: u32,
// }
//
// #[repr(C)]
// struct UdpHdr {
//     source: u16,
//     dest: u16,
//     len: u16,
//     check: u16,
// }
//
// #[repr(C)]
// struct IgmpEvent {
//     timestamp_ns: u64,
//     src_ip: u32,
//     group_addr: u32,
//     igmp_type: u8,
//     _pad: [u8; 3],
// }
//
// #[repr(C)]
// struct QuicEvent {
//     timestamp_ns: u64,
//     src_ip: u32,
//     dst_ip: u32,
//     src_port: u16,
//     dst_port: u16,
//     pid: u32,
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
// #[xdp]
// pub fn idr_xdp(ctx: XdpContext) -> u32 {
//     match process_packet(&ctx) {
//         Ok(action) => action,
//         Err(_) => xdp_action::XDP_PASS,
//     }
// }
//
// fn process_packet(ctx: &XdpContext) -> Result<u32, ()> {
//     let data = ctx.data();
//     let data_end = ctx.data_end();
//
//     // Parse Ethernet header
//     if data + mem::size_of::<EthHdr>() > data_end {
//         return Ok(xdp_action::XDP_PASS);
//     }
//     let eth = unsafe { &*(data as *const EthHdr) };
//     if u16::from_be(eth.eth_type) != ETH_P_IP {
//         return Ok(xdp_action::XDP_PASS);
//     }
//
//     // Parse IP header
//     let ip_offset = data + mem::size_of::<EthHdr>();
//     if ip_offset + mem::size_of::<IpHdr>() > data_end {
//         return Ok(xdp_action::XDP_PASS);
//     }
//     let ip = unsafe { &*(ip_offset as *const IpHdr) };
//
//     // Branch: IGMP detection
//     if ip.protocol == IPPROTO_IGMP {
//         let igmp_offset = ip_offset + ((ip.ver_ihl & 0x0F) as usize * 4);
//         if igmp_offset + 1 > data_end {
//             return Ok(xdp_action::XDP_PASS);
//         }
//         let igmp_type = unsafe { *(igmp_offset as *const u8) };
//
//         // Check for IGMP v3 Membership Report to all-hosts
//         if igmp_type == IGMP_V3_REPORT || ip.daddr == MULTICAST_ALL_HOSTS.to_be() {
//             // Emit IGMP event to ring buffer
//             if let Some(mut buf) = EVENTS.reserve::<RingHeader + IgmpEvent>(0) {
//                 let header = RingHeader { event_type: 1 }; // IGMP
//                 let event = IgmpEvent {
//                     timestamp_ns: bpf_ktime_get_ns(),
//                     src_ip: ip.saddr,
//                     group_addr: ip.daddr,
//                     igmp_type,
//                     _pad: [0; 3],
//                 };
//                 // Write header + event to ring buffer
//                 buf.write(header, event);
//                 buf.submit(0);
//             }
//         }
//     }
//
//     // Branch: UDP 443 (QUIC) heartbeat detection
//     if ip.protocol == IPPROTO_UDP {
//         let udp_offset = ip_offset + ((ip.ver_ihl & 0x0F) as usize * 4);
//         if udp_offset + mem::size_of::<UdpHdr>() > data_end {
//             return Ok(xdp_action::XDP_PASS);
//         }
//         let udp = unsafe { &*(udp_offset as *const UdpHdr) };
//
//         if u16::from_be(udp.dest) == QUIC_PORT {
//             // Emit QUIC heartbeat event
//             if let Some(mut buf) = EVENTS.reserve::<RingHeader + QuicEvent>(0) {
//                 let header = RingHeader { event_type: 2 }; // QUIC
//                 let event = QuicEvent {
//                     timestamp_ns: bpf_ktime_get_ns(),
//                     src_ip: ip.saddr,
//                     dst_ip: ip.daddr,
//                     src_port: u16::from_be(udp.source),
//                     dst_port: u16::from_be(udp.dest),
//                     pid: 0, // Populated by kprobe correlator
//                 };
//                 buf.write(header, event);
//                 buf.submit(0);
//             }
//         }
//     }
//
//     // ALWAYS pass — we are a sensor, not a firewall
//     Ok(xdp_action::XDP_PASS)
// }
//
// #[panic_handler]
// fn panic(_info: &core::panic::PanicInfo) -> ! {
//     loop {}
// }

/// Marker module — the actual eBPF bytecode is loaded from the compiled .o file.
/// This source documents the program logic for auditability.
pub const PROGRAM_NAME: &str = "idr_xdp";
