//! eBPF kprobe program for socket-to-process lineage tracking.
//!
//! Attaches to:
//! - `tcp_v4_connect` (outbound TCP connections)
//! - `udp_sendmsg` (outbound UDP)
//!
//! For each socket operation, captures:
//! - PID, TGID, comm, exe_path
//! - Destination IP and port
//! - Protocol type
//!
//! The userspace component performs SHA-256 hashing of the binary
//! and cross-references against the reputation database.
//!
//! NOTE: eBPF program source (requires bpfel-unknown-none target)
//
// #![no_std]
// #![no_main]
//
// use aya_ebpf::{
//     macros::{kprobe, map},
//     maps::RingBuf,
//     programs::ProbeContext,
//     helpers::{bpf_get_current_pid_tgid, bpf_get_current_comm, bpf_ktime_get_ns},
// };
//
// #[repr(C)]
// struct SocketEvent {
//     timestamp_ns: u64,
//     pid: u32,
//     tgid: u32,
//     dst_ip: u32,
//     dst_port: u16,
//     protocol: u8,
//     _pad: u8,
//     exe_path: [u8; 64],
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
// #[kprobe]
// pub fn idr_tcp_connect(ctx: ProbeContext) -> u32 {
//     match handle_connect(&ctx, 6) { // TCP = 6
//         Ok(()) => 0,
//         Err(_) => 0,
//     }
// }
//
// #[kprobe]
// pub fn idr_udp_sendmsg(ctx: ProbeContext) -> u32 {
//     match handle_connect(&ctx, 17) { // UDP = 17
//         Ok(()) => 0,
//         Err(_) => 0,
//     }
// }
//
// fn handle_connect(ctx: &ProbeContext, protocol: u8) -> Result<(), ()> {
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let pid = (pid_tgid >> 32) as u32;
//     let tgid = pid_tgid as u32;
//
//     // Read struct sock * from first argument
//     let sk: *const sock = ctx.arg(0).ok_or(())?;
//
//     // Extract destination from sock struct
//     // sk->__sk_common.skc_daddr and sk->__sk_common.skc_dport
//     let dst_ip = unsafe { bpf_probe_read_kernel(&(*sk).__sk_common.skc_daddr) }.map_err(|_| ())?;
//     let dst_port = unsafe { bpf_probe_read_kernel(&(*sk).__sk_common.skc_dport) }.map_err(|_| ())?;
//
//     // Get process comm (up to 16 bytes)
//     let mut comm = [0u8; 64];
//     let _ = bpf_get_current_comm(&mut comm[..16]);
//
//     // Emit socket event
//     if let Some(mut buf) = EVENTS.reserve::<RingHeader + SocketEvent>(0) {
//         let header = RingHeader { event_type: 3 }; // Socket
//         let event = SocketEvent {
//             timestamp_ns: bpf_ktime_get_ns(),
//             pid,
//             tgid,
//             dst_ip,
//             dst_port: u16::from_be(dst_port),
//             protocol,
//             _pad: 0,
//             exe_path: comm,
//         };
//         buf.write(header, event);
//         buf.submit(0);
//     }
//
//     Ok(())
// }
//
// #[panic_handler]
// fn panic(_info: &core::panic::PanicInfo) -> ! {
//     loop {}
// }

pub const PROGRAM_NAME_TCP: &str = "idr_tcp_connect";
pub const PROGRAM_NAME_UDP: &str = "idr_udp_sendmsg";
