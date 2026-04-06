#!/usr/bin/env bash
# IDR System Hardening Script
# Run as root before starting the Sentinel Engine.
#
# Applies kernel sysctl parameters to:
# 1. Harden BPF JIT against code-reuse attacks
# 2. Disable unprivileged BPF access
# 3. Additional network hardening

set -euo pipefail

echo "[IDR] Applying kernel hardening..."

# === BPF JIT Hardening ===
# Level 2: constant blinding + additional mitigations for JIT spraying
sysctl -w net.core.bpf_jit_harden=2
echo "[IDR] BPF JIT hardening: level 2 (constant blinding enabled)"

# Disable unprivileged BPF — only root can load BPF programs
sysctl -w kernel.unprivileged_bpf_disabled=1
echo "[IDR] Unprivileged BPF disabled"

# === Network Stack Hardening ===
# Disable IP forwarding (this is a sensor, not a router)
sysctl -w net.ipv4.ip_forward=0

# Enable strict reverse-path filtering (anti-spoofing)
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1

# Ignore ICMP redirects (prevent route injection)
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0

# Enable SYN cookies (mitigate SYN flood)
sysctl -w net.ipv4.tcp_syncookies=1

# Log martian packets (impossible source addresses)
sysctl -w net.ipv4.conf.all.log_martians=1

# === Kernel Module Hardening ===
# Restrict loading of kernel modules (if supported)
if [ -f /proc/sys/kernel/modules_disabled ]; then
    echo "[IDR] WARNING: Setting modules_disabled=1 is irreversible until reboot"
    echo "[IDR] Skipping modules_disabled — enable manually after all modules are loaded"
fi

# Restrict access to kernel logs
sysctl -w kernel.dmesg_restrict=1

# Restrict access to kernel pointers in /proc
sysctl -w kernel.kptr_restrict=2

# === File System Hardening ===
# Restrict ptrace (prevent cross-process memory inspection)
sysctl -w kernel.yama.ptrace_scope=2

echo "[IDR] Hardening complete. Verify with: sysctl net.core.bpf_jit_harden kernel.unprivileged_bpf_disabled"
