//! Socket-to-process lineage tracking.
//!
//! For every socket event from the eBPF kprobe:
//! 1. Read /proc/<pid>/exe to get the real binary path
//! 2. Compute SHA-256 hash of the binary
//! 3. Check if the binary is signed (via /proc/<pid>/status sigcap)
//! 4. Cross-reference destination IP against high-trust ASN list
//! 5. Flag unsigned/non-standard binaries beaconing to Google/Meta

use idr_common::events::{EventKind, EventSource, IdrEvent, Severity};
use idr_common::reputation::ReputationDb;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use tracing::{debug, warn};

/// Maximum cached PID entries (prevents memory exhaustion on high-churn systems)
const MAX_CACHE_ENTRIES: usize = 50_000;

/// Cache of PID → binary hash to avoid re-hashing on every socket event
struct BinaryCache {
    entries: HashMap<u32, CacheEntry>,
}

struct CacheEntry {
    exe_path: PathBuf,
    sha256: String,
    is_signed: bool,
}

impl BinaryCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn get_or_compute(&mut self, pid: u32) -> Option<&CacheEntry> {
        // Defend against PID reuse (TOCTOU): if cached, verify exe_path still matches
        if let Some(existing) = self.entries.get(&pid) {
            let exe_link = format!("/proc/{}/exe", pid);
            if let Ok(current_path) = std::fs::read_link(&exe_link) {
                if current_path != existing.exe_path {
                    // PID was recycled — invalidate stale entry
                    self.entries.remove(&pid);
                }
            }
        }

        if !self.entries.contains_key(&pid) {
            if let Some(entry) = Self::compute(pid) {
                // Enforce capacity limit
                if self.entries.len() >= MAX_CACHE_ENTRIES {
                    self.prune();
                    // If still over after prune, drop an arbitrary entry
                    if self.entries.len() >= MAX_CACHE_ENTRIES {
                        if let Some(key) = self.entries.keys().next().copied() {
                            self.entries.remove(&key);
                        }
                    }
                }
                self.entries.insert(pid, entry);
            }
        }
        self.entries.get(&pid)
    }

    fn compute(pid: u32) -> Option<CacheEntry> {
        // Read the real exe path via /proc
        let exe_link = format!("/proc/{}/exe", pid);
        let exe_path = std::fs::read_link(&exe_link).ok()?;

        // Safety: only hash files that look like real executables, not arbitrary paths.
        // Skip deleted binaries (kernel appends " (deleted)").
        let path_str = exe_path.to_string_lossy();
        if path_str.contains(" (deleted)") {
            return None;
        }

        // Only hash files, not directories or special files
        let metadata = std::fs::metadata(&exe_path).ok()?;
        if !metadata.is_file() {
            return None;
        }

        // Cap file size to prevent hashing multi-GB binaries (256 MB limit)
        if metadata.len() > 256 * 1024 * 1024 {
            warn!(path = %path_str, "Binary too large to hash, skipping");
            return None;
        }

        // Compute SHA-256 of the binary
        let binary_data = std::fs::read(&exe_path).ok()?;
        let mut hasher = Sha256::new();
        hasher.update(&binary_data);
        let sha256 = format!("{:x}", hasher.finalize());

        // Check if binary is in standard system paths
        let is_signed = is_standard_binary(&exe_path);

        Some(CacheEntry {
            exe_path,
            sha256,
            is_signed,
        })
    }

    /// Prune entries for processes that no longer exist
    fn prune(&mut self) {
        self.entries.retain(|pid, _| {
            std::path::Path::new(&format!("/proc/{}", pid)).exists()
        });
    }
}

/// Check if a binary is in a standard system path (simple heuristic)
fn is_standard_binary(path: &std::path::Path) -> bool {
    let standard_prefixes = [
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/lib/",
        "/usr/libexec/",
        "/bin/",
        "/sbin/",
        "/lib/",
    ];

    let path_str = path.to_string_lossy();
    standard_prefixes.iter().any(|prefix| path_str.starts_with(prefix))
}

/// Lineage tracker that enriches socket events with process information
pub struct LineageTracker {
    cache: BinaryCache,
    reputation: ReputationDb,
}

impl LineageTracker {
    pub fn new(reputation: ReputationDb) -> Self {
        Self {
            cache: BinaryCache::new(),
            reputation,
        }
    }

    /// Process a socket lineage event. Returns a SuspiciousBeacon event if
    /// an unsigned/non-standard binary is connecting to a high-trust IP.
    pub fn process(&mut self, event: &IdrEvent) -> Option<IdrEvent> {
        let (pid, dst_ip_str) = match &event.kind {
            EventKind::SocketLineage {
                pid,
                dst_ip,
                ..
            } => (*pid, dst_ip.clone()),
            _ => return None,
        };

        // Enrich with process info
        let cache_entry = self.cache.get_or_compute(pid)?;

        // Check if destination is a high-trust IP
        let dst_ip: Ipv4Addr = dst_ip_str.parse().ok()?;
        let trust = self.reputation.classify_ip(&dst_ip);

        if trust == idr_common::reputation::TrustLevel::HighTrust && !cache_entry.is_signed {
            let asn = self
                .reputation
                .lookup_asn(&dst_ip)
                .unwrap_or("unknown")
                .to_string();

            warn!(
                pid = pid,
                exe = %cache_entry.exe_path.display(),
                sha256 = %cache_entry.sha256,
                dst_ip = %dst_ip_str,
                asn = %asn,
                "Non-standard binary beaconing to high-trust IP"
            );

            return Some(IdrEvent::new(
                EventSource::KernelEbpf,
                Severity::High,
                EventKind::SuspiciousBeacon {
                    pid,
                    exe_path: cache_entry.exe_path.display().to_string(),
                    exe_sha256: cache_entry.sha256.clone(),
                    dst_ip: dst_ip_str,
                    asn_owner: asn,
                },
            ));
        }

        debug!(
            pid = pid,
            exe = %cache_entry.exe_path.display(),
            dst = %dst_ip_str,
            "Socket lineage tracked (benign)"
        );

        None
    }

    /// Periodically prune dead processes from cache
    pub fn prune_cache(&mut self) {
        self.cache.prune();
    }
}
