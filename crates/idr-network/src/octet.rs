//! Octet Reversal (DPI Evasion) Detection.
//!
//! The DPRK-001 campaign uses a technique where outbound connections go to
//! legitimate IPs (e.g., Google 142.250.x.x), but DNS PTR queries reveal the
//! octets are reversed. The reversed IP (x.250.142.x) resolves to a residential
//! ISP (Deutsche Telekom, 3BB), indicating the traffic is being tunneled through
//! a residential proxy to evade DPI.
//!
//! Detection logic:
//! 1. Extract PTR queries from Zeek DNS logs
//! 2. Reverse the octets of the queried IP
//! 3. Look up ASN for both forward and reversed IPs
//! 4. If forward = HighTrust and reversed = ResidentialISP → CRITICAL alert

use idr_common::events::{EventKind, EventSource, IdrEvent, Severity};
use idr_common::reputation::{ReputationDb, TrustLevel};
use std::net::Ipv4Addr;
use tracing::{info, warn};

pub struct OctetReversalDetector {
    reputation: ReputationDb,
}

impl OctetReversalDetector {
    pub fn new(reputation: ReputationDb) -> Self {
        Self { reputation }
    }

    /// Analyze a PTR-based event for octet reversal evasion.
    ///
    /// Takes an OctetReversalDetected event (with empty ASN fields) and
    /// enriches it with reputation data, returning a CRITICAL alert if
    /// the reversal pattern matches the DPRK-001 evasion technique.
    pub fn analyze(&self, event: &IdrEvent) -> Option<IdrEvent> {
        let (forward_ip_str, reversed_ip_str, ptr_query) = match &event.kind {
            EventKind::OctetReversalDetected {
                forward_ip,
                reversed_ip,
                ptr_query,
                ..
            } => (forward_ip.clone(), reversed_ip.clone(), ptr_query.clone()),
            _ => return None,
        };

        let forward_ip: Ipv4Addr = forward_ip_str.parse().ok()?;
        let reversed_ip: Ipv4Addr = reversed_ip_str.parse().ok()?;

        let forward_trust = self.reputation.classify_ip(&forward_ip);
        let reversed_trust = self.reputation.classify_ip(&reversed_ip);

        let forward_asn = self
            .reputation
            .lookup_asn(&forward_ip)
            .unwrap_or("unknown")
            .to_string();
        let reversed_asn = self
            .reputation
            .lookup_asn(&reversed_ip)
            .unwrap_or("unknown")
            .to_string();

        // The evasion pattern: forward IP is high-trust, reversed is residential
        if forward_trust == TrustLevel::HighTrust && reversed_trust == TrustLevel::ResidentialIsp {
            warn!(
                forward_ip = %forward_ip_str,
                reversed_ip = %reversed_ip_str,
                forward_asn = %forward_asn,
                reversed_asn = %reversed_asn,
                ptr_query = %ptr_query,
                "CRITICAL: Octet Reversal DPI Evasion Detected — DPRK-001 pattern match"
            );

            return Some(IdrEvent::new(
                EventSource::NetworkZeek,
                Severity::Critical,
                EventKind::OctetReversalDetected {
                    forward_ip: forward_ip_str,
                    reversed_ip: reversed_ip_str,
                    forward_asn,
                    reversed_asn,
                    ptr_query,
                },
            ));
        }

        info!(
            forward_ip = %forward_ip_str,
            forward_trust = ?forward_trust,
            reversed_ip = %reversed_ip_str,
            reversed_trust = ?reversed_trust,
            "PTR reversal analyzed — no evasion pattern detected"
        );

        None
    }

    /// Direct check: given an outbound connection IP, test if its reversal
    /// matches the evasion pattern.
    pub fn check_ip(&self, ip: &Ipv4Addr) -> Option<IdrEvent> {
        if let Some(result) = self.reputation.check_octet_reversal(ip) {
            warn!(
                forward_ip = %result.forward_ip,
                reversed_ip = %result.reversed_ip,
                forward_asn = %result.forward_asn,
                reversed_asn = %result.reversed_asn,
                "Octet reversal evasion detected via direct IP check"
            );

            return Some(IdrEvent::new(
                EventSource::NetworkZeek,
                Severity::Critical,
                EventKind::OctetReversalDetected {
                    forward_ip: result.forward_ip.to_string(),
                    reversed_ip: result.reversed_ip.to_string(),
                    forward_asn: result.forward_asn,
                    reversed_asn: result.reversed_asn,
                    ptr_query: format!(
                        "{}.in-addr.arpa",
                        result
                            .reversed_ip
                            .octets()
                            .iter()
                            .rev()
                            .map(|o| o.to_string())
                            .collect::<Vec<_>>()
                            .join(".")
                    ),
                },
            ));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_octet_reversal_detection() {
        let reputation = ReputationDb::new();
        let detector = OctetReversalDetector::new(reputation);

        // Test a known Google IP — its reversal might not map to residential,
        // but the logic is exercised
        let google_ip: Ipv4Addr = "142.250.80.46".parse().unwrap();
        let _result = detector.check_ip(&google_ip);
        // Result depends on whether the reversed IP (46.80.250.142) maps to a residential ASN
    }
}
