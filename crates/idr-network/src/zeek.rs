//! Zeek log ingestor — reads JSON events from a Unix socket.
//!
//! Zeek is configured to output structured JSON logs to a Unix domain socket
//! at a configurable path. This module:
//! 1. Connects to the socket
//! 2. Parses JSON-per-line events
//! 3. Converts relevant Zeek logs into IdrEvents for the Sentinel Engine

use anyhow::{Context, Result};
use idr_common::events::{EventKind, EventSource, IdrEvent, Severity};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Zeek DNS log entry (subset of fields we care about)
#[derive(Debug, Deserialize)]
struct ZeekDnsLog {
    query: Option<String>,
    qtype_name: Option<String>,
}

/// Zeek NTP log entry
#[derive(Debug, Deserialize)]
struct ZeekNtpLog {
    #[serde(rename = "id.resp_h")]
    resp_h: Option<String>,
    ref_time: Option<f64>,
    org_time: Option<f64>,
}

/// Zeek SSL/TLS log entry
#[derive(Debug, Deserialize)]
struct ZeekSslLog {
    server_name: Option<String>,
    not_valid_after: Option<String>,
    validation_status: Option<String>,
}

/// Wrapper for Zeek JSON log routing
#[derive(Debug, Deserialize)]
struct ZeekLogEntry {
    #[serde(rename = "_path")]
    path: String,
    #[serde(flatten)]
    data: serde_json::Value,
}

pub struct ZeekIngestor {
    socket_path: String,
}

impl ZeekIngestor {
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
        }
    }

    /// Connect to the Zeek Unix socket and start ingesting events
    pub async fn run(&mut self, tx: mpsc::Sender<IdrEvent>) -> Result<()> {
        info!(path = %self.socket_path, "Connecting to Zeek Unix socket");

        let stream = UnixStream::connect(&self.socket_path)
            .await
            .context("Failed to connect to Zeek socket")?;

        let reader = BufReader::new(stream);
        let mut lines = reader.lines();

        info!("Zeek ingestor connected — processing JSON logs");

        while let Some(line) = lines.next_line().await? {
            if line.is_empty() {
                continue;
            }

            match self.parse_zeek_line(&line) {
                Ok(Some(event)) => {
                    if tx.send(event).await.is_err() {
                        warn!("Failed to send Zeek event — channel closed");
                        break;
                    }
                }
                Ok(None) => {
                    debug!("Zeek line parsed but no event generated");
                }
                Err(e) => {
                    debug!(error = %e, "Failed to parse Zeek JSON line");
                }
            }
        }

        Ok(())
    }

    fn parse_zeek_line(&self, line: &str) -> Result<Option<IdrEvent>> {
        let entry: ZeekLogEntry = serde_json::from_str(line)?;

        match entry.path.as_str() {
            "dns" => self.handle_dns(&entry.data),
            "ntp" => self.handle_ntp(&entry.data),
            "ssl" => self.handle_ssl(&entry.data),
            _ => Ok(None),
        }
    }

    fn handle_dns(&self, data: &serde_json::Value) -> Result<Option<IdrEvent>> {
        let log: ZeekDnsLog = serde_json::from_value(data.clone())?;

        if let Some(qtype) = &log.qtype_name {
            if qtype == "PTR" {
                if let Some(query) = &log.query {
                    if query.ends_with(".in-addr.arpa") {
                        let reversed_octets: Vec<&str> = query
                            .trim_end_matches(".in-addr.arpa")
                            .split('.')
                            .collect();

                        if reversed_octets.len() == 4 {
                            let reversed_ip = format!(
                                "{}.{}.{}.{}",
                                reversed_octets[0],
                                reversed_octets[1],
                                reversed_octets[2],
                                reversed_octets[3]
                            );
                            let forward_ip = format!(
                                "{}.{}.{}.{}",
                                reversed_octets[3],
                                reversed_octets[2],
                                reversed_octets[1],
                                reversed_octets[0]
                            );

                            debug!(
                                ptr_query = %query,
                                forward_ip = %forward_ip,
                                reversed_ip = %reversed_ip,
                                "PTR query detected"
                            );

                            return Ok(Some(IdrEvent::new(
                                EventSource::NetworkZeek,
                                Severity::Info,
                                EventKind::OctetReversalDetected {
                                    forward_ip,
                                    reversed_ip,
                                    forward_asn: String::new(),
                                    reversed_asn: String::new(),
                                    ptr_query: query.clone(),
                                },
                            )));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    fn handle_ntp(&self, data: &serde_json::Value) -> Result<Option<IdrEvent>> {
        let log: ZeekNtpLog = serde_json::from_value(data.clone())?;

        if let (Some(ref_time), Some(org_time)) = (log.ref_time, log.org_time) {
            let offset = (ref_time - org_time).abs();

            if offset > 300.0 {
                let server = log.resp_h.unwrap_or_else(|| "unknown".to_string());

                warn!(
                    offset_seconds = offset,
                    ntp_server = %server,
                    "NTP time shift > 5 minutes detected"
                );

                return Ok(Some(IdrEvent::new(
                    EventSource::NetworkZeek,
                    Severity::High,
                    EventKind::NtpTimeShift {
                        offset_seconds: offset,
                        ntp_server: server,
                    },
                )));
            }
        }

        Ok(None)
    }

    fn handle_ssl(&self, data: &serde_json::Value) -> Result<Option<IdrEvent>> {
        let log: ZeekSslLog = serde_json::from_value(data.clone())?;

        if let Some(status) = &log.validation_status {
            if status.contains("expired") || status.contains("not yet valid") {
                let domain = log
                    .server_name
                    .unwrap_or_else(|| "unknown".to_string());
                let expiry = log
                    .not_valid_after
                    .unwrap_or_else(|| "unknown".to_string());

                warn!(
                    domain = %domain,
                    expiry = %expiry,
                    status = %status,
                    "Expired TLS certificate detected"
                );

                return Ok(Some(IdrEvent::new(
                    EventSource::NetworkZeek,
                    Severity::High,
                    EventKind::HstsTimeManipulation {
                        domain,
                        cert_expiry: expiry,
                        ntp_shift_seconds: 0.0,
                    },
                )));
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ptr_query() {
        let ingestor = ZeekIngestor::new("/tmp/test.sock");

        // Simulated Zeek DNS log with a PTR query
        // PTR for 8.8.8.8 → query is 8.8.8.8.in-addr.arpa
        let line = r#"{"_path":"dns","query":"8.8.8.8.in-addr.arpa","qtype_name":"PTR"}"#;

        let result = ingestor.parse_zeek_line(line).unwrap();
        assert!(result.is_some(), "PTR query should produce an event");

        let event = result.unwrap();
        if let EventKind::OctetReversalDetected {
            forward_ip,
            reversed_ip,
            ptr_query,
            ..
        } = &event.kind
        {
            // The reversed_ip is the octets as-is from the PTR query: "8.8.8.8"
            assert_eq!(reversed_ip, "8.8.8.8");
            // The forward_ip reverses the octets: "8.8.8.8" (symmetric in this case)
            assert_eq!(forward_ip, "8.8.8.8");
            assert_eq!(ptr_query, "8.8.8.8.in-addr.arpa");
        } else {
            panic!("expected OctetReversalDetected event kind");
        }

        // Test with an asymmetric PTR query: 46.80.250.142.in-addr.arpa
        // This represents a PTR lookup for IP 142.250.80.46
        let line2 = r#"{"_path":"dns","query":"46.80.250.142.in-addr.arpa","qtype_name":"PTR"}"#;

        let result2 = ingestor.parse_zeek_line(line2).unwrap();
        assert!(result2.is_some());

        let event2 = result2.unwrap();
        if let EventKind::OctetReversalDetected {
            forward_ip,
            reversed_ip,
            ..
        } = &event2.kind
        {
            // reversed_ip = octets as ordered in the query: 46.80.250.142
            assert_eq!(reversed_ip, "46.80.250.142");
            // forward_ip = reversed octets: 142.250.80.46
            assert_eq!(forward_ip, "142.250.80.46");
        } else {
            panic!("expected OctetReversalDetected event kind");
        }
    }
}
