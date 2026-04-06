##! IDR Detection Script for Zeek
##!
##! Outputs JSON logs to a Unix socket for the IDR Sentinel Engine.
##! Monitors:
##! - DNS PTR queries (octet reversal detection)
##! - NTP traffic (time-shift detection)
##! - TLS handshakes (expired certificate detection)

@load base/protocols/dns
@load base/protocols/ssl
@load base/frameworks/notice

module IDR;

export {
    ## Unix socket path for Sentinel Engine communication
    const sentinel_socket = "/var/run/idr/zeek.sock" &redef;

    ## Enable PTR query monitoring
    const monitor_ptr = T &redef;

    ## Enable NTP monitoring
    const monitor_ntp = T &redef;

    ## Enable TLS certificate monitoring
    const monitor_tls = T &redef;

    ## NTP time-shift threshold in seconds
    const ntp_shift_threshold = 300.0 &redef;

    redef enum Notice::Type += {
        ## Octet reversal detected in DNS PTR query
        Octet_Reversal_Detected,
        ## NTP time shift exceeds threshold
        NTP_Time_Shift,
        ## Expired TLS certificate accepted
        Expired_Cert_Accepted,
    };
}

# Track active connections for cross-referencing
global active_connections: table[addr] of set[addr] &create_expire=5min;

# Track NTP time-shift state
global ntp_shift_active: bool = F;
global ntp_shift_offset: double = 0.0;
global tls_handshakes_since_shift: count = 0;
const TLS_FLAG_LIMIT: count = 10;

## DNS PTR Query Monitor — Octet Reversal Detection
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( ! monitor_ptr )
        return;

    # qtype 12 = PTR
    if ( qtype != 12 )
        return;

    if ( ! /\.in-addr\.arpa$/ in query )
        return;

    # Extract the reversed IP octets from the PTR query
    local parts = split_string(query, /\./);
    if ( |parts| < 4 )
        return;

    # Reconstruct the reversed IP (D.C.B.A from PTR D.C.B.A.in-addr.arpa)
    local reversed_ip = fmt("%s.%s.%s.%s", parts[0], parts[1], parts[2], parts[3]);
    # Reconstruct the forward IP (A.B.C.D)
    local forward_ip = fmt("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0]);

    # Log as JSON for the Sentinel Engine
    local log_entry = fmt("{\"_path\":\"dns\",\"ts\":%.6f,\"id.orig_h\":\"%s\",\"id.resp_h\":\"%s\",\"query\":\"%s\",\"qtype_name\":\"PTR\",\"forward_ip\":\"%s\",\"reversed_ip\":\"%s\"}",
        network_time(), c$id$orig_h, c$id$resp_h, query, forward_ip, reversed_ip);

    # Write to Unix socket
    # Note: Actual socket writing requires Zeek's Input framework or external writer
    # For production, use: @load base/frameworks/logging/writers/ascii
    # with a custom writer that sends to the Unix socket

    NOTICE([$note=Octet_Reversal_Detected,
            $msg=fmt("PTR octet reversal: forward=%s reversed=%s query=%s",
                     forward_ip, reversed_ip, query),
            $conn=c,
            $identifier=query]);
    }

## NTP Time-Shift Detection
event ntp_message(c: connection, is_orig: bool, msg: NTP::Message)
    {
    if ( ! monitor_ntp )
        return;

    # Calculate time offset from NTP response
    # NTP offset = ((T2 - T1) + (T3 - T4)) / 2
    # Simplified: check if reference timestamp diverges significantly
    if ( is_orig )
        return;

    # Use transmit timestamp as rough indicator
    local ntp_time = msg$transmit_time;
    local sys_time = network_time();
    local offset = time_to_double(ntp_time) - time_to_double(sys_time);

    if ( offset < 0.0 )
        offset = -offset;

    if ( offset > ntp_shift_threshold )
        {
        ntp_shift_active = T;
        ntp_shift_offset = offset;
        tls_handshakes_since_shift = 0;

        NOTICE([$note=NTP_Time_Shift,
                $msg=fmt("NTP time shift of %.1f seconds detected from %s",
                         offset, c$id$resp_h),
                $conn=c]);

        local log_entry = fmt("{\"_path\":\"ntp\",\"ts\":%.6f,\"id.orig_h\":\"%s\",\"id.resp_h\":\"%s\",\"ref_time\":%.6f,\"org_time\":%.6f}",
            network_time(), c$id$orig_h, c$id$resp_h,
            time_to_double(ntp_time), time_to_double(sys_time));
        }
    }

## TLS Certificate Expiry Monitoring
event ssl_established(c: connection)
    {
    if ( ! monitor_tls )
        return;

    if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 )
        return;

    # Track TLS handshakes during NTP shift window
    if ( ntp_shift_active )
        {
        tls_handshakes_since_shift += 1;

        if ( tls_handshakes_since_shift >= TLS_FLAG_LIMIT )
            ntp_shift_active = F;

        # Check certificate validity
        if ( c$ssl?$validation_status )
            {
            if ( /expired/ in c$ssl$validation_status ||
                 /not yet valid/ in c$ssl$validation_status )
                {
                local domain = c$ssl?$server_name ? c$ssl$server_name : "unknown";
                local expiry = c$ssl?$not_valid_after ?
                    fmt("%s", c$ssl$not_valid_after) : "unknown";

                NOTICE([$note=Expired_Cert_Accepted,
                        $msg=fmt("Expired cert for %s (expiry: %s) accepted during NTP shift (%.1fs)",
                                 domain, expiry, ntp_shift_offset),
                        $conn=c]);

                local log_entry = fmt("{\"_path\":\"ssl\",\"ts\":%.6f,\"id.orig_h\":\"%s\",\"id.resp_h\":\"%s\",\"server_name\":\"%s\",\"not_valid_after\":\"%s\",\"validation_status\":\"%s\"}",
                    network_time(), c$id$orig_h, c$id$resp_h,
                    domain, expiry, c$ssl$validation_status);
                }
            }
        }
    }
