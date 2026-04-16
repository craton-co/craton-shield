// Copyright 2026 Craton Software Company
// SPDX-License-Identifier: Apache-2.0

//! Standalone example demonstrating `CoapMonitor` directly.
//!
//! This example creates a `CoAP` monitor with URI-based access rules and
//! method policies, then simulates several `CoAP` messages to show how
//! the monitor filters traffic based on URI prefix, allowed methods,
//! rate limits, and amplification detection.
//!
//! Run with:
//! ```sh
//! cargo run -p vs-coap-monitor --example coap_gateway
//! ```

use vs_coap_monitor::{AllowedMethods, CoapMonitor, UriAction};
use vs_types_embedded::{
    CoapMessage, CoapMessageType, CoapMethod, MAX_COAP_PAYLOAD_LEN, MAX_COAP_URI_LEN,
};

/// Helper to build a `CoapMessage` from a URI string and method.
fn make_coap_msg(uri: &str, method: CoapMethod, msg_type: CoapMessageType, id: u16) -> CoapMessage {
    let mut msg = CoapMessage {
        msg_type,
        method,
        message_id: id,
        token: [0u8; 8],
        token_len: 1,
        uri: [0u8; MAX_COAP_URI_LEN],
        uri_len: 0,
        payload: [0u8; MAX_COAP_PAYLOAD_LEN],
        payload_len: 0,
        timestamp_us: id as u64 * 1_000_000,
        ..CoapMessage::default()
    };
    let uri_bytes = uri.as_bytes();
    let len = uri_bytes.len().min(MAX_COAP_URI_LEN);
    msg.uri[..len].copy_from_slice(&uri_bytes[..len]);
    msg.uri_len = len as u8;
    msg.token[0] = id as u8;
    msg
}

fn main() {
    println!("=== Craton Shield - CoAP Gateway Monitor Example ===\n");

    // ── Create and configure the monitor ──────────────────────────────
    let mut monitor = CoapMonitor::new();

    // Allow GET only on /sensors/ prefix, rate limit 20 requests/sec
    let _ = monitor.add_rule(b"/sensors/", UriAction::Allow, AllowedMethods::GET_ONLY, 20);

    // Allow any method on /config/ prefix, rate limit 5 requests/sec
    let _ = monitor.add_rule(b"/config/", UriAction::Allow, AllowedMethods::ALL, 5);

    // Block all requests to /admin/ prefix
    let _ = monitor.add_rule(b"/admin/", UriAction::Block, AllowedMethods::NONE, 0);

    // Flag responses that are more than 10x larger than the request
    monitor.set_amplification_threshold(10);

    println!("Monitor configured:");
    println!("  /sensors/*  -> GET only, 20 req/s");
    println!("  /config/*   -> any method, 5 req/s");
    println!("  /admin/*    -> blocked");
    println!("  amplification threshold: 10x");
    println!();

    // ── Build simulated messages ──────────────────────────────────────
    let messages: Vec<(&str, CoapMessage)> = vec![
        (
            "GET /sensors/temp (should be allowed)",
            make_coap_msg(
                "/sensors/temp",
                CoapMethod::Get,
                CoapMessageType::Confirmable,
                1,
            ),
        ),
        (
            "PUT /sensors/temp (should be blocked - GET only)",
            make_coap_msg(
                "/sensors/temp",
                CoapMethod::Put,
                CoapMessageType::Confirmable,
                2,
            ),
        ),
        (
            "POST /config/update (should be allowed)",
            make_coap_msg(
                "/config/update",
                CoapMethod::Post,
                CoapMessageType::Confirmable,
                3,
            ),
        ),
        (
            "GET /admin/status (should be blocked)",
            make_coap_msg(
                "/admin/status",
                CoapMethod::Get,
                CoapMessageType::Confirmable,
                4,
            ),
        ),
        (
            "GET /unknown/path (should be allowed - no rule, default allow)",
            make_coap_msg(
                "/unknown/path",
                CoapMethod::Get,
                CoapMessageType::NonConfirmable,
                5,
            ),
        ),
    ];

    // ── Inspect each message ──────────────────────────────────────────
    println!("--- Inspecting CoAP messages ---\n");

    let mut total_alerts = 0u32;
    for (description, msg) in &messages {
        let result = monitor.inspect(msg);
        let status = if result.alert_count == 0 {
            "ALLOWED"
        } else {
            "ALERT"
        };
        println!("[{status}] {description}");
        for i in 0..result.alert_count as usize {
            println!("         -> {:?}", result.alerts[i]);
        }
        total_alerts += result.alert_count as u32;
    }

    // ── Summary ───────────────────────────────────────────────────────
    println!();
    println!("--- Summary ---");
    println!("Total inspected : {}", messages.len());
    println!("Total alerts    : {total_alerts}");
    println!();
    println!("=== Done ===");
}
