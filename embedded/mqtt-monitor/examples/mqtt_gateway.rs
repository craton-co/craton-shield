// Copyright 2026 Craton Software Company
// SPDX-License-Identifier: Apache-2.0

//! Standalone MQTT monitor example.
//!
//! Demonstrates configuring and using `MqttMonitor` directly, without the
//! full `EmbeddedShield` runtime (which requires a `CryptoProvider`).
//!
//! Run with:
//! ```bash
//! cargo run -p vs-mqtt-monitor --example mqtt_gateway
//! ```

use vs_mqtt_monitor::{MqttMonitor, QosPolicy, TopicAction};
use vs_types_embedded::{MqttMessage, MqttPacketType, MqttQoS};

fn main() {
    let mut monitor = MqttMonitor::new();

    // Allow sensor telemetry with rate limiting (10 msgs/sec).
    let shadowed = monitor
        .add_rule(b"sensors/#", TopicAction::Allow, QosPolicy::Any, 10)
        .expect("add sensors rule");
    if shadowed > 0 {
        println!("Warning: {shadowed} shadowed rule(s) detected");
    }

    // Critical topics require QoS >= 1.
    let _shadowed = monitor
        .add_rule(
            b"critical/#",
            TopicAction::Allow,
            QosPolicy::MinQoS(MqttQoS::AtLeastOnce),
            0,
        )
        .expect("add critical rule");

    // Block all admin topics.
    let _shadowed = monitor
        .add_rule(b"admin/#", TopicAction::Block, QosPolicy::Any, 0)
        .expect("add admin rule");

    // Detect connect storms: 5 connects within 60 seconds.
    monitor.set_connect_storm_params(5, 60_000_000);

    // --- Simulate incoming messages ---
    let messages: &[(&[u8], MqttPacketType, MqttQoS)] = &[
        (
            b"sensors/temp",
            MqttPacketType::Publish,
            MqttQoS::AtMostOnce,
        ),
        (
            b"sensors/humidity",
            MqttPacketType::Publish,
            MqttQoS::AtLeastOnce,
        ),
        (
            b"admin/config",
            MqttPacketType::Publish,
            MqttQoS::AtMostOnce,
        ),
        (
            b"critical/alarm",
            MqttPacketType::Publish,
            MqttQoS::AtMostOnce,
        ),
        (
            b"critical/alarm",
            MqttPacketType::Publish,
            MqttQoS::AtLeastOnce,
        ),
    ];

    for (i, (topic, pkt_type, qos)) in messages.iter().enumerate() {
        let mut msg = MqttMessage::default();
        msg.packet_type = *pkt_type;
        msg.topic[..topic.len()].copy_from_slice(topic);
        msg.topic_len = topic.len() as u8;
        msg.qos = *qos;
        msg.timestamp_us = (i as u64 + 1) * 1_000_000;

        let result = monitor.inspect(&msg);
        let topic_str = core::str::from_utf8(topic).unwrap_or("<invalid>");

        println!(
            "[{}] topic={:<25} qos={} => allowed={}, alerts={}",
            i + 1,
            topic_str,
            *qos as u8,
            result.allowed,
            result.alert_count,
        );
    }

    println!("\nTotal inspected: {}", monitor.total_inspected());
    println!("Total alerts:    {}", monitor.total_alerts());
}
