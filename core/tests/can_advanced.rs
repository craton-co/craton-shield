// SPDX-License-Identifier: Apache-2.0
//! Integration tests for CAN monitor allowlist and replay detection features.

mod common;
use common::{exact_id_rule, make_can_frame};
use vs_can_monitor::CanMonitor;
use vs_types::AlertSeverity;

// ===========================================================================
// Allowlist tests
// ===========================================================================

#[test]
fn allowlist_blocks_unknown_id() {
    let mut can = CanMonitor::default();
    can.allow_id(0x100).expect("allow_id should succeed");
    assert!(
        can.allowlist_enabled(),
        "allowlist should be enabled after adding an ID"
    );

    let frame = make_can_frame(0x200, 8, &[0x01; 8]);
    let alert = can.process_frame(&frame, 1_000_000);
    assert!(
        alert.is_some(),
        "unknown ID 0x200 must be blocked by allowlist"
    );
    assert_eq!(
        alert.expect("allowlist alert should be present").severity,
        AlertSeverity::High
    );
}

#[test]
fn allowlist_permits_known_id() {
    let mut can = CanMonitor::default();
    can.allow_id(0x100).expect("allow_id should succeed");

    let frame = make_can_frame(0x100, 8, &[0x01; 8]);
    assert!(
        can.process_frame(&frame, 1_000_000).is_none(),
        "allowed ID 0x100 should not generate an alert"
    );
}

#[test]
fn allowlist_disabled_by_default() {
    let mut can = CanMonitor::default();
    assert!(
        !can.allowlist_enabled(),
        "allowlist should be disabled on a fresh CanMonitor"
    );

    // With no allowlist, any frame should pass (no rules configured either).
    let frame = make_can_frame(0x123, 4, &[0xDE, 0xAD, 0xBE, 0xEF]);
    assert!(
        can.process_frame(&frame, 1_000_000).is_none(),
        "frame should pass when allowlist is disabled and no rules are set"
    );
}

#[test]
fn allowlist_multiple_ids() {
    let mut can = CanMonitor::default();
    can.allow_id(0x100).expect("allow 0x100");
    can.allow_id(0x200).expect("allow 0x200");
    can.allow_id(0x300).expect("allow 0x300");

    // All three allowed IDs should pass without alert.
    let ts_gap = 1_000_000;
    assert!(can
        .process_frame(&make_can_frame(0x100, 8, &[0x01; 8]), ts_gap)
        .is_none());
    assert!(can
        .process_frame(&make_can_frame(0x200, 8, &[0x02; 8]), ts_gap * 2)
        .is_none());
    assert!(can
        .process_frame(&make_can_frame(0x300, 8, &[0x03; 8]), ts_gap * 3)
        .is_none());

    // ID 0x400 is NOT in the allowlist — must generate an alert.
    let alert = can.process_frame(&make_can_frame(0x400, 8, &[0x04; 8]), ts_gap * 4);
    assert!(alert.is_some(), "ID 0x400 must be blocked by allowlist");
    assert_eq!(
        alert.expect("allowlist alert for 0x400").severity,
        AlertSeverity::High
    );
}

#[test]
fn allowlist_and_rule_combined() {
    let mut can = CanMonitor::default();

    // Allow only ID 0x100.
    can.allow_id(0x100).expect("allow 0x100");

    // Add a flood rule for 0x100 with min_interval 10_000 us.
    can.add_rule(exact_id_rule(0x100, 10_000, 8))
        .expect("add flood rule for 0x100");

    // Frame with ID 0x200 should be blocked by the allowlist before any rule
    // evaluation takes place.
    let alert = can.process_frame(&make_can_frame(0x200, 8, &[0xAA; 8]), 1_000_000);
    assert!(
        alert.is_some(),
        "ID 0x200 must be blocked by allowlist even with no rule for it"
    );
    assert_eq!(
        alert.expect("allowlist block alert").severity,
        AlertSeverity::High
    );

    // Now send two rapid frames with allowed ID 0x100 — the first seeds the
    // timestamp, the second (only 1_000 us later) triggers the flood rule.
    let frame_100 = make_can_frame(0x100, 8, &[0xBB; 8]);
    assert!(
        can.process_frame(&frame_100, 2_000_000).is_none(),
        "first frame with allowed ID 0x100 should pass"
    );

    let flood_alert = can.process_frame(&frame_100, 2_001_000);
    assert!(
        flood_alert.is_some(),
        "second rapid frame with ID 0x100 must trigger flood rule"
    );
    assert_eq!(
        flood_alert.expect("flood alert").severity,
        AlertSeverity::High
    );
}

// ===========================================================================
// Replay detection tests
// ===========================================================================

#[test]
fn replay_detection_triggers_on_third_repeat() {
    let mut can = CanMonitor::default();
    let frame = make_can_frame(0x500, 4, &[0xAA; 4]);

    // 1st frame — first seen, no alert.
    assert!(
        can.process_frame(&frame, 1_000_000).is_none(),
        "first occurrence should not trigger replay"
    );

    // 2nd frame — repeat_count=2, below threshold (3).
    assert!(
        can.process_frame(&frame, 2_000_000).is_none(),
        "second occurrence should not trigger replay"
    );

    // 3rd frame — repeat_count=3, replay alert fires.
    let alert = can.process_frame(&frame, 3_000_000);
    assert!(
        alert.is_some(),
        "third identical frame must trigger replay alert"
    );
    assert_eq!(alert.expect("replay alert").severity, AlertSeverity::Medium);
}

#[test]
fn replay_detection_resets_on_different_payload() {
    let mut can = CanMonitor::default();

    let payload_a = [0xAA; 4];
    let payload_b = [0xBB; 4];

    // Send payload_a twice for ID 0x500.
    assert!(can
        .process_frame(&make_can_frame(0x500, 4, &payload_a), 1_000_000)
        .is_none());
    assert!(can
        .process_frame(&make_can_frame(0x500, 4, &payload_a), 2_000_000)
        .is_none());

    // Now send a different payload — this resets the replay counter.
    assert!(can
        .process_frame(&make_can_frame(0x500, 4, &payload_b), 3_000_000)
        .is_none());

    // Send payload_a again twice — counter has been reset, so these are
    // occurrences 1 and 2 for this new run. Neither should trigger replay.
    assert!(
        can.process_frame(&make_can_frame(0x500, 4, &payload_a), 4_000_000)
            .is_none(),
        "first repeat after reset should not trigger replay"
    );
    assert!(
        can.process_frame(&make_can_frame(0x500, 4, &payload_a), 5_000_000)
            .is_none(),
        "second repeat after reset should not trigger replay"
    );
}

#[test]
fn replay_different_ids_independent() {
    let mut can = CanMonitor::default();
    let payload = [0xCC; 4];

    // Send same payload 3 times for ID 0x500 — triggers replay.
    assert!(can
        .process_frame(&make_can_frame(0x500, 4, &payload), 1_000_000)
        .is_none());
    assert!(can
        .process_frame(&make_can_frame(0x500, 4, &payload), 2_000_000)
        .is_none());
    let alert_500 = can.process_frame(&make_can_frame(0x500, 4, &payload), 3_000_000);
    assert!(alert_500.is_some(), "replay must trigger for ID 0x500");
    assert_eq!(
        alert_500.expect("replay alert for 0x500").severity,
        AlertSeverity::Medium
    );

    // Now send the same payload 3 times for ID 0x600 — independent tracker,
    // should also trigger on the third repeat.
    assert!(can
        .process_frame(&make_can_frame(0x600, 4, &payload), 4_000_000)
        .is_none());
    assert!(can
        .process_frame(&make_can_frame(0x600, 4, &payload), 5_000_000)
        .is_none());
    let alert_600 = can.process_frame(&make_can_frame(0x600, 4, &payload), 6_000_000);
    assert!(
        alert_600.is_some(),
        "replay must trigger independently for ID 0x600"
    );
    assert_eq!(
        alert_600.expect("replay alert for 0x600").severity,
        AlertSeverity::Medium
    );
}

#[test]
fn replay_reset_after_flood_detection() {
    let mut can = CanMonitor::default();

    // Add a flood rule for 0x100: min_interval = 10_000 us.
    can.add_rule(exact_id_rule(0x100, 10_000, 8))
        .expect("add flood rule for 0x100");

    let frame = make_can_frame(0x100, 8, &[0xDD; 8]);

    // First frame seeds the timestamp — no alert.
    assert!(can.process_frame(&frame, 1_000_000).is_none());

    // Second frame only 1_000 us later — flood detected.  This also resets
    // the replay counter for ID 0x100.
    let flood_alert = can.process_frame(&frame, 1_001_000);
    assert!(flood_alert.is_some(), "flood must be detected");
    assert_eq!(
        flood_alert.expect("flood alert").severity,
        AlertSeverity::High
    );

    // After the flood reset, send the same payload 3 more times with large
    // intervals (no flood).  The replay counter should start from scratch,
    // so the replay alert fires on the 3rd additional repeat.
    assert!(
        can.process_frame(&frame, 2_000_000).is_none(),
        "1st frame after flood reset should not trigger replay"
    );
    assert!(
        can.process_frame(&frame, 3_000_000).is_none(),
        "2nd frame after flood reset should not trigger replay"
    );
    let replay_alert = can.process_frame(&frame, 4_000_000);
    assert!(
        replay_alert.is_some(),
        "3rd frame after flood reset must trigger replay alert"
    );
    assert_eq!(
        replay_alert
            .expect("replay alert after flood reset")
            .severity,
        AlertSeverity::Medium
    );
}
