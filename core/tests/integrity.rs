// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the integrity monitor (`vs_integrity`).

mod common;

use vs_integrity::{IntegrityMonitor, IntegrityResult, IntegrityStatus, MonitorSnapshot};
use vs_types::VsError;

use common::make_crypto;

#[test]
fn integrity_register_and_verify_ok() {
    let mut monitor = IntegrityMonitor::new(make_crypto());
    let data = b"firmware data here";
    monitor
        .register_region(1, 0x0800_0000, data)
        .expect("register region");
    let result = monitor
        .verify_region(1, 0x0800_0000, data)
        .expect("verify region");
    assert_eq!(result.status, IntegrityStatus::Ok);
}

#[test]
fn integrity_tampered_data_detected() {
    let mut monitor = IntegrityMonitor::new(make_crypto());
    let original = b"original firmware payload";
    monitor
        .register_region(1, 0x0800_0000, original)
        .expect("register region");
    let result = monitor
        .verify_region(1, 0x0800_0000, b"TAMPERED firmware payload")
        .expect("verify region");
    assert_eq!(result.status, IntegrityStatus::Tampered);
}

#[test]
fn integrity_unknown_region() {
    let mut monitor = IntegrityMonitor::new(make_crypto());
    let result = monitor.verify_region(99, 0x1000, b"data");
    assert_eq!(result, Err(VsError::NotFound));
}

#[test]
fn integrity_unregister_region() {
    let mut monitor = IntegrityMonitor::new(make_crypto());
    let data = b"some region data";
    monitor
        .register_region(1, 0x0800_0000, data)
        .expect("register region");
    monitor.unregister_region(1).expect("unregister region");
    let result = monitor.verify_region(1, 0x0800_0000, data);
    assert!(result.is_err(), "verify after unregister should fail");
}

#[test]
fn integrity_update_baseline() {
    let mut monitor = IntegrityMonitor::new(make_crypto());
    let old_data = b"old firmware data";
    let new_data = b"new firmware data";

    monitor
        .register_region(1, 0x0800_0000, old_data)
        .expect("register region");
    monitor
        .update_baseline(1, new_data, None)
        .expect("update baseline");

    let result = monitor
        .verify_region(1, 0x0800_0000, new_data)
        .expect("verify with new data");
    assert_eq!(result.status, IntegrityStatus::Ok);

    let result = monitor
        .verify_region(1, 0x0800_0000, old_data)
        .expect("verify with old data");
    assert_eq!(result.status, IntegrityStatus::Tampered);
}

#[test]
fn integrity_verify_all() {
    let mut monitor = IntegrityMonitor::new(make_crypto());
    let data1 = b"region one data here";
    let data2 = b"region two data here";
    let data3 = b"region three data!!";

    monitor
        .register_region(1, 0x1000, data1)
        .expect("register 1");
    monitor
        .register_region(2, 0x2000, data2)
        .expect("register 2");
    monitor
        .register_region(3, 0x3000, data3)
        .expect("register 3");

    let mut results = [IntegrityResult {
        region_id: 0,
        status: IntegrityStatus::Unavailable,
    }; 8];

    let count = monitor
        .verify_all(
            |id, _base_addr, _length| match id {
                1 => Some(data1.as_slice()),
                2 => Some(data2.as_slice()),
                3 => Some(data3.as_slice()),
                _ => None,
            },
            &mut results,
        )
        .expect("verify_all");

    assert_eq!(count, 3);
    for result in &results[..3] {
        assert_eq!(
            result.status,
            IntegrityStatus::Ok,
            "region {} should be Ok",
            result.region_id
        );
    }
}

#[test]
fn integrity_verify_all_with_tampered() {
    let mut monitor = IntegrityMonitor::new(make_crypto());
    let data1 = b"region one content";
    let data2 = b"region two content";
    let data3 = b"region three content";

    monitor
        .register_region(1, 0x1000, data1)
        .expect("register 1");
    monitor
        .register_region(2, 0x2000, data2)
        .expect("register 2");
    monitor
        .register_region(3, 0x3000, data3)
        .expect("register 3");

    let mut results = [IntegrityResult {
        region_id: 0,
        status: IntegrityStatus::Unavailable,
    }; 8];

    let count = monitor
        .verify_all(
            |id, _base_addr, _length| match id {
                1 => Some(data1.as_slice()),
                2 => Some(b"WRONG data for region 2".as_slice()),
                3 => Some(data3.as_slice()),
                _ => None,
            },
            &mut results,
        )
        .expect("verify_all");

    assert_eq!(count, 3);

    for result in &results[..3] {
        if result.region_id == 2 {
            assert_eq!(
                result.status,
                IntegrityStatus::Tampered,
                "region 2 should be Tampered"
            );
        } else {
            assert_eq!(
                result.status,
                IntegrityStatus::Ok,
                "region {} should be Ok",
                result.region_id
            );
        }
    }
}

#[test]
fn integrity_measurement_count() {
    let mut monitor = IntegrityMonitor::new(make_crypto());
    let data = b"measurement counter test data";
    monitor
        .register_region(1, 0x0800_0000, data)
        .expect("register region");

    monitor
        .verify_region(1, 0x0800_0000, data)
        .expect("verify 1");
    monitor
        .verify_region(1, 0x0800_0000, data)
        .expect("verify 2");
    monitor
        .verify_region(1, 0x0800_0000, data)
        .expect("verify 3");

    assert_eq!(monitor.measurement_count(), 3);
}

#[test]
fn integrity_region_capacity() {
    let mut monitor = IntegrityMonitor::new(make_crypto());

    let (used, max) = monitor.region_capacity();
    assert_eq!(used, 0);
    assert_eq!(max, 64);

    monitor
        .register_region(1, 0x1000, b"data")
        .expect("register region");

    let (used, max) = monitor.region_capacity();
    assert_eq!(used, 1);
    assert_eq!(max, 64);
    assert_eq!(monitor.active_region_count(), 1);
}

#[test]
fn integrity_duplicate_region_id() {
    let mut monitor = IntegrityMonitor::new(make_crypto());
    monitor
        .register_region(1, 0x1000, b"first region")
        .expect("register first");

    let result = monitor.register_region(1, 0x2000, b"second region");
    assert!(
        result.is_err(),
        "registering duplicate region id should fail"
    );
}

#[test]
fn integrity_monitor_snapshot_round_trip() {
    let mut monitor = IntegrityMonitor::new(make_crypto());

    // Register two regions.
    let data1 = b"snapshot region one data";
    let data2 = b"snapshot region two data";
    monitor
        .register_region(10, 0x1000, data1)
        .expect("register region 10");
    monitor
        .register_region(20, 0x2000, data2)
        .expect("register region 20");

    // Verify both regions to advance last_verified_epoch / measurement counter.
    monitor
        .verify_region(10, 0x1000, data1)
        .expect("verify region 10");
    monitor
        .verify_region(20, 0x2000, data2)
        .expect("verify region 20");

    let original_region_count = monitor.active_region_count();
    let original_measurement_count = monitor.measurement_count();

    // Take a snapshot.
    let snapshot: MonitorSnapshot = monitor.snapshot().expect("snapshot");

    // Restore from snapshot into a fresh monitor.
    let mut restored = IntegrityMonitor::from_snapshot(snapshot, make_crypto())
        .expect("from_snapshot should succeed");

    // Active region count must match.
    assert_eq!(
        restored.active_region_count(),
        original_region_count,
        "active_region_count should survive snapshot round-trip"
    );

    // Measurement count must match.
    assert_eq!(
        restored.measurement_count(),
        original_measurement_count,
        "measurement_count should survive snapshot round-trip"
    );

    // Individual regions must still pass verification.
    let result1 = restored
        .verify_region(10, 0x1000, data1)
        .expect("verify region 10 after restore");
    assert_eq!(
        result1.status,
        IntegrityStatus::Ok,
        "region 10 should be Ok after restore"
    );

    let result2 = restored
        .verify_region(20, 0x2000, data2)
        .expect("verify region 20 after restore");
    assert_eq!(
        result2.status,
        IntegrityStatus::Ok,
        "region 20 should be Ok after restore"
    );
}
