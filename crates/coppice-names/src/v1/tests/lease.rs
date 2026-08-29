use super::*;

#[test]
fn reset_horizon_covers_active_and_latest_possible_release() {
    let params = V1Parameters::testing();
    let anchor = 100;
    let horizon = params.reset_horizon().unwrap();
    assert_eq!(horizon, 35);
    assert_eq!(params.lease_expiry(anchor), Some(132));
    assert_eq!(
        params.claimable_from(StateStatus::Active, 132, 0),
        Some(anchor + horizon)
    );
    // RELEASE is valid through height 131, and its delay also ends at
    // the same reset boundary for the test constants.
    assert_eq!(
        params.claimable_from(StateStatus::Released, 132, 131),
        Some(anchor + horizon)
    );
}

#[test]
fn payable_window_is_separate_from_lease_lifetime() {
    let params = V1Parameters::testing();
    assert_eq!(params.max_anchor_gap().unwrap(), 15);
    assert_eq!(params.max_anchor_age().unwrap(), 15);
    assert_eq!(params.max_two_slot_gap().unwrap(), 23);
    assert!(params.lease_duration_blocks > params.max_two_slot_gap().unwrap());
}
