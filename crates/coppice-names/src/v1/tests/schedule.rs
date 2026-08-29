use super::*;

#[test]
fn different_names_can_share_a_slot_without_sharing_state() {
    let params = V1Parameters::testing();
    let first = super::super::state::name_id("name0").unwrap();
    let mut collision = None;
    for index in 1..256 {
        let candidate = super::super::state::name_id(&format!("name{index}")).unwrap();
        if candidate != first
            && slot_offset(first, 4, params.epoch_size)
                == slot_offset(candidate, 4, params.epoch_size)
        {
            collision = Some(candidate);
            break;
        }
    }
    let second = collision.expect("a 1/8 slot collision should be found quickly");
    assert_eq!(
        slot_height(first, 4, params),
        slot_height(second, 4, params)
    );
    assert!(is_anchor_height(
        first,
        slot_height(first, 4, params).unwrap(),
        params
    ));
    assert!(is_anchor_height(
        second,
        slot_height(second, 4, params).unwrap(),
        params
    ));
}

#[test]
fn name_grinding_changes_only_the_derived_slot() {
    let params = V1Parameters::testing();
    let first = super::super::state::name_id("grind-a").unwrap();
    let second = super::super::state::name_id("grind-b").unwrap();
    assert_ne!(first, second);
    assert_ne!(
        slot_offset(first, 7, params.epoch_size),
        slot_offset(second, 7, params.epoch_size)
    );
    assert!(is_anchor_height(
        first,
        slot_height(first, 7, params).unwrap(),
        params
    ));
    assert!(is_anchor_height(
        second,
        slot_height(second, 7, params).unwrap(),
        params
    ));
}

#[test]
fn second_following_opportunity_has_tight_three_epoch_bound() {
    for epoch_size in 1..64u32 {
        let mut maximum = 0;
        for first_offset in 0..epoch_size {
            for second_offset in 0..epoch_size {
                let gap = 2 * epoch_size + second_offset - first_offset;
                maximum = maximum.max(gap);
                assert!(gap <= 3 * epoch_size - 1);
            }
        }
        assert_eq!(maximum, 3 * epoch_size - 1);
    }
}
