//! Deterministic, name-derived REVEAL/RENEW anchor opportunities.

use super::{lease::V2Parameters, state::NameId};

/// Returns the one slot offset selected for a name in an epoch.
pub fn slot_offset(name_id: NameId, epoch: u64, epoch_size: u32) -> u32 {
    assert!(epoch_size > 0, "a schedule needs at least one slot");
    let mut input = Vec::with_capacity(32 + 8);
    input.extend_from_slice(&name_id);
    input.extend_from_slice(&epoch.to_be_bytes());
    let hash = super::state::hash_bytes("CoppiceN2Slot", &input);
    let value = u64::from_le_bytes(hash[..8].try_into().expect("slot hash prefix"));
    (value % u64::from(epoch_size)) as u32
}

/// Returns the canonical anchor height for a name and epoch.
pub fn slot_height(name_id: NameId, epoch: u64, params: V2Parameters) -> Option<u32> {
    let base = epoch.checked_mul(u64::from(params.epoch_size))?;
    let height = base.checked_add(u64::from(slot_offset(name_id, epoch, params.epoch_size)))?;
    u32::try_from(height).ok()
}

/// Returns whether a height is the scheduled opportunity for this name.
pub fn is_anchor_height(name_id: NameId, height: u32, params: V2Parameters) -> bool {
    if params.epoch_size == 0 || height < params.activation_height {
        return false;
    }
    let epoch = u64::from(height / params.epoch_size);
    slot_height(name_id, epoch, params) == Some(height)
}

/// Derives every candidate slot in an inclusive anchor-age window, oldest
/// first. `maximum_age` is an age, not a count of blocks.
pub fn candidate_anchor_heights_with_age(
    name_id: NameId,
    tip_height: u32,
    params: V2Parameters,
    maximum_age: u32,
) -> Vec<u32> {
    let lower = tip_height.saturating_sub(maximum_age);
    let first_epoch = u64::from(lower / params.epoch_size.max(1));
    let last_epoch = u64::from(tip_height / params.epoch_size.max(1));
    let mut result = Vec::new();
    for epoch in first_epoch..=last_epoch {
        if let Some(height) = slot_height(name_id, epoch, params)
            && (params.activation_height..=tip_height).contains(&height)
            && height >= lower
        {
            result.push(height);
        }
    }
    result
}

/// Derives scheduled anchors that can still make a state payable at the tip.
pub fn fresh_candidate_anchor_heights(
    name_id: NameId,
    tip_height: u32,
    params: V2Parameters,
) -> Vec<u32> {
    let Ok(max_age) = params.max_anchor_age() else {
        return Vec::new();
    };
    candidate_anchor_heights_with_age(name_id, tip_height, params, max_age)
}

/// Derives scheduled anchors whose resulting lineage could still affect a
/// no-predecessor COMMIT at the tip.
pub fn reset_candidate_anchor_heights(
    name_id: NameId,
    height: u32,
    params: V2Parameters,
) -> Vec<u32> {
    let Ok(horizon) = params.reset_horizon() else {
        return Vec::new();
    };
    candidate_anchor_heights_with_age(name_id, height, params, horizon)
}

/// Backward-compatible test helper for the schedule's physical slot gap.
pub fn candidate_anchor_heights(
    name_id: NameId,
    tip_height: u32,
    params: V2Parameters,
) -> Vec<u32> {
    let Ok(max_gap) = params.max_anchor_gap() else {
        return Vec::new();
    };
    candidate_anchor_heights_with_age(name_id, tip_height, params, max_gap)
}

/// Computes the next scheduled slot at or after a height.
pub fn next_anchor_height(name_id: NameId, from_height: u32, params: V2Parameters) -> Option<u32> {
    if params.epoch_size == 0 {
        return None;
    }
    let mut epoch = u64::from(from_height / params.epoch_size.max(1));
    for _ in 0..=2 {
        let height = slot_height(name_id, epoch, params)?;
        if height >= from_height && height >= params.activation_height {
            return Some(height);
        }
        epoch = epoch.checked_add(1)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_names_can_share_a_slot_without_sharing_state() {
        let params = V2Parameters::testing();
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
        let params = V2Parameters::testing();
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
}
