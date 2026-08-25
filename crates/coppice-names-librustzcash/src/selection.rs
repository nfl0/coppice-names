use coppice::bond_tag::derive_v1_bond_tag;

use crate::inventory::{InventoryError, IronwoodViewingCapability, OwnedIronwoodNote};

/// The result of pure bond-note selection for a new registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedBondNote {
    pub output_id: crate::IronwoodOutputId,
    pub value_zat: u64,
    pub bond_tag: [u8; 32],
    pub position: u32,
}

/// Controls whether bond selection may consume more than the deployment's
/// minimum bond value.
///
/// The default is intentionally exact-minimum selection. A wallet may opt in
/// to [`BondNoteSelectionPolicy::AllowLarger`] when the user has explicitly
/// chosen to bond a larger note.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BondNoteSelectionPolicy {
    #[default]
    ExactMinimum,
    AllowLarger,
}

/// The adapter-level action needed to obtain a bond note without silently
/// reserving a larger note than the minimum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BondNotePreparation {
    /// An eligible exact-minimum note is already available.
    Existing(SelectedBondNote),
    /// No exact-minimum note is available; a normal self-send may split this
    /// explicitly selected larger eligible note into a minimum bond and
    /// ordinary change.
    Split(SelectedBondNote),
}

/// Registration-specific freshness supplied by the future witness/chain
/// adapter.
///
/// The floor is derived outside this crate from the canonical Ironwood and
/// Coppice history for the prospective COMMIT context. Raw wallet inventory
/// must not guess it from wallet birthday, mined height, or local note age.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreshnessEligibility {
    pub position_floor: u32,
}

impl FreshnessEligibility {
    pub const fn new(position_floor: u32) -> Self {
        Self { position_floor }
    }

    fn accepts(self, note: &OwnedIronwoodNote) -> bool {
        note.position
            .is_some_and(|position| position >= self.position_floor)
    }
}

/// Selects an eligible exact-minimum note.
///
/// Larger-note selection is available only through
/// [`select_bond_note_with_policy`]. Existing active locks, including a
/// Coppice reservation, are not reusable for a new registration.
pub fn select_bond_note(
    notes: &[OwnedIronwoodNote],
    minimum_bond_value: u64,
    capability: IronwoodViewingCapability,
    freshness: FreshnessEligibility,
) -> Result<Option<SelectedBondNote>, InventoryError> {
    select_bond_note_with_policy(
        notes,
        minimum_bond_value,
        capability,
        freshness,
        BondNoteSelectionPolicy::ExactMinimum,
    )
}

/// Selects an eligible bond note using an explicit larger-note policy.
///
/// Selection is ordered by `(value_zat, output_id)`, so equal-value notes do
/// not depend on wallet iteration order.
pub fn select_bond_note_with_policy(
    notes: &[OwnedIronwoodNote],
    minimum_bond_value: u64,
    capability: IronwoodViewingCapability,
    freshness: FreshnessEligibility,
    policy: BondNoteSelectionPolicy,
) -> Result<Option<SelectedBondNote>, InventoryError> {
    capability.require_nullifier_derivation()?;

    let mut selected: Option<SelectedBondNote> = None;
    for note in notes.iter().copied().filter(|note| {
        let value_eligible = match policy {
            BondNoteSelectionPolicy::ExactMinimum => note.value_zat == minimum_bond_value,
            BondNoteSelectionPolicy::AllowLarger => note.value_zat >= minimum_bond_value,
        };
        value_eligible && note.spendable && freshness.accepts(note) && !note.locked
    }) {
        let Some(position) = note.position else {
            continue;
        };
        let bond_tag = derive_v1_bond_tag(&note.nullifier).map_err(|source| {
            InventoryError::NonCanonicalNullifier {
                output_id: note.output_id,
                source,
            }
        })?;
        let candidate = SelectedBondNote {
            output_id: note.output_id,
            value_zat: note.value_zat,
            bond_tag,
            position,
        };
        if selected
            .map(|current| {
                (candidate.value_zat, candidate.output_id) < (current.value_zat, current.output_id)
            })
            .unwrap_or(true)
        {
            selected = Some(candidate);
        }
    }
    Ok(selected)
}

/// Reports whether the wallet already has an exact-minimum bond note or
/// whether an explicit self-send preparation can split the smallest eligible
/// larger note.
pub fn prepare_bond_note(
    notes: &[OwnedIronwoodNote],
    minimum_bond_value: u64,
    capability: IronwoodViewingCapability,
    freshness: FreshnessEligibility,
) -> Result<Option<BondNotePreparation>, InventoryError> {
    if let Some(note) = select_bond_note(notes, minimum_bond_value, capability, freshness)? {
        return Ok(Some(BondNotePreparation::Existing(note)));
    }

    Ok(select_bond_note_with_policy(
        notes,
        minimum_bond_value,
        capability,
        freshness,
        BondNoteSelectionPolicy::AllowLarger,
    )?
    .map(BondNotePreparation::Split))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IronwoodOutputId;

    fn note(
        id: u8,
        value_zat: u64,
        locked: bool,
        spendable: bool,
        position: Option<u32>,
    ) -> OwnedIronwoodNote {
        OwnedIronwoodNote {
            output_id: IronwoodOutputId::new([id; 32], u32::from(id)),
            value_zat,
            nullifier: [id; 32],
            position,
            locked,
            spendable,
        }
    }

    fn full_viewing() -> IronwoodViewingCapability {
        IronwoodViewingCapability::FullViewing
    }

    fn freshness(position_floor: u32) -> FreshnessEligibility {
        FreshnessEligibility::new(position_floor)
    }

    #[test]
    fn no_notes_and_all_below_minimum_have_no_candidate() {
        assert_eq!(
            select_bond_note(&[], 10, full_viewing(), freshness(0)).unwrap(),
            None
        );
        assert_eq!(
            select_bond_note(
                &[note(1, 9, false, true, Some(1))],
                10,
                full_viewing(),
                freshness(0),
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn default_selection_requires_exact_minimum() {
        let notes = [
            note(1, 100, false, true, Some(1)),
            note(2, 20, false, true, Some(2)),
            note(3, 10, false, true, Some(3)),
        ];
        let selected = select_bond_note(&notes, 10, full_viewing(), freshness(0))
            .unwrap()
            .unwrap();
        assert_eq!(selected.output_id, notes[2].output_id);
        assert_eq!(selected.value_zat, 10);
    }

    #[test]
    fn larger_selection_requires_explicit_policy() {
        let notes = [
            note(1, 100, false, true, Some(1)),
            note(2, 20, false, true, Some(2)),
        ];
        assert_eq!(
            select_bond_note(&notes, 10, full_viewing(), freshness(0)).unwrap(),
            None
        );
        let selected = select_bond_note_with_policy(
            &notes,
            10,
            full_viewing(),
            freshness(0),
            BondNoteSelectionPolicy::AllowLarger,
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.output_id, notes[1].output_id);
        assert_eq!(selected.value_zat, 20);
    }

    #[test]
    fn preparation_prefers_exact_note_over_split() {
        let exact = note(1, 10, false, true, Some(1));
        let larger = note(2, 20, false, true, Some(2));
        assert_eq!(
            prepare_bond_note(&[larger, exact], 10, full_viewing(), freshness(0)).unwrap(),
            Some(BondNotePreparation::Existing(SelectedBondNote {
                output_id: exact.output_id,
                value_zat: 10,
                bond_tag: derive_v1_bond_tag(&[1; 32]).unwrap(),
                position: 1,
            }))
        );
    }

    #[test]
    fn preparation_selects_larger_note_for_explicit_split() {
        let larger = note(2, 20, false, true, Some(2));
        assert_eq!(
            prepare_bond_note(&[larger], 10, full_viewing(), freshness(0)).unwrap(),
            Some(BondNotePreparation::Split(SelectedBondNote {
                output_id: larger.output_id,
                value_zat: 20,
                bond_tag: derive_v1_bond_tag(&[2; 32]).unwrap(),
                position: 2,
            }))
        );
    }

    #[test]
    fn equal_value_selection_uses_output_id_tie_break() {
        let first = note(2, 10, false, true, Some(2));
        let second = note(1, 10, false, true, Some(1));
        let selected = select_bond_note(&[first, second], 10, full_viewing(), freshness(0))
            .unwrap()
            .unwrap();
        assert_eq!(selected.output_id, second.output_id);
    }

    #[test]
    fn excludes_foreign_and_existing_coppice_locks() {
        let foreign = note(1, 10, true, true, Some(1));
        let coppice = note(2, 11, true, true, Some(2));
        assert_eq!(
            select_bond_note(&[foreign, coppice], 10, full_viewing(), freshness(0)).unwrap(),
            None
        );
    }

    #[test]
    fn preparation_ignores_locked_ineligible_and_insufficient_notes() {
        let notes = [
            note(1, 10, true, true, Some(1)),
            note(2, 20, false, false, Some(2)),
            note(3, 9, false, true, Some(3)),
        ];
        assert_eq!(
            prepare_bond_note(&notes, 10, full_viewing(), freshness(0)).unwrap(),
            None
        );
    }

    #[test]
    fn excludes_unavailable_and_freshness_ineligible_notes() {
        let notes = [
            note(1, 10, false, false, Some(1)),
            note(2, 11, false, true, Some(0)),
        ];
        assert_eq!(
            select_bond_note(&notes, 10, full_viewing(), freshness(1)).unwrap(),
            None
        );
    }

    #[test]
    fn exact_minimum_is_accepted_and_tag_is_canonical_v1_derivation() {
        let selected = select_bond_note(
            &[note(7, 10, false, true, Some(7))],
            10,
            full_viewing(),
            freshness(7),
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.value_zat, 10);
        assert_eq!(
            selected.bond_tag,
            coppice::bond_tag::derive_v1_bond_tag(&[7; 32]).unwrap()
        );
    }

    #[test]
    fn incoming_only_fails_explicitly_even_with_no_candidates() {
        assert_eq!(
            select_bond_note(
                &[],
                10,
                IronwoodViewingCapability::IncomingOnly,
                freshness(0),
            ),
            Err(InventoryError::InsufficientViewingCapability)
        );
    }

    #[test]
    fn output_id_order_is_independent_of_input_order() {
        let reversed = vec![
            note(2, 10, false, true, Some(2)),
            note(1, 10, false, true, Some(1)),
        ];
        let selected = select_bond_note(&reversed, 10, full_viewing(), freshness(0))
            .unwrap()
            .unwrap();
        assert_eq!(selected.output_id, IronwoodOutputId::new([1; 32], 1));
    }

    #[test]
    fn freshness_uses_explicit_position_floor() {
        let at_floor = note(1, 10, false, true, Some(7));
        let below_floor = note(2, 10, false, true, Some(6));
        let missing = note(3, 10, false, true, None);

        let selected = select_bond_note(
            &[below_floor, missing, at_floor],
            10,
            full_viewing(),
            freshness(7),
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.output_id, at_floor.output_id);
        assert_eq!(selected.position, 7);
    }
}
