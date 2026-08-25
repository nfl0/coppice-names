use std::{collections::BTreeSet, fmt::Debug};

use coppice::{
    bond_tag::{BondTagError, derive_v1_bond_tag},
    names_runtime::NamesRuntime,
    state::CoppiceState,
};
use zcash_client_backend::wallet::OutputRef;
use zcash_protocol::{PoolType, TxId};

/// An ephemeral Ironwood output identity used by adapter operations.
///
/// This is intentionally absent from [`crate::PendingRegistration`]. A later
/// wallet backend can convert it to its native `OutputRef` whenever it needs
/// to inspect or mutate output-lock state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IronwoodOutputId {
    txid: [u8; 32],
    output_index: u32,
}

impl IronwoodOutputId {
    pub const fn new(txid: [u8; 32], output_index: u32) -> Self {
        Self { txid, output_index }
    }

    pub const fn txid(self) -> [u8; 32] {
        self.txid
    }

    pub const fn output_index(self) -> u32 {
        self.output_index
    }

    /// Converts this adapter-owned identity to the pinned public wallet API's
    /// output reference type.
    pub fn as_output_ref(self) -> OutputRef {
        OutputRef::new(
            TxId::from_bytes(self.txid),
            PoolType::IRONWOOD,
            self.output_index,
        )
    }
}

/// Wallet viewing authority relevant to local bond reconstruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IronwoodViewingCapability {
    /// A full viewing key can derive note nullifiers.
    FullViewing,
    /// A spending capability also includes the required viewing authority.
    Spending,
    /// An incoming-only key cannot derive the nullifier mapping required here.
    IncomingOnly,
}

/// Supplies wallet-owned, unspent Ironwood notes to the adapter.
///
/// A concrete implementation over the pinned librustzcash [`InputSource`]
/// must enumerate with `LockFilter::Unfiltered`. The default
/// `LockedInputPolicy::Exclude` is suitable for ordinary input selection, but
/// is not sufficient for reconstructing Coppice reservations: reconciliation
/// must see outputs that are already locked. The concrete implementation also
/// supplies the account, target height, and note decryption/nullifier
/// derivation needed to build [`OwnedIronwoodNote`] values. Registration
/// freshness is deliberately not part of this inventory boundary; it depends
/// on the prospective COMMIT context and is supplied to bond-note selection
/// separately.
///
/// [`InputSource`]: zcash_client_backend::data_api::InputSource
pub trait OwnedIronwoodNoteSource {
    type Error: Debug;

    fn owned_unspent_ironwood_notes(&self) -> Result<Vec<OwnedIronwoodNote>, Self::Error>;
}

impl IronwoodViewingCapability {
    pub(crate) fn require_nullifier_derivation(self) -> Result<(), InventoryError> {
        match self {
            Self::FullViewing | Self::Spending => Ok(()),
            Self::IncomingOnly => Err(InventoryError::InsufficientViewingCapability),
        }
    }
}

/// Wallet-owned, unspent Ironwood note facts required by Coppice.
///
/// The nullifier is assumed to have been derived locally by the wallet's
/// viewing capability. It is never sent to a remote service by this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedIronwoodNote {
    pub output_id: IronwoodOutputId,
    pub value_zat: u64,
    pub nullifier: [u8; 32],
    pub position: Option<u32>,
    /// Whether the note is currently locked at the wallet's selection target.
    pub locked: bool,
    /// Whether the host wallet considers the note spendable for a new use.
    pub spendable: bool,
}

/// An owned live canonical Coppice bond reconstructed from a note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedBond {
    pub output_id: IronwoodOutputId,
    pub value_zat: u64,
    pub position: Option<u32>,
    pub bond_tag: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InventoryError {
    InsufficientViewingCapability,
    NonCanonicalNullifier {
        output_id: IronwoodOutputId,
        source: BondTagError,
    },
}

#[derive(Clone, Copy)]
pub(crate) struct ClassifiedNote {
    pub(crate) note: OwnedIronwoodNote,
    pub(crate) bond_tag: [u8; 32],
}

pub(crate) fn classify_notes(
    notes: &[OwnedIronwoodNote],
    capability: IronwoodViewingCapability,
) -> Result<Vec<ClassifiedNote>, InventoryError> {
    capability.require_nullifier_derivation()?;

    let mut classified = notes
        .iter()
        .copied()
        .map(|note| {
            let bond_tag = derive_v1_bond_tag(&note.nullifier).map_err(|source| {
                InventoryError::NonCanonicalNullifier {
                    output_id: note.output_id,
                    source,
                }
            })?;
            Ok(ClassifiedNote { note, bond_tag })
        })
        .collect::<Result<Vec<_>, InventoryError>>()?;

    classified.sort_by_key(|classified| (classified.bond_tag, classified.note.output_id));
    Ok(classified)
}

/// Returns the canonical active bond tags from runtime state without exposing
/// runtime mutation or wallet state to the core crate.
pub fn active_canonical_bond_tags(runtime: &NamesRuntime) -> BTreeSet<[u8; 32]> {
    runtime
        .state()
        .active_bond_index()
        .keys()
        .copied()
        .collect()
}

/// Returns the canonical active bond tags from a read-only core state.
pub fn active_canonical_bond_tags_from_state(state: &CoppiceState) -> BTreeSet<[u8; 32]> {
    state.active_bond_index().keys().copied().collect()
}

/// Classifies wallet-owned unspent notes whose v1 bond tags are active in the
/// canonical Coppice state.
pub fn classify_owned_bonds(
    active_tags: &BTreeSet<[u8; 32]>,
    notes: &[OwnedIronwoodNote],
    capability: IronwoodViewingCapability,
) -> Result<Vec<OwnedBond>, InventoryError> {
    classify_notes(notes, capability).map(|classified| {
        classified
            .into_iter()
            .filter(|classified| active_tags.contains(&classified.bond_tag))
            .map(|classified| OwnedBond {
                output_id: classified.note.output_id,
                value_zat: classified.note.value_zat,
                position: classified.note.position,
                bond_tag: classified.bond_tag,
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(id: u8) -> OwnedIronwoodNote {
        OwnedIronwoodNote {
            output_id: IronwoodOutputId::new([id; 32], u32::from(id)),
            value_zat: u64::from(id),
            nullifier: [id; 32],
            position: Some(u32::from(id)),
            locked: true,
            spendable: false,
        }
    }

    fn tag(id: u8) -> [u8; 32] {
        derive_v1_bond_tag(&[id; 32]).unwrap()
    }

    #[test]
    fn owned_active_bonds_are_derived_and_sorted_without_using_foreign_tags() {
        let active_tags = BTreeSet::from([tag(2), tag(3)]);
        let bonds = classify_owned_bonds(
            &active_tags,
            &[note(3), note(1), note(2)],
            IronwoodViewingCapability::FullViewing,
        )
        .unwrap();
        assert_eq!(bonds.len(), 2);
        assert!(
            bonds
                .iter()
                .all(|bond| active_tags.contains(&bond.bond_tag))
        );
        assert_eq!(
            bonds.iter().map(|bond| bond.output_id).collect::<Vec<_>>(),
            {
                let mut expected = vec![note(2).output_id, note(3).output_id];
                expected.sort_by_key(|output_id| (tag(output_id.output_index() as u8), *output_id));
                expected
            }
        );
    }

    #[test]
    fn incoming_only_is_an_explicit_inventory_error() {
        assert_eq!(
            classify_owned_bonds(
                &BTreeSet::new(),
                &[],
                IronwoodViewingCapability::IncomingOnly,
            ),
            Err(InventoryError::InsufficientViewingCapability)
        );
    }

    #[test]
    fn active_tags_can_be_read_from_core_state_without_wallet_types() {
        use std::collections::BTreeMap;

        let mut names = BTreeMap::new();
        names.insert(
            "active".to_owned(),
            coppice::record::NameRecord {
                owner_pk: [1; 32],
                bond_tag: [2; 32],
                sequence: 0,
                address: Vec::new(),
                status: coppice::record::NameStatus::Active,
            },
        );
        names.insert(
            "terminal".to_owned(),
            coppice::record::NameRecord {
                owner_pk: [1; 32],
                bond_tag: [3; 32],
                sequence: 1,
                address: Vec::new(),
                status: coppice::record::NameStatus::Released {
                    terminal_height: 10,
                },
            },
        );
        let state = CoppiceState::from_authoritative_parts(
            names,
            coppice::pending::PendingCommitments::new(),
            coppice::recent_spent::RecentSpent::new(),
        )
        .unwrap();
        assert_eq!(
            active_canonical_bond_tags_from_state(&state),
            BTreeSet::from([[2; 32]])
        );
    }
}
