//! Canonical action views and operation envelopes for Names v2.

use super::{
    registration::{CommitRef, RegistrationIntent, ReplacementRef},
    state::{NameId, ProducerPosition, StateData, StateRef},
};
use coppice::application::{ApplicationBlockContext, ApplicationTransactionContext};
use coppice::replay::CoreTransactionContext;
use serde::{Deserialize, Serialize};

/// The operation codes used by the Names v2 state-note circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationKind {
    /// Changes the canonical record while preserving the lease.
    Update,
    /// Renews the lease at a deterministic name-derived slot.
    Renew,
    /// Ends the active lineage explicitly.
    Release,
}

impl OperationKind {
    /// Returns the circuit operation code.
    pub const fn code(self) -> u8 {
        match self {
            Self::Update => orchard::circuit::state_note_binding::OPERATION_UPDATE,
            Self::Renew => orchard::circuit::state_note_binding::OPERATION_RENEW,
            Self::Release => orchard::circuit::state_note_binding::OPERATION_RELEASE,
        }
    }
}

/// A typed pair of canonical Ironwood effects from one action index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IronwoodActionRef {
    /// Canonical action index in the transaction.
    pub action_index: u32,
    /// Canonical predecessor nullifier at this action index.
    pub nullifier: [u8; 32],
    /// Canonical successor commitment at this action index.
    pub commitment: [u8; 32],
}

/// Errors while constructing an action view from generic Core effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionViewError {
    /// Core’s parallel effect arrays do not describe one action per index.
    MismatchedEffectLengths,
    /// A supplied action index is not its canonical zero-based array index.
    NonCanonicalIndex,
    /// The effect arrays contain more actions than the v2 index type can name.
    TooManyActions,
}

impl IronwoodActionRef {
    /// Zips the existing Core arrays into an application-side typed action view.
    ///
    /// Core has already validated each array and, for a full transaction, its
    /// exact canonical action order. The length check prevents an application
    /// from ever pairing a nullifier with a commitment from a different index.
    pub fn from_core_transaction(
        transaction: &CoreTransactionContext,
    ) -> Result<Vec<Self>, ActionViewError> {
        let effects = transaction.ironwood_effects();
        let nullifiers = effects.nullifiers();
        let commitments = effects.commitments();
        if nullifiers.len() != commitments.len() {
            return Err(ActionViewError::MismatchedEffectLengths);
        }
        nullifiers
            .iter()
            .copied()
            .zip(commitments.iter().copied())
            .enumerate()
            .map(|(action_index, (nullifier, commitment))| {
                Ok(Self {
                    action_index: u32::try_from(action_index)
                        .map_err(|_| ActionViewError::TooManyActions)?,
                    nullifier,
                    commitment,
                })
            })
            .collect()
    }

    /// Returns the action at one exact canonical index.
    pub fn at(actions: &[Self], action_index: u32) -> Option<Self> {
        actions
            .iter()
            .copied()
            .find(|action| action.action_index == action_index)
    }
}

/// A Names v2 operation carried by a canonical transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum V2Operation {
    /// Hidden registration intent committed before maturity.
    Commit {
        /// The hidden commitment value.
        commitment: [u8; 32],
    },
    /// Matures a COMMIT and creates the first state-note lineage head.
    Reveal {
        /// The disclosed intent.
        intent: Box<RegistrationIntent>,
        /// Exact earlier COMMIT position and value.
        commit: CommitRef,
        /// Previous terminal head when reclaiming a name; `None` for first use.
        replacement_predecessor: ReplacementRef,
        /// Initial state values.
        state: StateData,
        /// Commitment created by the REVEAL Ironwood action.
        state_commitment: [u8; 32],
        /// Future nullifier of the created state note.
        state_nullifier: [u8; 32],
        /// Exact action whose commitment is `state_commitment`.
        action_index: u32,
        /// Names v2 genesis state-note proof.
        proof: Vec<u8>,
    },
    /// Arbitrary-height record update.
    Update {
        /// Exact current state head being spent.
        predecessor: StateRef,
        /// Successor state values.
        state: StateData,
        /// Commitment created by this action.
        state_commitment: [u8; 32],
        /// Future nullifier of the created state note.
        state_nullifier: [u8; 32],
        /// Exact action whose commitment is `state_commitment`.
        action_index: u32,
        /// Names v2 transition proof.
        proof: Vec<u8>,
    },
    /// Deterministic-slot lease renewal.
    Renew {
        /// Exact current state head being spent.
        predecessor: StateRef,
        /// Successor state values.
        state: StateData,
        /// Commitment created by this action.
        state_commitment: [u8; 32],
        /// Future nullifier of the created state note.
        state_nullifier: [u8; 32],
        /// Exact action whose commitment is `state_commitment`.
        action_index: u32,
        /// Names v2 transition proof.
        proof: Vec<u8>,
    },
    /// Explicit terminal release.
    Release {
        /// Exact current state head being spent.
        predecessor: StateRef,
        /// Terminal successor state values.
        state: StateData,
        /// Commitment created by this action.
        state_commitment: [u8; 32],
        /// Future nullifier of the created terminal state note.
        state_nullifier: [u8; 32],
        /// Exact action whose commitment is `state_commitment`.
        action_index: u32,
        /// Names v2 transition proof.
        proof: Vec<u8>,
    },
}

impl V2Operation {
    /// Returns the state operation kind, if this is a state operation.
    pub const fn kind(&self) -> Option<OperationKind> {
        match self {
            Self::Commit { .. } | Self::Reveal { .. } => None,
            Self::Update { .. } => Some(OperationKind::Update),
            Self::Renew { .. } => Some(OperationKind::Renew),
            Self::Release { .. } => Some(OperationKind::Release),
        }
    }

    /// Returns the operation’s exact action index, if it consumes/creates one.
    pub const fn action_index(&self) -> Option<u32> {
        match self {
            Self::Commit { .. } => None,
            Self::Reveal { action_index, .. }
            | Self::Update { action_index, .. }
            | Self::Renew { action_index, .. }
            | Self::Release { action_index, .. } => Some(*action_index),
        }
    }

    /// Returns the name identifier carried by the operation.
    pub fn name_id(&self) -> Option<NameId> {
        match self {
            Self::Commit { .. } => None,
            Self::Reveal { intent, .. } => intent.name_id().ok(),
            Self::Update { state, .. }
            | Self::Renew { state, .. }
            | Self::Release { state, .. } => Some(state.name_id),
        }
    }

    /// Returns the output state commitment, if this operation creates one.
    pub const fn state_commitment(&self) -> Option<[u8; 32]> {
        match self {
            Self::Commit { .. } => None,
            Self::Reveal {
                state_commitment, ..
            }
            | Self::Update {
                state_commitment, ..
            }
            | Self::Renew {
                state_commitment, ..
            }
            | Self::Release {
                state_commitment, ..
            } => Some(*state_commitment),
        }
    }

    /// Returns the authenticated future nullifier of the output state note.
    pub const fn state_nullifier(&self) -> Option<[u8; 32]> {
        match self {
            Self::Commit { .. } => None,
            Self::Reveal {
                state_nullifier, ..
            }
            | Self::Update {
                state_nullifier, ..
            }
            | Self::Renew {
                state_nullifier, ..
            }
            | Self::Release {
                state_nullifier, ..
            } => Some(*state_nullifier),
        }
    }
}

/// Canonical transaction data required by the v2 application.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalTransaction {
    /// Canonical transaction index.
    pub tx_index: u32,
    /// Canonical transaction identifier.
    pub txid: [u8; 32],
    /// Ordered Ironwood effects from Core.
    pub actions: Vec<IronwoodActionRef>,
    /// v2 operations in canonical carrier order.
    pub operations: Vec<V2Operation>,
}

impl CanonicalTransaction {
    /// Adapts the ordinary application-scoped Core context into the v2 replay
    /// view. Malformed v2 payloads contribute no typed messages; their
    /// canonical Ironwood effects remain visible for current-note spend
    /// detection.
    pub fn from_application_context(
        transaction: &ApplicationTransactionContext,
    ) -> Result<Self, ActionViewError> {
        let core = transaction.core();
        Ok(Self {
            tx_index: core.tx_index(),
            txid: core.txid(),
            actions: IronwoodActionRef::from_core_transaction(core)?,
            operations: transaction
                .payload()
                .and_then(|payload| super::wire::decode_operations(payload).ok())
                .unwrap_or_default(),
        })
    }
    /// Returns this transaction’s canonical producer position at a height.
    pub const fn position(&self, height: u32) -> ProducerPosition {
        ProducerPosition::new(height, self.tx_index, self.txid)
    }

    /// Returns the exact action pair selected by an application operation.
    pub fn action(&self, action_index: u32) -> Option<IronwoodActionRef> {
        IronwoodActionRef::at(&self.actions, action_index)
    }

    /// Checks that carrier operations do not reorder canonical action indices.
    pub fn has_canonical_operation_order(&self) -> bool {
        operations_have_canonical_order(&self.operations)
    }

    /// Returns true when `operation_index` is the first carrier message in
    /// this transaction that claims its selected Ironwood action.
    ///
    /// Action ownership is deliberately structural: an earlier malformed or
    /// proof-invalid state operation still reserves the action for the rest
    /// of its transaction. This keeps acceptance locally decidable from the
    /// transaction itself and avoids replaying unrelated names.
    pub fn is_first_action_claim(&self, operation_index: usize) -> bool {
        let Some(action_index) = self
            .operations
            .get(operation_index)
            .and_then(V2Operation::action_index)
        else {
            return true;
        };
        !self.operations[..operation_index]
            .iter()
            .any(|operation| operation.action_index() == Some(action_index))
    }
}

pub(super) fn operations_have_canonical_order(operations: &[V2Operation]) -> bool {
    operations
        .windows(2)
        .all(|pair| operation_order_key(&pair[0]) <= operation_order_key(&pair[1]))
}

fn operation_order_key(operation: &V2Operation) -> (u8, u32) {
    match operation.action_index() {
        None => (0, 0),
        Some(action_index) => (1, action_index),
    }
}

/// One canonical block body supplied by ordinary Coppice/Zcash acquisition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalBlock {
    /// Canonical block height.
    pub height: u32,
    /// Canonical block hash.
    pub block_hash: [u8; 32],
    /// Canonical predecessor block hash.
    pub prev_block_hash: [u8; 32],
    /// Transactions in canonical transaction order.
    pub transactions: Vec<CanonicalTransaction>,
}

impl CanonicalBlock {
    /// Returns the tip represented by this block.
    pub const fn tip(&self) -> ChainTip {
        ChainTip {
            height: self.height,
            block_hash: self.block_hash,
        }
    }

    /// Adapts one ordinary application-scoped canonical block without a
    /// Names-specific RPC or provider index.
    pub fn from_application_context(
        block: &ApplicationBlockContext,
    ) -> Result<Option<Self>, ActionViewError> {
        let Some(core) = block.core() else {
            return Ok(None);
        };
        let transactions = block
            .transactions()
            .iter()
            .map(CanonicalTransaction::from_application_context)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(Self {
            height: core.height(),
            block_hash: core.block_hash(),
            prev_block_hash: core.prev_block_hash(),
            transactions,
        }))
    }
}

/// A canonical chain tip used by the state machine and resolver.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainTip {
    /// Tip height.
    pub height: u32,
    /// Tip hash.
    pub block_hash: [u8; 32],
}
