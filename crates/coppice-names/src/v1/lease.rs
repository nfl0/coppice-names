//! Deterministic v1 lease and reclaimability rules.

use super::{state::StateData, state::StateError, state::StateStatus};
use serde::{Deserialize, Serialize};

/// Errors from Names v1 protocol-parameter validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseParameterError {
    /// The schedule would have no slots.
    ZeroEpochSize,
    /// The activation height is not representable as an active chain start.
    ZeroActivationHeight,
    /// An empty machine was initialized at or after its activation height.
    InitialTipAfterActivation,
    /// A commitment has no post-COMMIT block in which it can be revealed.
    CommitTtlTooShort,
    /// A lease could expire before a name reaches its next scheduled anchor.
    LeaseDurationTooShort,
    /// A payable state could outlive the window in which a fresh resolver
    /// probes its deterministic anchors.
    RefreshDeadlineTooShort,
    /// A grace or reuse interval of zero is not used by Names v1.
    ZeroTerminalInterval,
    /// A zero-value state note cannot serve as a bond.
    ZeroMinimumBond,
    /// A checked parameter sum overflowed u32.
    ArithmeticOverflow,
}

/// The v1 constants that affect schedule, registration, and lease semantics.
///
/// These values are explicit protocol parameters and are intentionally kept
/// separate from generic Coppice runtime configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V1Parameters {
    /// First height at which v1 operations may be accepted.
    pub activation_height: u32,
    /// Number of blocks in one deterministic anchor epoch.
    pub epoch_size: u32,
    /// Inclusive COMMIT-to-REVEAL lifetime in blocks.
    pub commit_ttl_blocks: u32,
    /// Exclusive age at which an anchor stops making a state payable.
    ///
    /// This is deliberately independent from the longer lease lifetime. A
    /// missed slot therefore makes a record stale without immediately taking
    /// the name away from its owner.
    pub refresh_deadline_blocks: u32,
    /// Lease length measured from the accepted REVEAL or RENEW height.
    pub lease_duration_blocks: u32,
    /// Grace interval after lease expiry before a name is reclaimable.
    pub grace_period_blocks: u32,
    /// Delay after explicit RELEASE before a name is reclaimable.
    pub reuse_delay_blocks: u32,
    /// Maximum canonical record size used by the v1 state encoding.
    pub max_record_bytes: usize,
    /// Minimum value, in zatoshis, carried by every state note.
    pub minimum_bond_zatoshis: u64,
}

impl V1Parameters {
    /// A small deterministic fixture policy used by focused unit tests.
    pub const fn testing() -> Self {
        Self {
            activation_height: 1,
            epoch_size: 8,
            commit_ttl_blocks: 15,
            refresh_deadline_blocks: 16,
            lease_duration_blocks: 32,
            grace_period_blocks: 3,
            reuse_delay_blocks: 4,
            max_record_bytes: super::state::MAX_RECORD_BYTES,
            minimum_bond_zatoshis: 1,
        }
    }

    /// Validates arithmetic and the discovery guarantees implied by the policy.
    pub fn validate(self) -> Result<(), LeaseParameterError> {
        if self.activation_height == 0 {
            return Err(LeaseParameterError::ZeroActivationHeight);
        }
        if self.epoch_size == 0 {
            return Err(LeaseParameterError::ZeroEpochSize);
        }
        if self.commit_ttl_blocks == 0 {
            return Err(LeaseParameterError::CommitTtlTooShort);
        }
        if self.grace_period_blocks == 0 || self.reuse_delay_blocks == 0 {
            return Err(LeaseParameterError::ZeroTerminalInterval);
        }
        if self.minimum_bond_zatoshis == 0 {
            return Err(LeaseParameterError::ZeroMinimumBond);
        }
        if self.refresh_deadline_blocks == 0
            || self.refresh_deadline_blocks >= self.lease_duration_blocks
        {
            return Err(LeaseParameterError::RefreshDeadlineTooShort);
        }
        self.lease_expiry(self.activation_height)
            .ok_or(LeaseParameterError::ArithmeticOverflow)?;
        self.activation_height
            .checked_add(self.grace_period_blocks)
            .and_then(|value| value.checked_add(self.reuse_delay_blocks))
            .ok_or(LeaseParameterError::ArithmeticOverflow)?;
        Ok(())
    }

    /// The formal maximum gap between consecutive scheduled slots.
    ///
    /// For one slot per epoch, the offset can move from the beginning of one
    /// epoch to the end of the next, so the gap is `2 * epoch_size - 1`, not
    /// `epoch_size`.
    pub fn max_anchor_gap(self) -> Result<u32, LeaseParameterError> {
        self.epoch_size
            .checked_mul(2)
            .and_then(|value| value.checked_sub(1))
            .ok_or(LeaseParameterError::ArithmeticOverflow)
    }

    /// The largest distance from one anchor to the second following scheduled
    /// opportunity. For `s_e = eE + o_e`, this is
    /// `s_(e+2) - s_e <= 3E - 1`.
    pub fn max_two_slot_gap(self) -> Result<u32, LeaseParameterError> {
        self.epoch_size
            .checked_mul(3)
            .and_then(|value| value.checked_sub(1))
            .ok_or(LeaseParameterError::ArithmeticOverflow)
    }

    /// Returns the inclusive maximum age of a payable anchor.
    ///
    /// An anchor at `a` is fresh at exactly the integer heights in
    /// `[a, a + refresh_deadline_blocks)`, so its maximum age is
    /// `refresh_deadline_blocks - 1`.
    pub fn max_anchor_age(self) -> Result<u32, LeaseParameterError> {
        self.refresh_deadline_blocks
            .checked_sub(1)
            .ok_or(LeaseParameterError::RefreshDeadlineTooShort)
    }

    /// Recovers an anchor height from the deterministic lease encoding.
    pub fn anchor_height(self, lease_expiry: u32) -> Option<u32> {
        lease_expiry.checked_sub(self.lease_duration_blocks)
    }

    /// First height at which an active state may be renewed.
    pub fn renewal_opening(self, lease_expiry: u32) -> Option<u32> {
        lease_expiry.checked_sub(self.refresh_deadline_blocks)
    }

    /// Returns whether an active state has a current discovery anchor.
    pub fn is_fresh(self, state: &StateData, height: u32) -> bool {
        state.status == StateStatus::Active
            && self
                .anchor_height(state.lease_expiry)
                .and_then(|anchor| anchor.checked_add(self.refresh_deadline_blocks))
                .is_some_and(|deadline| height < deadline)
    }

    /// Maximum lookback after which an old accepted anchor cannot block a
    /// no-predecessor registration at height `C`.
    ///
    /// Active/grace state becomes claimable no later than `a + D + G`, because
    /// unmatched-spend abandonment is capped at that ordinary boundary. A
    /// release can be accepted only through `a + D - 1` and then blocks through
    /// `a + D - 1 + R`. The greater of those two exclusive claimability
    /// points is the reset horizon.
    pub fn reset_horizon(self) -> Result<u32, LeaseParameterError> {
        let active = self
            .lease_duration_blocks
            .checked_add(self.grace_period_blocks)
            .ok_or(LeaseParameterError::ArithmeticOverflow)?;
        let released = self
            .lease_duration_blocks
            .checked_sub(1)
            .and_then(|value| value.checked_add(self.reuse_delay_blocks))
            .ok_or(LeaseParameterError::ArithmeticOverflow)?;
        Ok(active.max(released))
    }

    /// Computes an exclusive lease expiry for an accepted anchor.
    pub fn lease_expiry(self, anchor_height: u32) -> Option<u32> {
        anchor_height.checked_add(self.lease_duration_blocks)
    }

    /// Returns the claimability height for a terminal state.
    pub fn claimable_from(
        self,
        status: StateStatus,
        lease_expiry: u32,
        terminal_height: u32,
    ) -> Option<u32> {
        match status {
            StateStatus::Active => lease_expiry.checked_add(self.grace_period_blocks),
            StateStatus::Released => terminal_height.checked_add(self.reuse_delay_blocks),
        }
    }

    /// Returns the claimability height for a replayed state head.
    ///
    /// An unmatched spend makes an active state non-payable immediately, but
    /// cannot extend its ordinary lease-and-grace lifetime. Released terminal
    /// states retain their explicit release boundary.
    pub fn head_claimable_from(
        self,
        state: &StateData,
        abandoned_height: Option<u32>,
    ) -> Option<u32> {
        let ordinary =
            self.claimable_from(state.status, state.lease_expiry, state.terminal_height)?;
        match (state.status, abandoned_height) {
            (StateStatus::Active, Some(height)) => height
                .checked_add(self.reuse_delay_blocks)
                .map(|abandoned| abandoned.min(ordinary)),
            _ => Some(ordinary),
        }
    }

    /// Classifies a state at a canonical height.
    pub fn lifecycle(self, state: &StateData, height: u32) -> Lifecycle {
        match state.status {
            StateStatus::Active if height < state.lease_expiry && self.is_fresh(state, height) => {
                Lifecycle::Active
            }
            StateStatus::Active if height < state.lease_expiry => Lifecycle::Stale,
            StateStatus::Active => {
                let claimable = self
                    .claimable_from(state.status, state.lease_expiry, state.terminal_height)
                    .unwrap_or(u32::MAX);
                if height < claimable {
                    Lifecycle::Grace
                } else {
                    Lifecycle::Claimable
                }
            }
            StateStatus::Released => {
                let claimable = self
                    .claimable_from(state.status, state.lease_expiry, state.terminal_height)
                    .unwrap_or(u32::MAX);
                if height < claimable {
                    Lifecycle::Released
                } else {
                    Lifecycle::Claimable
                }
            }
        }
    }

    /// Validates that a state has the expected v1 representation limits.
    pub fn validate_state(self, state: &StateData) -> Result<(), StateError> {
        state.validate()?;
        if state.record.len() > self.max_record_bytes {
            return Err(StateError::RecordTooLarge);
        }
        Ok(())
    }
}

/// A state’s lifecycle at a particular canonical height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lifecycle {
    /// The state is payable and can be updated, renewed, or released.
    Active,
    /// The lease still belongs to the owner, but its last anchor is too old
    /// to resolve/pay. A scheduled RENEW can recover it before lease expiry.
    Stale,
    /// The state is no longer payable but still blocks replacement.
    Grace,
    /// The state can be replaced by a valid COMMIT/REVEAL.
    Claimable,
    /// An explicitly released state waiting for its reuse delay.
    Released,
}

#[cfg(test)]
#[path = "tests/lease.rs"]
mod tests;
