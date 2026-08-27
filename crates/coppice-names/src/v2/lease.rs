//! Deterministic v2 lease and reclaimability rules.

use super::{state::StateData, state::StateError, state::StateStatus};

/// Errors from experimental v2 protocol-parameter validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseParameterError {
    /// The schedule would have no slots.
    ZeroEpochSize,
    /// The activation height is not representable as an active chain start.
    ZeroActivationHeight,
    /// A commitment could expire before the next name-derived reveal slot.
    CommitTtlTooShort,
    /// A lease could expire before a name reaches its next scheduled anchor.
    LeaseDurationTooShort,
    /// A grace or reuse interval of zero is not used by this experiment.
    ZeroTerminalInterval,
    /// A checked parameter sum overflowed u32.
    ArithmeticOverflow,
}

/// The v2 constants that affect schedule, registration, and lease semantics.
///
/// These values are experimental and are intentionally not a deployment
/// identity or a replacement for the frozen v1 `DeploymentParameters`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V2Parameters {
    /// First height at which v2 operations may be accepted.
    pub activation_height: u32,
    /// Number of blocks in one deterministic anchor epoch.
    pub epoch_size: u32,
    /// Inclusive COMMIT-to-REVEAL lifetime in blocks.
    pub commit_ttl_blocks: u32,
    /// Lease length measured from the accepted REVEAL or RENEW height.
    pub lease_duration_blocks: u32,
    /// Grace interval after lease expiry before a name is reclaimable.
    pub grace_period_blocks: u32,
    /// Delay after explicit RELEASE before a name is reclaimable.
    pub reuse_delay_blocks: u32,
    /// Maximum canonical record size used by the v2 state encoding.
    pub max_record_bytes: usize,
}

impl V2Parameters {
    /// A small deterministic fixture policy used by focused unit tests.
    pub const fn testing() -> Self {
        Self {
            activation_height: 1,
            epoch_size: 8,
            commit_ttl_blocks: 15,
            lease_duration_blocks: 32,
            grace_period_blocks: 3,
            reuse_delay_blocks: 4,
            max_record_bytes: super::state::MAX_RECORD_BYTES,
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
        if self.grace_period_blocks == 0 || self.reuse_delay_blocks == 0 {
            return Err(LeaseParameterError::ZeroTerminalInterval);
        }
        if self.max_anchor_gap()? > self.commit_ttl_blocks {
            return Err(LeaseParameterError::CommitTtlTooShort);
        }
        if self.lease_duration_blocks <= self.max_anchor_gap()? {
            return Err(LeaseParameterError::LeaseDurationTooShort);
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

    /// Classifies a state at a canonical height.
    pub fn lifecycle(self, state: &StateData, height: u32) -> Lifecycle {
        match state.status {
            StateStatus::Active if height < state.lease_expiry => Lifecycle::Active,
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

    /// Validates that a state has the expected v2 representation limits.
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
    /// The state is no longer payable but still blocks replacement.
    Grace,
    /// The state can be replaced by a valid COMMIT/REVEAL.
    Claimable,
    /// An explicitly released state waiting for its reuse delay.
    Released,
}
