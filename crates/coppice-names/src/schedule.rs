//! Height-only schedule and lifecycle arithmetic.

use crate::protocol::NameId;

/// Candidate deployment timing selected for current Ironwood spacing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub deployment_id: [u8; 32],
    pub activation_height: u32,
    pub epoch_blocks: u32,
    pub window_blocks: u32,
    pub commit_maturity_blocks: u32,
    pub commit_ttl_blocks: u32,
    pub lease_blocks: u32,
    pub cooldown_blocks: u32,
}

impl Parameters {
    pub const fn candidate(deployment_id: [u8; 32], activation_height: u32) -> Self {
        Self {
            deployment_id,
            activation_height,
            epoch_blocks: 1_152,
            window_blocks: 24,
            commit_maturity_blocks: 24,
            commit_ttl_blocks: 192,
            lease_blocks: 250_000,
            cooldown_blocks: 1_152,
        }
    }

    pub fn validate(self) -> Result<Self, ScheduleError> {
        if self.window_blocks == 0
            || self.window_blocks > self.commit_maturity_blocks
            || self.commit_maturity_blocks >= self.commit_ttl_blocks
            || self.commit_ttl_blocks >= self.epoch_blocks
            || self.lease_blocks <= self.epoch_blocks
            || self.cooldown_blocks != self.epoch_blocks
        {
            return Err(ScheduleError::InvalidParameters);
        }
        Ok(self)
    }

    pub fn epoch(self, height: u32) -> Result<u32, ScheduleError> {
        if height < self.activation_height {
            return Err(ScheduleError::BeforeActivation);
        }
        Ok((height - self.activation_height) / self.epoch_blocks)
    }

    pub fn window(self, name_id: NameId, epoch: u32) -> Result<Window, ScheduleError> {
        self.validate()?;
        let epoch_start = self
            .activation_height
            .checked_add(
                epoch
                    .checked_mul(self.epoch_blocks)
                    .ok_or(ScheduleError::Overflow)?,
            )
            .ok_or(ScheduleError::Overflow)?;
        let start = epoch_start
            .checked_add(self.offset(name_id))
            .ok_or(ScheduleError::Overflow)?;
        let end = start
            .checked_add(self.window_blocks)
            .ok_or(ScheduleError::Overflow)?;
        Ok(Window { start, end })
    }

    pub fn accepts_operation(self, name_id: NameId, height: u32) -> bool {
        self.epoch(height)
            .and_then(|epoch| self.window(name_id, epoch))
            .is_ok_and(|window| window.contains(height))
    }

    /// Returns nonempty operation windows intersecting `[start, end)`, newest
    /// first and clipped to the requested range.
    ///
    /// A resolver can scan compact action effects across its authenticated
    /// range while restricting name-route trial decryption and full-transaction
    /// acquisition to these windows. No candidate outside a returned window
    /// can be accepted by the protocol.
    pub fn operation_windows_descending(
        self,
        name_id: NameId,
        start: u32,
        end: u32,
    ) -> Result<Vec<Window>, ScheduleError> {
        self.validate()?;
        if start >= end {
            return Err(ScheduleError::InvalidRange);
        }
        let effective_start = start.max(self.activation_height);
        if effective_start >= end {
            return Ok(Vec::new());
        }
        let first_epoch = self.epoch(effective_start)?;
        let last_epoch = self.epoch(end - 1)?;
        let mut windows = Vec::new();
        for epoch in (first_epoch..=last_epoch).rev() {
            let window = self.window(name_id, epoch)?;
            let clipped = Window {
                start: window.start.max(effective_start),
                end: window.end.min(end),
            };
            if clipped.start < clipped.end {
                windows.push(clipped);
            }
        }
        Ok(windows)
    }

    pub fn accepts_commit(self, commit_height: u32, reveal_height: u32) -> bool {
        if commit_height < self.activation_height || reveal_height < commit_height {
            return false;
        }
        let age = reveal_height - commit_height;
        age >= self.commit_maturity_blocks && age < self.commit_ttl_blocks
    }

    pub fn expiry(self, producer_height: u32) -> Result<u32, ScheduleError> {
        producer_height
            .checked_add(self.lease_blocks)
            .ok_or(ScheduleError::Overflow)
    }

    pub fn claimable(self, terminal_height: u32) -> Result<u32, ScheduleError> {
        terminal_height
            .checked_add(self.cooldown_blocks)
            .ok_or(ScheduleError::Overflow)
    }

    fn offset(self, name_id: NameId) -> u32 {
        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(&self.deployment_id);
        input.extend_from_slice(&name_id.to_bytes());
        let digest = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"CoppiceN2Off")
            .hash(&input);
        let value = u64::from_le_bytes(digest.as_bytes()[..8].try_into().expect("eight bytes"));
        let span = self.epoch_blocks - self.window_blocks + 1;
        u32::try_from(value % u64::from(span)).expect("offset is below u32 span")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub start: u32,
    pub end: u32,
}

impl Window {
    pub const fn contains(self, height: u32) -> bool {
        self.start <= height && height < self.end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleError {
    InvalidParameters,
    InvalidRange,
    BeforeActivation,
    Overflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::NameId;

    fn synthetic() -> Parameters {
        Parameters::candidate(
            hex::decode("0f0a82a82d6645b74a7ae2fc86722440c8f1395993e5b3efdf566a8815ab1d5c")
                .unwrap()
                .try_into()
                .unwrap(),
            100_000,
        )
    }

    fn alice() -> NameId {
        NameId::from_bytes(
            hex::decode("b646f07d05366fb8127c706843da84c62e42eec3ba2e66af0188c20d0093710a")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn reviewed_window_and_half_open_boundaries_match() {
        let parameters = synthetic().validate().unwrap();
        assert_eq!(
            parameters.window(alice(), 17).unwrap(),
            Window {
                start: 120_080,
                end: 120_104
            }
        );
        assert!(parameters.accepts_operation(alice(), 120_080));
        assert!(parameters.accepts_operation(alice(), 120_103));
        assert!(!parameters.accepts_operation(alice(), 120_104));
    }

    #[test]
    fn maturity_ttl_expiry_and_cooldown_are_half_open() {
        let parameters = synthetic();
        assert!(!parameters.accepts_commit(120_000, 120_023));
        assert!(parameters.accepts_commit(120_000, 120_024));
        assert!(parameters.accepts_commit(120_000, 120_191));
        assert!(!parameters.accepts_commit(120_000, 120_192));
        assert_eq!(parameters.expiry(120_080), Ok(370_080));
        assert_eq!(parameters.claimable(370_080), Ok(371_232));
    }

    #[test]
    fn arithmetic_never_wraps() {
        let parameters = synthetic();
        assert_eq!(parameters.expiry(u32::MAX), Err(ScheduleError::Overflow));
        assert_eq!(parameters.claimable(u32::MAX), Err(ScheduleError::Overflow));
        assert_eq!(
            parameters.window(alice(), u32::MAX),
            Err(ScheduleError::Overflow)
        );
    }

    #[test]
    fn descending_acquisition_windows_are_clipped_and_complete() {
        let parameters = synthetic();
        let name_id = alice();
        let windows = parameters
            .operation_windows_descending(name_id, 120_090, 122_500)
            .unwrap();
        assert_eq!(windows.len(), 3);
        assert_eq!(
            windows[2],
            Window {
                start: 120_090,
                end: 120_104
            }
        );
        assert!(windows.windows(2).all(|pair| pair[0].start > pair[1].start));

        for height in 120_090..122_500 {
            assert_eq!(
                parameters.accepts_operation(name_id, height),
                windows.iter().any(|window| window.contains(height))
            );
        }
        assert_eq!(
            parameters.operation_windows_descending(name_id, 99_000, 100_000),
            Ok(Vec::new())
        );
        assert_eq!(
            parameters.operation_windows_descending(name_id, 100_000, 100_000),
            Err(ScheduleError::InvalidRange)
        );
    }
}
