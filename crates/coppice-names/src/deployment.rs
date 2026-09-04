//! Canonical proof-system and deployment identity derivation.

use crate::{
    names_application_id,
    protocol::{BOND_ZATOSHIS, MAX_NAME_BYTES, MAX_UA_BYTES},
    ruleset::ruleset_fingerprint,
    schedule::Parameters,
};
use coppice::identity::CoreRuntimeId;

/// CA01 application version of the replacement protocol.
pub const NAMES_APPLICATION_VERSION: u16 = 2;
/// Verifier-manifest encoding revision.
pub const VERIFIER_MANIFEST_REVISION: u8 = 1;
/// Verifier-suite manifest encoding revision.
pub const VERIFIER_SUITE_REVISION: u8 = 1;
/// Encoding revision for the canonical Names v2 deployment preimage.
pub const DEPLOYMENT_PREIMAGE_REVISION: u8 = 1;

const DEPLOYMENT_PERSONALIZATION: &[u8] = b"CoppiceN2Dep";
const REVEAL_VERIFIER_PERSONALIZATION: &[u8] = b"CoppiceN2ReVr";
const REFRESH_VERIFIER_PERSONALIZATION: &[u8] = b"CoppiceN2RfVr";
const VERIFIER_SUITE_PERSONALIZATION: &[u8] = b"CoppiceN2VrfS";

/// Exact verifier behavior selected by the first replacement deployment.
///
/// This manifest is deliberately independent of the Names circuit. The
/// circuit shape is committed by the generated-key fingerprint; this commits
/// the proof/transcript verifier that interprets it.
pub const VERIFIER_SUITE_MANIFEST: &[u8] = b"CNV2S\x01\
curve=VestaAffine;scalar=PallasBase;commitment=Halo2IPA;\
transcript=Blake2bRead+Blake2bWrite/Halo2-Transcript;challenge=Challenge255;\
strategy=SingleVerifier;proof_encoding=zakura-halo2-proofs-1.0.0-Blake2bWrite;\
zakura-halo2-proofs=1.0.0/7c1386cce49a4d9e4a1b1e32fbbb3ba34d23e53dcefd700ee976d736d72f302a;\
zakura-pasta-curves=1.0.0/9b11ea111779520b119485fdb0fd69c3ec96b6eaab0e1bfbfb3f9cb67c55815a";

/// One full proof-verifier identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierId([u8; 32]);

impl VerifierId {
    /// Returns the identity bytes.
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Immutable proof identities selected by one deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofIdentity {
    reveal: VerifierId,
    refresh: VerifierId,
    reveal_key_fingerprint: [u8; 32],
    refresh_key_fingerprint: [u8; 32],
    circuit_k: u8,
    reveal_proof_bytes: u16,
    refresh_proof_bytes: u16,
}

impl ProofIdentity {
    /// Derives both verifier identities from the exact proof configuration.
    pub fn derive(
        circuit_k: u8,
        reveal_proof_bytes: u16,
        refresh_proof_bytes: u16,
        reveal_key_fingerprint: [u8; 32],
        refresh_key_fingerprint: [u8; 32],
    ) -> Self {
        let suite = verifier_suite_id();
        Self {
            reveal: verifier_id(
                REVEAL_VERIFIER_PERSONALIZATION,
                1,
                suite,
                circuit_k,
                reveal_proof_bytes,
                reveal_key_fingerprint,
            ),
            refresh: verifier_id(
                REFRESH_VERIFIER_PERSONALIZATION,
                2,
                suite,
                circuit_k,
                refresh_proof_bytes,
                refresh_key_fingerprint,
            ),
            reveal_key_fingerprint,
            refresh_key_fingerprint,
            circuit_k,
            reveal_proof_bytes,
            refresh_proof_bytes,
        }
    }

    /// Returns the REVEAL verifier identity.
    pub const fn reveal(self) -> VerifierId {
        self.reveal
    }

    /// Returns the REFRESH verifier identity.
    pub const fn refresh(self) -> VerifierId {
        self.refresh
    }

    /// Returns the generated REVEAL key fingerprint.
    pub const fn reveal_key_fingerprint(self) -> [u8; 32] {
        self.reveal_key_fingerprint
    }

    /// Returns the generated REFRESH key fingerprint.
    pub const fn refresh_key_fingerprint(self) -> [u8; 32] {
        self.refresh_key_fingerprint
    }

    /// Returns the Halo2 parameter exponent.
    pub const fn circuit_k(self) -> u8 {
        self.circuit_k
    }

    /// Returns the fixed REVEAL proof length.
    pub const fn reveal_proof_bytes(self) -> u16 {
        self.reveal_proof_bytes
    }

    /// Returns the fixed REFRESH proof length.
    pub const fn refresh_proof_bytes(self) -> u16 {
        self.refresh_proof_bytes
    }
}

/// Inputs that canonically identify one Names deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeploymentParameters {
    pub core_runtime_id: CoreRuntimeId,
    pub activation_height: u32,
    pub epoch_blocks: u32,
    pub window_blocks: u32,
    pub commit_maturity_blocks: u32,
    pub commit_ttl_blocks: u32,
    pub lease_blocks: u32,
    pub cooldown_blocks: u32,
    pub ruleset_fingerprint: [u8; 32],
    pub proof: ProofIdentity,
}

/// A deployment identity or schedule input was malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeploymentError {
    InvalidSchedule,
    InvalidProofSize,
    RulesetMismatch,
}

impl DeploymentParameters {
    /// Builds the production-candidate deployment profile.
    pub fn candidate(
        core_runtime_id: CoreRuntimeId,
        activation_height: u32,
        proof: ProofIdentity,
    ) -> Self {
        let timing = Parameters::candidate([0; 32], activation_height);
        Self::with_timing(core_runtime_id, timing, proof)
    }

    /// Builds the accelerated local-Regtest deployment profile.
    ///
    /// Timing fields remain identity-bearing, so this profile cannot be
    /// confused with the production candidate even if every other input is
    /// identical.
    pub fn regtest(
        core_runtime_id: CoreRuntimeId,
        activation_height: u32,
        proof: ProofIdentity,
    ) -> Self {
        let timing = Parameters::regtest([0; 32], activation_height);
        Self::with_timing(core_runtime_id, timing, proof)
    }

    fn with_timing(
        core_runtime_id: CoreRuntimeId,
        timing: Parameters,
        proof: ProofIdentity,
    ) -> Self {
        Self {
            core_runtime_id,
            activation_height: timing.activation_height,
            epoch_blocks: timing.epoch_blocks,
            window_blocks: timing.window_blocks,
            commit_maturity_blocks: timing.commit_maturity_blocks,
            commit_ttl_blocks: timing.commit_ttl_blocks,
            lease_blocks: timing.lease_blocks,
            cooldown_blocks: timing.cooldown_blocks,
            ruleset_fingerprint: ruleset_fingerprint(),
            proof,
        }
    }

    /// Validates the identity-bearing parameters.
    pub fn validate(self) -> Result<Self, DeploymentError> {
        if usize::from(self.proof.reveal_proof_bytes) > crate::codec::MAX_REVEAL_PROOF_BYTES
            || usize::from(self.proof.refresh_proof_bytes) > crate::codec::MAX_REFRESH_PROOF_BYTES
        {
            return Err(DeploymentError::InvalidProofSize);
        }
        if self.ruleset_fingerprint != ruleset_fingerprint() {
            return Err(DeploymentError::RulesetMismatch);
        }
        self.schedule([1; 32])
            .validate()
            .map_err(|_| DeploymentError::InvalidSchedule)?;
        Ok(self)
    }

    /// Returns the exact 206-byte, big-endian deployment preimage.
    pub fn canonical_preimage(self) -> Result<[u8; 206], DeploymentError> {
        let validated = self.validate()?;
        let mut output = Vec::with_capacity(206);
        output.extend_from_slice(b"CND2");
        output.push(DEPLOYMENT_PREIMAGE_REVISION);
        output.extend_from_slice(validated.core_runtime_id.as_bytes());
        output.extend_from_slice(names_application_id().as_bytes());
        output.extend_from_slice(&NAMES_APPLICATION_VERSION.to_be_bytes());
        output.extend_from_slice(&validated.ruleset_fingerprint);
        output.extend_from_slice(&validated.activation_height.to_be_bytes());
        output.extend_from_slice(&validated.epoch_blocks.to_be_bytes());
        output.extend_from_slice(&validated.window_blocks.to_be_bytes());
        output.extend_from_slice(&validated.commit_maturity_blocks.to_be_bytes());
        output.extend_from_slice(&validated.commit_ttl_blocks.to_be_bytes());
        output.extend_from_slice(&validated.lease_blocks.to_be_bytes());
        output.extend_from_slice(&validated.cooldown_blocks.to_be_bytes());
        output.extend_from_slice(&BOND_ZATOSHIS.to_be_bytes());
        output.push(MAX_NAME_BYTES as u8);
        output.extend_from_slice(&(MAX_UA_BYTES as u16).to_be_bytes());
        output.extend_from_slice(&validated.proof.reveal.to_bytes());
        output.extend_from_slice(&validated.proof.refresh.to_bytes());
        Ok(output
            .try_into()
            .expect("deployment preimage length is fixed"))
    }

    /// Derives the Names deployment ID.
    pub fn deployment_id(self) -> Result<[u8; 32], DeploymentError> {
        Ok(hash32(
            DEPLOYMENT_PERSONALIZATION,
            &self.canonical_preimage()?,
        ))
    }

    /// Returns reducer schedule parameters bound to the supplied ID.
    pub const fn schedule(self, deployment_id: [u8; 32]) -> Parameters {
        Parameters {
            deployment_id,
            activation_height: self.activation_height,
            epoch_blocks: self.epoch_blocks,
            window_blocks: self.window_blocks,
            commit_maturity_blocks: self.commit_maturity_blocks,
            commit_ttl_blocks: self.commit_ttl_blocks,
            lease_blocks: self.lease_blocks,
            cooldown_blocks: self.cooldown_blocks,
        }
    }
}

/// Returns the identity of the frozen Halo2 IPA/Pasta verifier suite.
pub fn verifier_suite_id() -> [u8; 32] {
    hash32(VERIFIER_SUITE_PERSONALIZATION, VERIFIER_SUITE_MANIFEST)
}

fn verifier_id(
    personalization: &[u8],
    operation_tag: u8,
    suite_id: [u8; 32],
    circuit_k: u8,
    proof_bytes: u16,
    key_fingerprint: [u8; 32],
) -> VerifierId {
    let mut manifest = Vec::with_capacity(74);
    manifest.extend_from_slice(b"CNV2V");
    manifest.push(VERIFIER_MANIFEST_REVISION);
    manifest.push(operation_tag);
    manifest.extend_from_slice(&suite_id);
    manifest.push(circuit_k);
    manifest.extend_from_slice(&proof_bytes.to_be_bytes());
    manifest.extend_from_slice(&key_fingerprint);
    VerifierId(hash32(personalization, &manifest))
}

fn hash32(personalization: &[u8], input: &[u8]) -> [u8; 32] {
    blake2b_simd::Params::new()
        .hash_length(32)
        .personal(personalization)
        .hash(input)
        .as_bytes()
        .try_into()
        .expect("BLAKE2b-256 output")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deployment() -> DeploymentParameters {
        DeploymentParameters::candidate(
            CoreRuntimeId::from_bytes([3; 32]),
            100_000,
            ProofIdentity::derive(11, 4_704, 4_704, [1; 32], [2; 32]),
        )
    }

    #[test]
    fn regtest_timing_changes_the_deployment_identity() {
        let production = deployment();
        let regtest = DeploymentParameters::regtest(
            production.core_runtime_id,
            production.activation_height,
            production.proof,
        );
        assert!(regtest.validate().is_ok());
        assert_ne!(production.deployment_id(), regtest.deployment_id());
        assert_eq!(regtest.epoch_blocks, 32);
        assert_eq!(regtest.lease_blocks, 128);
    }

    #[test]
    fn verifier_manifest_binds_every_input() {
        let baseline = ProofIdentity::derive(11, 4_704, 4_704, [1; 32], [2; 32]);
        assert_ne!(baseline.reveal, baseline.refresh);
        assert_ne!(
            baseline,
            ProofIdentity::derive(12, 4_704, 4_704, [1; 32], [2; 32])
        );
        assert_ne!(
            baseline,
            ProofIdentity::derive(11, 4_705, 4_704, [1; 32], [2; 32])
        );
        assert_ne!(
            baseline,
            ProofIdentity::derive(11, 4_704, 4_704, [3; 32], [2; 32])
        );
    }

    #[test]
    fn verifier_suite_manifest_has_frozen_identity() {
        assert_eq!(
            hex::encode(verifier_suite_id()),
            "2d39faaba54a731c3f2d4c15ae0d6ca665a2124dc7575926b69217c993b3de67"
        );
    }

    #[test]
    fn deployment_identity_binds_every_variable_input() {
        let baseline = deployment();
        let expected = baseline.deployment_id().unwrap();
        assert_eq!(baseline.canonical_preimage().unwrap().len(), 206);

        let changes: [fn(&mut DeploymentParameters); 10] = [
            |value| value.core_runtime_id = CoreRuntimeId::from_bytes([4; 32]),
            |value| value.activation_height += 1,
            |value| {
                value.epoch_blocks += 1;
                value.cooldown_blocks += 1;
            },
            |value| value.window_blocks -= 1,
            |value| value.commit_maturity_blocks += 1,
            |value| value.commit_ttl_blocks += 1,
            |value| value.lease_blocks += 1,
            |value| value.cooldown_blocks = value.epoch_blocks + 1,
            |value| value.proof = ProofIdentity::derive(11, 4_704, 4_704, [9; 32], [2; 32]),
            |value| value.proof = ProofIdentity::derive(11, 4_704, 4_704, [1; 32], [9; 32]),
        ];
        for change in changes {
            let mut changed = baseline;
            change(&mut changed);
            match changed.deployment_id() {
                Ok(actual) => assert_ne!(actual, expected),
                Err(DeploymentError::InvalidSchedule) => {}
                Err(other) => panic!("unexpected deployment error: {other:?}"),
            }
        }
    }

    #[test]
    fn deployment_rejects_invalid_schedule_and_proof_sizes() {
        let mut invalid = deployment();
        invalid.window_blocks = 0;
        assert_eq!(invalid.validate(), Err(DeploymentError::InvalidSchedule));
        invalid = deployment();
        invalid.proof = ProofIdentity::derive(
            11,
            (crate::codec::MAX_REVEAL_PROOF_BYTES + 1) as u16,
            4_704,
            [1; 32],
            [2; 32],
        );
        assert_eq!(invalid.validate(), Err(DeploymentError::InvalidProofSize));
        invalid = deployment();
        invalid.ruleset_fingerprint[0] ^= 1;
        assert_eq!(invalid.validate(), Err(DeploymentError::RulesetMismatch));
    }
}
