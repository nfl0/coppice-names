use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use coppice::{
    config::{DeploymentEncodingError, DeploymentParameters, DeploymentValidationError},
    crypto, envelope,
    owner::parse_v1_owner_key,
    pending::PendingTimingError,
    registration::registration_commitment,
    reveal::{RevealValidationError, canonical_v1_address},
};

/// Stable wallet-local identity for the Orchard account that owns a pending
/// registration bond.
///
/// This is derived from the canonical Orchard full viewing key rather than a
/// backend row identifier. In particular, librustzcash `AccountUuid` values
/// may change when the same account is restored into a new wallet database.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WalletAccountId([u8; 32]);

impl WalletAccountId {
    pub fn from_orchard_fvk(fvk: &orchard::keys::FullViewingKey) -> Self {
        Self(
            crypto::hash("CoppiceAcctV1", &fvk.to_bytes())
                .expect("fixed ASCII account-identity domain"),
        )
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Wallet-local metadata for one registration attempt.
///
/// This type intentionally does not implement `Debug`: it contains the
/// registration secret. It also contains no output reference, witness,
/// signing key, spending key, proof, anchor, or runtime state.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingRegistration {
    account_id: WalletAccountId,
    name: String,
    address: Vec<u8>,
    owner_pk: [u8; 32],
    bond_tag: [u8; 32],
    secret: [u8; 32],
    commitment: [u8; 32],
    /// Wallet-local identifier of the transaction this wallet broadcast, if
    /// known. It is transport metadata and has no protocol authority.
    commit_txid: Option<[u8; 32]>,
    /// Last observed canonical runtime height for the semantic commitment.
    /// This is a reorg-updatable cache, not the mined height of `commit_txid`.
    commit_height: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingRegistrationValidationError {
    InvalidDeployment(DeploymentValidationError),
    InvalidName,
    InvalidOwnerKey,
    InvalidAddress(RevealValidationError),
    CommitmentEncoding(DeploymentEncodingError),
    CommitmentMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingRegistrationTransitionError {
    CommitTxidAlreadyRecorded,
}

impl PendingRegistration {
    /// Constructs a validated wallet-local registration intent.
    // Account ownership and each commitment fact remain explicit so callers
    // cannot accidentally persist an intent under a different wallet account.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deployment: &DeploymentParameters,
        account_id: WalletAccountId,
        name: String,
        address: Vec<u8>,
        owner_pk: [u8; 32],
        bond_tag: [u8; 32],
        secret: [u8; 32],
        commitment: [u8; 32],
    ) -> Result<Self, PendingRegistrationValidationError> {
        deployment
            .validate()
            .map_err(PendingRegistrationValidationError::InvalidDeployment)?;
        let name = envelope::normalize_name(&name)
            .map_err(|_| PendingRegistrationValidationError::InvalidName)?;
        parse_v1_owner_key(owner_pk)
            .map_err(|_| PendingRegistrationValidationError::InvalidOwnerKey)?;

        let canonical_address = canonical_v1_address(&address, deployment)
            .map_err(PendingRegistrationValidationError::InvalidAddress)?;
        if canonical_address != address {
            return Err(PendingRegistrationValidationError::InvalidAddress(
                RevealValidationError::NonCanonicalAddress,
            ));
        }

        let expected =
            registration_commitment(deployment, &name, owner_pk, bond_tag, &address, secret)
                .map_err(PendingRegistrationValidationError::CommitmentEncoding)?;
        if expected != commitment {
            return Err(PendingRegistrationValidationError::CommitmentMismatch);
        }

        Ok(Self {
            account_id,
            name,
            address,
            owner_pk,
            bond_tag,
            secret,
            commitment,
            commit_txid: None,
            commit_height: None,
        })
    }

    pub const fn account_id(&self) -> WalletAccountId {
        self.account_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn address(&self) -> &[u8] {
        &self.address
    }

    pub const fn owner_pk(&self) -> [u8; 32] {
        self.owner_pk
    }

    pub const fn bond_tag(&self) -> [u8; 32] {
        self.bond_tag
    }

    /// Returns the secret for the later reveal builder. Callers must keep it
    /// within the wallet's private workflow.
    pub const fn secret(&self) -> [u8; 32] {
        self.secret
    }

    pub const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    pub const fn commit_txid(&self) -> Option<[u8; 32]> {
        self.commit_txid
    }

    pub const fn commit_height(&self) -> Option<u32> {
        self.commit_height
    }

    pub fn record_commit_txid(
        &mut self,
        txid: [u8; 32],
    ) -> Result<(), PendingRegistrationTransitionError> {
        match self.commit_txid {
            None => {
                self.commit_txid = Some(txid);
                Ok(())
            }
            Some(existing) if existing == txid => Ok(()),
            Some(_) => Err(PendingRegistrationTransitionError::CommitTxidAlreadyRecorded),
        }
    }

    /// Updates the last canonical runtime observation for this commitment.
    ///
    /// This is crate-private so arbitrary callers cannot assign protocol
    /// heights. The registration controller calls it only after reading the
    /// current runtime's authenticated pending map.
    pub(crate) fn observe_canonical_commit_height(&mut self, height: u32) {
        self.commit_height = Some(height);
    }

    pub(crate) fn clear_canonical_commit_height(&mut self) {
        self.commit_height = None;
    }
}

/// Errors for the wallet-local pending-registration collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingRegistrationCollectionError {
    DuplicateCommitment,
    UnknownCommitment,
    Transition(PendingRegistrationTransitionError),
}

pub const PENDING_REGISTRATION_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingRegistrationPersistenceError {
    Encoding,
    UnsupportedFormat,
    DeploymentMismatch,
    InvalidRegistration(PendingRegistrationValidationError),
    DuplicateCommitment,
    InvalidTransition(PendingRegistrationTransitionError),
}

#[derive(Serialize, Deserialize)]
struct StoredPendingRegistration {
    account_id: WalletAccountId,
    name: String,
    address: Vec<u8>,
    owner_pk: [u8; 32],
    bond_tag: [u8; 32],
    secret: [u8; 32],
    commitment: [u8; 32],
    commit_txid: Option<[u8; 32]>,
    commit_height: Option<u32>,
}

#[derive(Serialize, Deserialize)]
struct StoredPendingCollection {
    format_version: u32,
    deployment_id: [u8; 32],
    registrations: Vec<StoredPendingRegistration>,
}

/// In-memory wallet-local pending registration intents.
///
/// This is deliberately distinct from the protocol runtime's global
/// `PendingCommitments` map. It is not consensus state and is not a source of
/// truth for replay.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct PendingRegistrationCollection {
    by_commitment: BTreeMap<[u8; 32], PendingRegistration>,
}

impl PendingRegistrationCollection {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        pending: PendingRegistration,
    ) -> Result<(), PendingRegistrationCollectionError> {
        let commitment = pending.commitment();
        if self.by_commitment.contains_key(&commitment) {
            return Err(PendingRegistrationCollectionError::DuplicateCommitment);
        }
        self.by_commitment.insert(commitment, pending);
        Ok(())
    }

    pub fn get(&self, commitment: &[u8; 32]) -> Option<&PendingRegistration> {
        self.by_commitment.get(commitment)
    }

    pub fn len(&self) -> usize {
        self.by_commitment.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_commitment.is_empty()
    }

    pub fn pending_bond_tags_for_account(&self, account_id: WalletAccountId) -> BTreeSet<[u8; 32]> {
        self.by_commitment
            .values()
            .filter(|pending| pending.account_id() == account_id)
            .map(PendingRegistration::bond_tag)
            .collect()
    }

    /// Iterates public semantic commitment identifiers without exposing the
    /// secret-bearing pending values.
    pub fn commitments(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.by_commitment.keys().copied()
    }

    pub fn commitments_for_account(
        &self,
        account_id: WalletAccountId,
    ) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.by_commitment
            .iter()
            .filter(move |(_, pending)| pending.account_id() == account_id)
            .map(|(commitment, _)| *commitment)
    }

    /// Serializes secret-bearing pending intents for trusted local wallet
    /// storage. Callers must not log or expose these bytes.
    pub fn save_local(
        &self,
        deployment: &DeploymentParameters,
    ) -> Result<Vec<u8>, PendingRegistrationPersistenceError> {
        let deployment_id = deployment
            .validate()
            .map_err(|_| PendingRegistrationPersistenceError::DeploymentMismatch)?;
        let registrations = self
            .by_commitment
            .values()
            .map(|pending| StoredPendingRegistration {
                account_id: pending.account_id,
                name: pending.name.clone(),
                address: pending.address.clone(),
                owner_pk: pending.owner_pk,
                bond_tag: pending.bond_tag,
                secret: pending.secret,
                commitment: pending.commitment,
                commit_txid: pending.commit_txid,
                commit_height: pending.commit_height,
            })
            .collect();
        serde_json::to_vec(&StoredPendingCollection {
            format_version: PENDING_REGISTRATION_FORMAT_VERSION,
            deployment_id,
            registrations,
        })
        .map_err(|_| PendingRegistrationPersistenceError::Encoding)
    }

    /// Loads pending intents by reconstructing each entry through the same
    /// canonical constructor used for newly-created registrations.
    pub fn load_local(
        deployment: &DeploymentParameters,
        bytes: &[u8],
    ) -> Result<Self, PendingRegistrationPersistenceError> {
        let deployment_id = deployment
            .validate()
            .map_err(|_| PendingRegistrationPersistenceError::DeploymentMismatch)?;
        let stored: StoredPendingCollection = serde_json::from_slice(bytes)
            .map_err(|_| PendingRegistrationPersistenceError::Encoding)?;
        if stored.format_version != PENDING_REGISTRATION_FORMAT_VERSION {
            return Err(PendingRegistrationPersistenceError::UnsupportedFormat);
        }
        if stored.deployment_id != deployment_id {
            return Err(PendingRegistrationPersistenceError::DeploymentMismatch);
        }
        let mut collection = Self::new();
        for stored in stored.registrations {
            let mut pending = PendingRegistration::new(
                deployment,
                stored.account_id,
                stored.name,
                stored.address,
                stored.owner_pk,
                stored.bond_tag,
                stored.secret,
                stored.commitment,
            )
            .map_err(PendingRegistrationPersistenceError::InvalidRegistration)?;
            if let Some(txid) = stored.commit_txid {
                pending
                    .record_commit_txid(txid)
                    .map_err(PendingRegistrationPersistenceError::InvalidTransition)?;
            }
            if let Some(height) = stored.commit_height {
                pending.observe_canonical_commit_height(height);
            }
            collection
                .insert(pending)
                .map_err(|_| PendingRegistrationPersistenceError::DuplicateCommitment)?;
        }
        Ok(collection)
    }

    pub fn mark_commit_broadcast(
        &mut self,
        commitment: &[u8; 32],
        txid: [u8; 32],
    ) -> Result<(), PendingRegistrationCollectionError> {
        self.by_commitment
            .get_mut(commitment)
            .ok_or(PendingRegistrationCollectionError::UnknownCommitment)?
            .record_commit_txid(txid)
            .map_err(PendingRegistrationCollectionError::Transition)
    }

    pub(crate) fn observe_canonical_commit_height(
        &mut self,
        commitment: &[u8; 32],
        height: u32,
    ) -> Result<(), PendingRegistrationCollectionError> {
        self.by_commitment
            .get_mut(commitment)
            .ok_or(PendingRegistrationCollectionError::UnknownCommitment)?
            .observe_canonical_commit_height(height);
        Ok(())
    }

    pub(crate) fn clear_canonical_commit_height(
        &mut self,
        commitment: &[u8; 32],
    ) -> Result<(), PendingRegistrationCollectionError> {
        self.by_commitment
            .get_mut(commitment)
            .ok_or(PendingRegistrationCollectionError::UnknownCommitment)?
            .clear_canonical_commit_height();
        Ok(())
    }

    /// Removes a completed or deliberately abandoned local attempt.
    pub fn remove(&mut self, commitment: &[u8; 32]) -> Option<PendingRegistration> {
        self.by_commitment.remove(commitment)
    }
}

/// Returns whether a canonically observed COMMIT is expired at canonical
/// height `height`.
///
/// This delegates to the core's checked pending-expiry arithmetic and never
/// mutates or removes local metadata.
pub fn pending_commit_expired(
    commit_height: u32,
    commit_ttl_blocks: u32,
    height: u32,
) -> Result<bool, PendingTimingError> {
    coppice::pending::commitment_expired_at_end_of_block(commit_height, commit_ttl_blocks, height)
}

/// Returns whether a local attempt's last observed canonical COMMIT height is
/// expired. An attempt without a cached canonical observation is not expired
/// by this audit helper.
pub fn pending_attempt_expired(
    pending: &PendingRegistration,
    commit_ttl_blocks: u32,
    height: u32,
) -> Result<bool, PendingTimingError> {
    pending.commit_height().map_or(Ok(false), |commit_height| {
        pending_commit_expired(commit_height, commit_ttl_blocks, height)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use coppice::{
        config::{DeploymentParameters, REGTEST, Rendezvous},
        constants::REGTEST_ACTIVATION_HEIGHT,
        owner::{OwnerSigningKey, owner_key_bytes},
    };
    use zcash_protocol::consensus::NetworkType;

    const ADDRESS: &[u8] = b"uregtest15zjdhgeu9vfwkrgxvxyuynkprgryyww0cl668tpj0ykhl7nvvh7v7ln89f0v8c36vwyffxglg24zh5d4622ela80w065cc28mv7gf423";

    fn deployment() -> DeploymentParameters {
        DeploymentParameters {
            network_id: REGTEST.network_id.to_vec(),
            address_network: NetworkType::Regtest,
            activation_height: REGTEST_ACTIVATION_HEIGHT,
            minimum_bond_value: REGTEST.minimum_bond_value,
            commit_ttl_blocks: 20,
            reuse_delay_blocks: 10,
            bond_note_max_age_blocks: 100,
            rendezvous: Rendezvous {
                orchard_ivk: REGTEST.rendezvous.orchard_ivk,
                orchard_receiver: REGTEST.rendezvous.orchard_receiver,
            },
        }
    }

    fn account_id() -> WalletAccountId {
        WalletAccountId::from_bytes([0x11; 32])
    }

    fn owner_pk() -> [u8; 32] {
        let key = OwnerSigningKey::try_from([1; 32]).unwrap();
        owner_key_bytes(&(&key).into())
    }

    fn pending() -> PendingRegistration {
        let deployment = deployment();
        let commitment = registration_commitment(
            &deployment,
            "alice",
            owner_pk(),
            [0x42; 32],
            ADDRESS,
            [0xa5; 32],
        )
        .unwrap();
        PendingRegistration::new(
            &deployment,
            account_id(),
            "alice".to_owned(),
            ADDRESS.to_vec(),
            owner_pk(),
            [0x42; 32],
            [0xa5; 32],
            commitment,
        )
        .unwrap()
    }

    fn pending_for(
        account_id: WalletAccountId,
        name: &str,
        bond_tag: [u8; 32],
    ) -> PendingRegistration {
        let deployment = deployment();
        let secret = [name.as_bytes()[0]; 32];
        let commitment =
            registration_commitment(&deployment, name, owner_pk(), bond_tag, ADDRESS, secret)
                .unwrap();
        PendingRegistration::new(
            &deployment,
            account_id,
            name.to_owned(),
            ADDRESS.to_vec(),
            owner_pk(),
            bond_tag,
            secret,
            commitment,
        )
        .unwrap()
    }

    #[test]
    fn constructor_checks_commitment_and_does_not_store_an_output_reference() {
        let pending = pending();
        assert_eq!(pending.name(), "alice");
        assert_eq!(pending.address(), ADDRESS);
        assert_eq!(pending.commit_txid(), None);
        assert_eq!(pending.commit_height(), None);

        let deployment = deployment();
        let mut wrong = pending.commitment();
        wrong[0] ^= 1;
        assert!(matches!(
            PendingRegistration::new(
                &deployment,
                account_id(),
                "alice".to_owned(),
                ADDRESS.to_vec(),
                owner_pk(),
                [0x42; 32],
                [0xa5; 32],
                wrong,
            ),
            Err(PendingRegistrationValidationError::CommitmentMismatch)
        ));
    }

    #[test]
    fn constructor_canonicalizes_presentation_suffix_before_storage() {
        let deployment = deployment();
        let name = "alice.zec";
        let secret = [0xa5; 32];
        let commitment =
            registration_commitment(&deployment, name, owner_pk(), [0x42; 32], ADDRESS, secret)
                .unwrap();
        let pending = PendingRegistration::new(
            &deployment,
            account_id(),
            name.to_owned(),
            ADDRESS.to_vec(),
            owner_pk(),
            [0x42; 32],
            secret,
            commitment,
        )
        .unwrap();
        assert_eq!(pending.name(), "alice");
        assert_eq!(
            pending.commitment(),
            registration_commitment(
                &deployment,
                "alice",
                owner_pk(),
                [0x42; 32],
                ADDRESS,
                secret,
            )
            .unwrap()
        );
    }

    #[test]
    fn constructor_rejects_identity_v1_owner_key() {
        let deployment = deployment();
        let identity = [0; 32];
        let commitment = registration_commitment(
            &deployment,
            "alice",
            identity,
            [0x42; 32],
            ADDRESS,
            [0xa5; 32],
        )
        .unwrap();
        assert!(matches!(
            PendingRegistration::new(
                &deployment,
                account_id(),
                "alice".to_owned(),
                ADDRESS.to_vec(),
                identity,
                [0x42; 32],
                [0xa5; 32],
                commitment,
            ),
            Err(PendingRegistrationValidationError::InvalidOwnerKey)
        ));
    }

    #[test]
    fn canonical_height_cache_is_independent_of_broadcast_and_reorg_updatable() {
        let first = pending();
        let commitment = first.commitment();
        let mut collection = PendingRegistrationCollection::new();
        collection.insert(first.clone()).unwrap();
        assert_eq!(
            collection.insert(first),
            Err(PendingRegistrationCollectionError::DuplicateCommitment)
        );
        collection
            .observe_canonical_commit_height(&commitment, 10)
            .unwrap();
        assert_eq!(collection.get(&commitment).unwrap().commit_txid(), None);
        collection
            .mark_commit_broadcast(&commitment, [7; 32])
            .unwrap();
        collection
            .observe_canonical_commit_height(&commitment, 11)
            .unwrap();
        assert_eq!(
            collection.get(&commitment).unwrap().commit_height(),
            Some(11)
        );
    }

    #[test]
    fn expiration_uses_checked_protocol_arithmetic_without_deleting_metadata() {
        let mut pending = pending();
        assert!(!pending_attempt_expired(&pending, 20, 100).unwrap());
        pending.observe_canonical_commit_height(100);
        assert!(!pending_attempt_expired(&pending, 20, 119).unwrap());
        assert!(pending_attempt_expired(&pending, 20, 120).unwrap());
        assert_eq!(
            pending_commit_expired(u32::MAX, 1, u32::MAX),
            Err(PendingTimingError::HeightOverflow)
        );
    }

    #[test]
    fn secret_pending_collection_round_trips_through_validated_local_format() {
        let deployment = deployment();
        let mut collection = PendingRegistrationCollection::new();
        let mut entry = pending();
        entry.record_commit_txid([7; 32]).unwrap();
        entry.observe_canonical_commit_height(11);
        collection.insert(entry).unwrap();

        let bytes = collection.save_local(&deployment).unwrap();
        let restored = PendingRegistrationCollection::load_local(&deployment, &bytes).unwrap();
        assert!(restored == collection);

        let mut old_format: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        old_format["format_version"] = serde_json::Value::from(2);
        assert!(matches!(
            PendingRegistrationCollection::load_local(
                &deployment,
                &serde_json::to_vec(&old_format).unwrap()
            ),
            Err(PendingRegistrationPersistenceError::UnsupportedFormat)
        ));

        let mut wrong = deployment.clone();
        wrong.network_id.push(1);
        assert!(matches!(
            PendingRegistrationCollection::load_local(&wrong, &bytes),
            Err(PendingRegistrationPersistenceError::DeploymentMismatch)
        ));
    }

    #[test]
    fn account_ownership_survives_restart_and_filters_exactly() {
        let deployment = deployment();
        let account_a = WalletAccountId::from_bytes([0xa1; 32]);
        let account_b = WalletAccountId::from_bytes([0xb2; 32]);
        let pending_a = pending_for(account_a, "alice", [0x41; 32]);
        let pending_b = pending_for(account_b, "bob", [0x42; 32]);
        let commitment_a = pending_a.commitment();
        let commitment_b = pending_b.commitment();
        let mut collection = PendingRegistrationCollection::new();
        collection.insert(pending_a).unwrap();
        collection.insert(pending_b).unwrap();

        let restored = PendingRegistrationCollection::load_local(
            &deployment,
            &collection.save_local(&deployment).unwrap(),
        )
        .unwrap();
        assert_eq!(restored.get(&commitment_a).unwrap().account_id(), account_a);
        assert_eq!(restored.get(&commitment_b).unwrap().account_id(), account_b);
        assert_eq!(
            restored
                .commitments_for_account(account_a)
                .collect::<Vec<_>>(),
            vec![commitment_a]
        );
        assert_eq!(
            restored
                .commitments_for_account(account_b)
                .collect::<Vec<_>>(),
            vec![commitment_b]
        );
        assert_eq!(
            restored.pending_bond_tags_for_account(account_a),
            BTreeSet::from([[0x41; 32]])
        );
        assert_eq!(
            restored.pending_bond_tags_for_account(account_b),
            BTreeSet::from([[0x42; 32]])
        );
    }
}
