use std::{collections::BTreeSet, fmt::Debug};

use orchard::keys::FullViewingKey;
use zcash_client_backend::data_api::{InputSource, wallet::TargetHeight};
use zcash_client_backend::data_api::{OutputLockStore, locking::LockError};
use zcash_client_backend::wallet::LockOwner;
use zcash_client_backend::wallet::OutputRef;
use zcash_protocol::consensus::BlockHeight;

use crate::{
    InputSourceIronwoodNoteSource, InventoryError, IronwoodNoteSourceError, IronwoodOutputId,
    IronwoodViewingCapability, OwnedBond, OwnedIronwoodNote, OwnedIronwoodNoteSource,
    PendingRegistrationCollection, WalletAccountId,
    inventory::{ClassifiedNote, classify_notes},
};

/// The smallest wallet-backend seam required by reconstructible Coppice locks.
///
/// The concrete wallet implementation is responsible for making
/// `owned_unspent_ironwood_notes` include already-locked outputs. The only
/// mutation methods are Coppice-scoped; this trait has no operation for
/// inspecting or clearing arbitrary foreign locks.
pub trait CoppiceLockBackend {
    type Error: Debug;

    fn owned_unspent_ironwood_notes(&self) -> Result<Vec<OwnedIronwoodNote>, Self::Error>;

    fn ensure_coppice_lock(
        &mut self,
        output_id: &IronwoodOutputId,
        bond_tag: [u8; 32],
        expiry_height: BlockHeight,
    ) -> Result<(), Self::Error>;

    fn remove_coppice_lock(
        &mut self,
        output_id: &IronwoodOutputId,
        bond_tag: [u8; 32],
    ) -> Result<bool, Self::Error>;

    fn max_lock_expiry_height(&self) -> BlockHeight;
}

/// Constructs the exact pinned librustzcash lock identity for a Coppice bond.
/// The bond tag is used directly; it is not hashed again.
pub const fn lock_owner_for_bond(bond_tag: [u8; 32]) -> LockOwner {
    LockOwner::new(bond_tag)
}

/// Errors produced by the direct pinned-librustzcash lock-store bridge.
#[derive(Debug)]
pub enum OutputLockBackendError<NoteSourceError, StorageError> {
    NoteSource(NoteSourceError),
    LockConflict(OutputRef),
    Storage(StorageError),
    UnexpectedLockCount { output: OutputRef, count: usize },
    UnknownLockFailure,
}

pub type WalletCoppiceLockError<DbT> = OutputLockBackendError<
    IronwoodNoteSourceError<<DbT as InputSource>::Error, <DbT as OutputLockStore>::Error>,
    <DbT as OutputLockStore>::Error,
>;

enum ExactLockError<E> {
    Conflict(OutputRef),
    Storage(E),
    UnexpectedCount { output: OutputRef, count: usize },
    Unknown,
}

fn ensure_exact_lock<Store: OutputLockStore>(
    store: &mut Store,
    output: OutputRef,
    owner: LockOwner,
    expiry_height: BlockHeight,
) -> Result<(), ExactLockError<Store::Error>> {
    match store.lock_outputs(&[output], owner, expiry_height) {
        Ok(1) => Ok(()),
        Ok(count) => Err(ExactLockError::UnexpectedCount { output, count }),
        Err(LockError::LockFailure(output)) => Err(ExactLockError::Conflict(output)),
        Err(LockError::Storage(error)) => Err(ExactLockError::Storage(error)),
        Err(_) => Err(ExactLockError::Unknown),
    }
}

fn map_exact_lock_error<NoteError, StorageError>(
    error: ExactLockError<StorageError>,
) -> OutputLockBackendError<NoteError, StorageError> {
    match error {
        ExactLockError::Conflict(output) => OutputLockBackendError::LockConflict(output),
        ExactLockError::Storage(error) => OutputLockBackendError::Storage(error),
        ExactLockError::UnexpectedCount { output, count } => {
            OutputLockBackendError::UnexpectedLockCount { output, count }
        }
        ExactLockError::Unknown => OutputLockBackendError::UnknownLockFailure,
    }
}

/// Composes a wallet-owned note source with the pinned public
/// [`OutputLockStore`] API.
///
/// Inventory and lock storage are deliberately separate inputs: the pinned
/// lock store owns lock mutations, not note enumeration. This bridge does not
/// require `zcash_client_sqlite` and never calls
/// [`OutputLockStore::clear_locked_outputs`].
pub struct OutputLockStoreBridge<NoteSource, LockStore> {
    note_source: NoteSource,
    lock_store: LockStore,
}

impl<NoteSource, LockStore> OutputLockStoreBridge<NoteSource, LockStore> {
    pub fn new(note_source: NoteSource, lock_store: LockStore) -> Self {
        Self {
            note_source,
            lock_store,
        }
    }

    pub fn note_source(&self) -> &NoteSource {
        &self.note_source
    }

    pub fn lock_store(&self) -> &LockStore {
        &self.lock_store
    }

    pub fn lock_store_mut(&mut self) -> &mut LockStore {
        &mut self.lock_store
    }

    pub fn into_parts(self) -> (NoteSource, LockStore) {
        (self.note_source, self.lock_store)
    }
}

impl<NoteSource, LockStore> CoppiceLockBackend for OutputLockStoreBridge<NoteSource, LockStore>
where
    NoteSource: OwnedIronwoodNoteSource,
    LockStore: OutputLockStore,
{
    type Error = OutputLockBackendError<NoteSource::Error, LockStore::Error>;

    fn owned_unspent_ironwood_notes(&self) -> Result<Vec<OwnedIronwoodNote>, Self::Error> {
        self.note_source
            .owned_unspent_ironwood_notes()
            .map_err(OutputLockBackendError::NoteSource)
    }

    fn ensure_coppice_lock(
        &mut self,
        output_id: &IronwoodOutputId,
        bond_tag: [u8; 32],
        expiry_height: BlockHeight,
    ) -> Result<(), Self::Error> {
        let output = output_id.as_output_ref();
        let owner = lock_owner_for_bond(bond_tag);
        ensure_exact_lock(&mut self.lock_store, output, owner, expiry_height)
            .map_err(map_exact_lock_error)
    }

    fn remove_coppice_lock(
        &mut self,
        output_id: &IronwoodOutputId,
        bond_tag: [u8; 32],
    ) -> Result<bool, Self::Error> {
        let output = output_id.as_output_ref();
        self.lock_store
            .unlock_output(&output, lock_owner_for_bond(bond_tag))
            .map_err(OutputLockBackendError::Storage)
    }

    fn max_lock_expiry_height(&self) -> BlockHeight {
        BlockHeight::from_u32(u32::MAX)
    }
}

/// One-object facade for inventory and Coppice lock mutation over a real wallet
/// backend. It is deliberately transient and contains no self-references.
pub struct WalletCoppiceLockBackend<'a, DbT>
where
    DbT: InputSource + OutputLockStore<AccountId = <DbT as InputSource>::AccountId>,
{
    wallet_db: &'a mut DbT,
    account: <DbT as InputSource>::AccountId,
    target_height: TargetHeight,
    orchard_fvk: &'a FullViewingKey,
    capability: IronwoodViewingCapability,
}

impl<'a, DbT> WalletCoppiceLockBackend<'a, DbT>
where
    DbT: InputSource + OutputLockStore<AccountId = <DbT as InputSource>::AccountId>,
{
    pub fn new(
        wallet_db: &'a mut DbT,
        account: <DbT as InputSource>::AccountId,
        target_height: TargetHeight,
        orchard_fvk: &'a FullViewingKey,
        capability: IronwoodViewingCapability,
    ) -> Self {
        Self {
            wallet_db,
            account,
            target_height,
            orchard_fvk,
            capability,
        }
    }

    pub fn wallet_db_mut(&mut self) -> &mut DbT {
        self.wallet_db
    }

    pub const fn capability(&self) -> IronwoodViewingCapability {
        self.capability
    }

    pub const fn target_height(&self) -> TargetHeight {
        self.target_height
    }
}

impl<DbT> CoppiceLockBackend for WalletCoppiceLockBackend<'_, DbT>
where
    DbT: InputSource + OutputLockStore<AccountId = <DbT as InputSource>::AccountId>,
    <DbT as InputSource>::Error: Debug,
    <DbT as OutputLockStore>::Error: Debug,
{
    type Error = WalletCoppiceLockError<DbT>;

    fn owned_unspent_ironwood_notes(&self) -> Result<Vec<OwnedIronwoodNote>, Self::Error> {
        InputSourceIronwoodNoteSource::new(
            &*self.wallet_db,
            &*self.wallet_db,
            self.account,
            self.target_height,
            self.orchard_fvk,
            self.capability,
        )
        .owned_unspent_ironwood_notes()
        .map_err(OutputLockBackendError::NoteSource)
    }

    fn ensure_coppice_lock(
        &mut self,
        output_id: &IronwoodOutputId,
        bond_tag: [u8; 32],
        expiry_height: BlockHeight,
    ) -> Result<(), Self::Error> {
        ensure_exact_lock(
            self.wallet_db,
            output_id.as_output_ref(),
            lock_owner_for_bond(bond_tag),
            expiry_height,
        )
        .map_err(map_exact_lock_error)
    }

    fn remove_coppice_lock(
        &mut self,
        output_id: &IronwoodOutputId,
        bond_tag: [u8; 32],
    ) -> Result<bool, Self::Error> {
        self.wallet_db
            .unlock_output(&output_id.as_output_ref(), lock_owner_for_bond(bond_tag))
            .map_err(OutputLockBackendError::Storage)
    }

    fn max_lock_expiry_height(&self) -> BlockHeight {
        BlockHeight::from_u32(u32::MAX)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesiredLockSetError {
    Inventory(InventoryError),
    MissingPendingBond { bond_tag: [u8; 32] },
}

/// Computes the I-004 desired lock tags.
///
/// Canonical active tags are intersected with tags reconstructed from this
/// wallet's notes. Local pending tags are then unioned in, but a pending tag
/// whose note is missing is reported explicitly rather than silently dropped.
pub fn desired_lock_tags(
    active_tags: &BTreeSet<[u8; 32]>,
    pending: &PendingRegistrationCollection,
    account_id: WalletAccountId,
    notes: &[OwnedIronwoodNote],
    capability: IronwoodViewingCapability,
) -> Result<BTreeSet<[u8; 32]>, DesiredLockSetError> {
    let classified = classify_notes(notes, capability).map_err(DesiredLockSetError::Inventory)?;
    desired_lock_tags_from_classified(active_tags, pending, account_id, &classified)
}

fn desired_lock_tags_from_classified(
    active_tags: &BTreeSet<[u8; 32]>,
    pending: &PendingRegistrationCollection,
    account_id: WalletAccountId,
    classified: &[ClassifiedNote],
) -> Result<BTreeSet<[u8; 32]>, DesiredLockSetError> {
    let owned_tags: BTreeSet<[u8; 32]> = classified
        .iter()
        .map(|classified| classified.bond_tag)
        .collect();
    let pending_tags = pending.pending_bond_tags_for_account(account_id);
    for bond_tag in &pending_tags {
        if !owned_tags.contains(bond_tag) {
            return Err(DesiredLockSetError::MissingPendingBond {
                bond_tag: *bond_tag,
            });
        }
    }

    let mut desired = active_tags
        .intersection(&owned_tags)
        .copied()
        .collect::<BTreeSet<_>>();
    desired.extend(pending_tags);
    Ok(desired)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciliationReport {
    pub desired_tags: BTreeSet<[u8; 32]>,
    pub owned_active_bonds: Vec<OwnedBond>,
    pub ensured_locks: usize,
    pub removed_locks: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconciliationError<E: Debug> {
    Inventory(InventoryError),
    MissingPendingBond { bond_tag: [u8; 32] },
    Backend(E),
}

fn map_desired_error<E: Debug>(error: DesiredLockSetError) -> ReconciliationError<E> {
    match error {
        DesiredLockSetError::Inventory(error) => ReconciliationError::Inventory(error),
        DesiredLockSetError::MissingPendingBond { bond_tag } => {
            ReconciliationError::MissingPendingBond { bond_tag }
        }
    }
}

/// Reconciles every owned unspent Ironwood note against the reconstructible
/// desired Coppice lock set.
pub fn reconcile_locks<B: CoppiceLockBackend>(
    active_tags: &BTreeSet<[u8; 32]>,
    pending: &PendingRegistrationCollection,
    account_id: WalletAccountId,
    capability: IronwoodViewingCapability,
    backend: &mut B,
) -> Result<ReconciliationReport, ReconciliationError<B::Error>> {
    // Check the capability before asking the backend for notes. Incoming-only
    // wallets must fail explicitly and must not mutate lock state.
    capability
        .require_nullifier_derivation()
        .map_err(ReconciliationError::Inventory)?;
    let notes = backend
        .owned_unspent_ironwood_notes()
        .map_err(ReconciliationError::Backend)?;
    let classified = classify_notes(&notes, capability).map_err(ReconciliationError::Inventory)?;
    let desired = desired_lock_tags_from_classified(active_tags, pending, account_id, &classified)
        .map_err(map_desired_error::<B::Error>)?;

    let owned_active_bonds = classified
        .iter()
        .filter(|classified| active_tags.contains(&classified.bond_tag))
        .map(|classified| OwnedBond {
            output_id: classified.note.output_id,
            value_zat: classified.note.value_zat,
            position: classified.note.position,
            bond_tag: classified.bond_tag,
        })
        .collect::<Vec<_>>();

    let expiry_height = backend.max_lock_expiry_height();
    let mut ensured_locks = 0;
    let mut removed_locks = 0;

    // `classify_notes` provides a stable `(bond_tag, output_id)` order, so
    // backend iteration order cannot affect mutation order or the report.
    for classified in classified {
        let note = classified.note;
        let bond_tag = classified.bond_tag;
        if desired.contains(&bond_tag) {
            backend
                .ensure_coppice_lock(&note.output_id, bond_tag, expiry_height)
                .map_err(ReconciliationError::Backend)?;
            ensured_locks += 1;
        } else if backend
            .remove_coppice_lock(&note.output_id, bond_tag)
            .map_err(ReconciliationError::Backend)?
        {
            removed_locks += 1;
        }
    }

    Ok(ReconciliationReport {
        desired_tags: desired,
        owned_active_bonds,
        ensured_locks,
        removed_locks,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use coppice::{
        config::{DeploymentParameters, REGTEST, Rendezvous},
        constants::REGTEST_ACTIVATION_HEIGHT,
        owner::{OwnerSigningKey, owner_key_bytes},
        record::{NameRecord, NameStatus},
        registration::registration_commitment,
        state::CoppiceState,
    };
    use zcash_client_backend::{
        data_api::{OutputLockStore, locking::LockError},
        wallet::{LockOwner, OutputRef},
    };
    use zcash_protocol::consensus::{BlockHeight, NetworkType};

    use super::*;
    use crate::{
        IronwoodOutputId, OwnedIronwoodNoteSource, PendingRegistration,
        PendingRegistrationCollection,
    };

    const ADDRESS: &[u8] = b"uregtest15zjdhgeu9vfwkrgxvxyuynkprgryyww0cl668tpj0ykhl7nvvh7v7ln89f0v8c36vwyffxglg24zh5d4622ela80w065cc28mv7gf423";

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FakeLock {
        owner: LockOwner,
        expiry: BlockHeight,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum FakeError {
        ForeignLock,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct FakeBackend {
        notes: Vec<OwnedIronwoodNote>,
        locks: BTreeMap<IronwoodOutputId, FakeLock>,
    }

    impl FakeBackend {
        fn new(notes: Vec<OwnedIronwoodNote>) -> Self {
            Self {
                notes,
                locks: BTreeMap::new(),
            }
        }

        fn with_lock(mut self, output_id: IronwoodOutputId, owner: LockOwner) -> Self {
            self.locks.insert(
                output_id,
                FakeLock {
                    owner,
                    expiry: BlockHeight::from_u32(123),
                },
            );
            self.sync_note(output_id);
            self
        }

        fn sync_note(&mut self, output_id: IronwoodOutputId) {
            let lock = self.locks.get(&output_id).copied();
            if let Some(note) = self
                .notes
                .iter_mut()
                .find(|note| note.output_id == output_id)
            {
                note.locked = lock.is_some();
            }
        }
    }

    impl CoppiceLockBackend for FakeBackend {
        type Error = FakeError;

        fn owned_unspent_ironwood_notes(&self) -> Result<Vec<OwnedIronwoodNote>, Self::Error> {
            Ok(self.notes.clone())
        }

        fn ensure_coppice_lock(
            &mut self,
            output_id: &IronwoodOutputId,
            bond_tag: [u8; 32],
            expiry_height: BlockHeight,
        ) -> Result<(), Self::Error> {
            let owner = lock_owner_for_bond(bond_tag);
            if self
                .locks
                .get(output_id)
                .is_some_and(|lock| lock.owner != owner)
            {
                return Err(FakeError::ForeignLock);
            }
            self.locks.insert(
                *output_id,
                FakeLock {
                    owner,
                    expiry: expiry_height,
                },
            );
            self.sync_note(*output_id);
            Ok(())
        }

        fn remove_coppice_lock(
            &mut self,
            output_id: &IronwoodOutputId,
            bond_tag: [u8; 32],
        ) -> Result<bool, Self::Error> {
            let owner = lock_owner_for_bond(bond_tag);
            let removable = self
                .locks
                .get(output_id)
                .is_some_and(|lock| lock.owner == owner);
            if removable {
                self.locks.remove(output_id);
                self.sync_note(*output_id);
            }
            Ok(removable)
        }

        fn max_lock_expiry_height(&self) -> BlockHeight {
            BlockHeight::from_u32(u32::MAX)
        }
    }

    fn note(id: u8) -> OwnedIronwoodNote {
        OwnedIronwoodNote {
            output_id: IronwoodOutputId::new([id; 32], u32::from(id)),
            value_zat: 100,
            nullifier: [id; 32],
            position: Some(u32::from(id)),
            locked: false,
            spendable: true,
        }
    }

    fn tag(id: u8) -> [u8; 32] {
        coppice::bond_tag::derive_v1_bond_tag(&[id; 32]).unwrap()
    }

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

    fn pending_for(name: &str, bond_tag: [u8; 32]) -> PendingRegistration {
        pending_for_account(account_id(), name, bond_tag)
    }

    fn pending_for_account(
        account_id: WalletAccountId,
        name: &str,
        bond_tag: [u8; 32],
    ) -> PendingRegistration {
        let deployment = deployment();
        let key = OwnerSigningKey::try_from([1; 32]).unwrap();
        let owner_pk = owner_key_bytes(&(&key).into());
        let secret = [0xa5; 32];
        let commitment =
            registration_commitment(&deployment, name, owner_pk, bond_tag, ADDRESS, secret)
                .unwrap();
        PendingRegistration::new(
            &deployment,
            account_id,
            name.to_owned(),
            ADDRESS.to_vec(),
            owner_pk,
            bond_tag,
            secret,
            commitment,
        )
        .unwrap()
    }

    fn collection_with(pending: PendingRegistration) -> PendingRegistrationCollection {
        let mut collection = PendingRegistrationCollection::new();
        collection.insert(pending).unwrap();
        collection
    }

    fn empty_pending() -> PendingRegistrationCollection {
        PendingRegistrationCollection::new()
    }

    #[test]
    fn owned_active_bond_is_locked() {
        let active = BTreeSet::from([tag(1)]);
        let mut backend = FakeBackend::new(vec![note(1)]);
        let report = reconcile_locks(
            &active,
            &empty_pending(),
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        assert_eq!(report.desired_tags, active);
        assert_eq!(
            backend.locks[&note(1).output_id].owner,
            lock_owner_for_bond(tag(1))
        );
        assert_eq!(
            backend.locks[&note(1).output_id].expiry,
            BlockHeight::from_u32(u32::MAX)
        );
    }

    #[test]
    fn pending_registrations_are_reconciled_only_with_their_owning_account() {
        let account_a = WalletAccountId::from_bytes([0xa1; 32]);
        let account_b = WalletAccountId::from_bytes([0xb2; 32]);
        let tag_a = tag(1);
        let tag_b = tag(2);
        let mut pending = PendingRegistrationCollection::new();
        pending
            .insert(pending_for_account(account_a, "alice", tag_a))
            .unwrap();

        let mut backend_a = FakeBackend::new(vec![note(1)]);
        let mut backend_b = FakeBackend::new(vec![note(2)]);
        let active = BTreeSet::from([tag_b]);

        let report_b = reconcile_locks(
            &active,
            &pending,
            account_b,
            IronwoodViewingCapability::FullViewing,
            &mut backend_b,
        )
        .unwrap();
        assert_eq!(report_b.desired_tags, BTreeSet::from([tag_b]));
        assert_eq!(
            backend_b.locks[&note(2).output_id].owner,
            lock_owner_for_bond(tag_b)
        );

        let report_a = reconcile_locks(
            &active,
            &pending,
            account_a,
            IronwoodViewingCapability::FullViewing,
            &mut backend_a,
        )
        .unwrap();
        assert_eq!(report_a.desired_tags, BTreeSet::from([tag_a]));
        assert_eq!(
            backend_a.locks[&note(1).output_id].owner,
            lock_owner_for_bond(tag_a)
        );
    }

    #[test]
    fn owned_pending_bond_is_locked() {
        let pending = pending_for("alice", tag(2));
        let mut backend = FakeBackend::new(vec![note(2)]);
        let report = reconcile_locks(
            &BTreeSet::new(),
            &collection_with(pending),
            account_id(),
            IronwoodViewingCapability::Spending,
            &mut backend,
        )
        .unwrap();
        assert_eq!(report.desired_tags, BTreeSet::from([tag(2)]));
        assert_eq!(
            backend.locks[&note(2).output_id].owner,
            lock_owner_for_bond(tag(2))
        );
    }

    #[test]
    fn same_active_and_pending_tag_is_one_desired_tag() {
        let pending = pending_for("alice", tag(3));
        let mut backend = FakeBackend::new(vec![note(3)]);
        let report = reconcile_locks(
            &BTreeSet::from([tag(3)]),
            &collection_with(pending),
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        assert_eq!(report.desired_tags, BTreeSet::from([tag(3)]));
        assert_eq!(report.ensured_locks, 1);
    }

    #[test]
    fn unrelated_owned_coppice_lock_is_removed() {
        let old_tag = tag(4);
        let output_id = note(4).output_id;
        let mut backend =
            FakeBackend::new(vec![note(4)]).with_lock(output_id, lock_owner_for_bond(old_tag));
        let report = reconcile_locks(
            &BTreeSet::new(),
            &empty_pending(),
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        assert_eq!(report.removed_locks, 1);
        assert!(!backend.locks.contains_key(&output_id));
    }

    #[test]
    fn foreign_lock_is_preserved() {
        let output_id = note(5).output_id;
        let foreign = LockOwner::new([0xf5; 32]);
        let mut backend = FakeBackend::new(vec![note(5)]).with_lock(output_id, foreign);
        reconcile_locks(
            &BTreeSet::new(),
            &empty_pending(),
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        assert_eq!(backend.locks[&output_id].owner, foreign);
    }

    #[test]
    fn off_transition_cleanup_removes_only_coppice_owned_locks() {
        let own_output = note(4).output_id;
        let foreign_output = note(5).output_id;
        let foreign_owner = LockOwner::new([0xf5; 32]);
        let mut backend = FakeBackend::new(vec![note(4), note(5)])
            .with_lock(own_output, lock_owner_for_bond(tag(4)))
            .with_lock(foreign_output, foreign_owner);
        let report = reconcile_locks(
            &BTreeSet::new(),
            &PendingRegistrationCollection::new(),
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        assert_eq!(report.removed_locks, 1);
        assert!(!backend.locks.contains_key(&own_output));
        assert_eq!(backend.locks[&foreign_output].owner, foreign_owner);
    }

    #[test]
    fn active_canonical_tag_without_owned_note_is_harmless() {
        let active = BTreeSet::from([tag(6)]);
        let mut backend = FakeBackend::new(Vec::new());
        let report = reconcile_locks(
            &active,
            &empty_pending(),
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        assert!(report.desired_tags.is_empty());
        assert!(backend.locks.is_empty());
    }

    #[test]
    fn missing_pending_note_is_explicit_and_does_not_mutate() {
        let pending = pending_for("alice", tag(7));
        let mut backend = FakeBackend::new(Vec::new());
        let before = backend.clone();
        assert_eq!(
            reconcile_locks(
                &BTreeSet::new(),
                &collection_with(pending),
                account_id(),
                IronwoodViewingCapability::FullViewing,
                &mut backend,
            ),
            Err(ReconciliationError::MissingPendingBond { bond_tag: tag(7) })
        );
        assert_eq!(backend, before);
    }

    #[test]
    fn repeated_reconciliation_is_idempotent() {
        let active = BTreeSet::from([tag(8)]);
        let mut backend = FakeBackend::new(vec![note(8)]);
        let first = reconcile_locks(
            &active,
            &empty_pending(),
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        let state_after_first = backend.clone();
        let second = reconcile_locks(
            &active,
            &empty_pending(),
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        assert_eq!(backend, state_after_first);
        assert_eq!(first, second);
    }

    #[test]
    fn terminal_active_name_removes_old_lock_but_pending_keeps_it() {
        let old_tag = tag(9);
        let output_id = note(9).output_id;
        let mut backend =
            FakeBackend::new(vec![note(9)]).with_lock(output_id, lock_owner_for_bond(old_tag));
        reconcile_locks(
            &BTreeSet::new(),
            &empty_pending(),
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        assert!(!backend.locks.contains_key(&output_id));

        let mut backend =
            FakeBackend::new(vec![note(9)]).with_lock(output_id, lock_owner_for_bond(old_tag));
        reconcile_locks(
            &BTreeSet::new(),
            &collection_with(pending_for("alice", old_tag)),
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        assert_eq!(
            backend.locks[&output_id].owner,
            lock_owner_for_bond(old_tag)
        );
    }

    #[test]
    fn phase6_rebuilt_state_restores_only_active_bond_locks() {
        let active_tag = tag(20);
        let released_tag = tag(21);
        let spent_tag = tag(22);
        let mut names = BTreeMap::new();
        names.insert(
            "phase6-active".to_owned(),
            NameRecord {
                owner_pk: [0x20; 32],
                bond_tag: active_tag,
                sequence: 1,
                address: ADDRESS.to_vec(),
                status: NameStatus::Active,
            },
        );
        names.insert(
            "phase6-released".to_owned(),
            NameRecord {
                owner_pk: [0x21; 32],
                bond_tag: released_tag,
                sequence: 1,
                address: ADDRESS.to_vec(),
                status: NameStatus::Released {
                    terminal_height: 103,
                },
            },
        );
        names.insert(
            "phase6-spent".to_owned(),
            NameRecord {
                owner_pk: [0x22; 32],
                bond_tag: spent_tag,
                sequence: 0,
                address: ADDRESS.to_vec(),
                status: NameStatus::BondSpent {
                    terminal_height: 150,
                },
            },
        );
        let rebuilt_state = CoppiceState::from_authoritative_parts(
            names,
            BTreeMap::new(),
            BTreeMap::from([(spent_tag, 150)]),
        )
        .unwrap();
        let active_tags = crate::active_canonical_bond_tags_from_state(&rebuilt_state);
        assert_eq!(active_tags, BTreeSet::from([active_tag]));

        let mut backend = FakeBackend::new(vec![note(20), note(21), note(22)])
            .with_lock(note(21).output_id, lock_owner_for_bond(released_tag))
            .with_lock(note(22).output_id, lock_owner_for_bond(spent_tag));
        let report = reconcile_locks(
            &active_tags,
            &empty_pending(),
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();

        assert_eq!(report.desired_tags, BTreeSet::from([active_tag]));
        assert_eq!(report.ensured_locks, 1);
        assert_eq!(report.removed_locks, 2);
        assert_eq!(
            backend.locks[&note(20).output_id].owner,
            lock_owner_for_bond(active_tag)
        );
        assert!(!backend.locks.contains_key(&note(21).output_id));
        assert!(!backend.locks.contains_key(&note(22).output_id));
    }

    #[test]
    fn incoming_only_fails_before_note_enumeration_or_lock_mutation() {
        let output_id = note(10).output_id;
        let foreign = LockOwner::new([0xaa; 32]);
        let mut backend = FakeBackend::new(vec![note(10)]).with_lock(output_id, foreign);
        let before = backend.clone();
        assert_eq!(
            reconcile_locks(
                &BTreeSet::from([tag(10)]),
                &empty_pending(),
                account_id(),
                IronwoodViewingCapability::IncomingOnly,
                &mut backend,
            ),
            Err(ReconciliationError::Inventory(
                InventoryError::InsufficientViewingCapability
            ))
        );
        assert_eq!(backend, before);
    }

    #[test]
    fn desired_lock_set_has_the_same_missing_pending_diagnostic() {
        let pending = pending_for("alice", tag(11));
        assert_eq!(
            desired_lock_tags(
                &BTreeSet::new(),
                &collection_with(pending),
                account_id(),
                &[],
                IronwoodViewingCapability::FullViewing,
            ),
            Err(DesiredLockSetError::MissingPendingBond { bond_tag: tag(11) })
        );
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct FakeNoteSource {
        notes: Vec<OwnedIronwoodNote>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FakeNoteSourceError;

    impl OwnedIronwoodNoteSource for FakeNoteSource {
        type Error = FakeNoteSourceError;

        fn owned_unspent_ironwood_notes(&self) -> Result<Vec<OwnedIronwoodNote>, Self::Error> {
            Ok(self.notes.clone())
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FakeStoreError {
        Storage,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct FakeOutputLockStore {
        locks: BTreeMap<OutputRef, FakeLock>,
        clear_calls: usize,
        fail_storage: bool,
    }

    impl FakeOutputLockStore {
        fn new() -> Self {
            Self {
                locks: BTreeMap::new(),
                clear_calls: 0,
                fail_storage: false,
            }
        }
    }

    impl OutputLockStore for FakeOutputLockStore {
        type Error = FakeStoreError;
        type AccountId = u8;

        fn lock_outputs(
            &mut self,
            outputs: &[OutputRef],
            owner: LockOwner,
            lock_expiry_height: BlockHeight,
        ) -> Result<usize, LockError<Self::Error>> {
            if self.fail_storage {
                return Err(LockError::Storage(FakeStoreError::Storage));
            }
            // Preflight all outputs so this fake preserves the pinned
            // OutputLockStore atomicity guarantee.
            if let Some(output) = outputs.iter().find(|output| {
                self.locks
                    .get(output)
                    .is_some_and(|lock| lock.owner != owner)
            }) {
                return Err(LockError::LockFailure(*output));
            }
            for output in outputs {
                self.locks.insert(
                    *output,
                    FakeLock {
                        owner,
                        expiry: lock_expiry_height,
                    },
                );
            }
            Ok(outputs.len())
        }

        fn unlock_output(
            &mut self,
            output: &OutputRef,
            owner: LockOwner,
        ) -> Result<bool, Self::Error> {
            if self.fail_storage {
                return Err(FakeStoreError::Storage);
            }
            let removable = self
                .locks
                .get(output)
                .is_some_and(|lock| lock.owner == owner);
            if removable {
                self.locks.remove(output);
            }
            Ok(removable)
        }

        fn clear_locked_outputs(
            &mut self,
            _account: Self::AccountId,
        ) -> Result<usize, Self::Error> {
            self.clear_calls += 1;
            let count = self.locks.len();
            self.locks.clear();
            Ok(count)
        }

        fn get_locked_outputs(
            &self,
            _account: Self::AccountId,
        ) -> Result<Vec<OutputRef>, Self::Error> {
            Ok(self.locks.keys().copied().collect())
        }
    }

    #[test]
    fn output_lock_store_bridge_uses_exact_ref_owner_and_max_expiry() {
        let output_id = note(12).output_id;
        let mut bridge = OutputLockStoreBridge::new(
            FakeNoteSource {
                notes: vec![note(12)],
            },
            FakeOutputLockStore::new(),
        );
        let expiry = bridge.max_lock_expiry_height();
        CoppiceLockBackend::ensure_coppice_lock(&mut bridge, &output_id, tag(12), expiry).unwrap();

        let output_ref = output_id.as_output_ref();
        let lock = bridge.lock_store().locks.get(&output_ref).unwrap();
        assert_eq!(lock.owner, LockOwner::new(tag(12)));
        assert_eq!(lock.expiry, BlockHeight::from_u32(u32::MAX));
        assert_eq!(
            bridge.max_lock_expiry_height(),
            BlockHeight::from_u32(u32::MAX)
        );
    }

    #[test]
    fn output_lock_store_bridge_maps_conflict_and_storage_errors() {
        let output_id = note(13).output_id;
        let output_ref = output_id.as_output_ref();
        let mut store = FakeOutputLockStore::new();
        store.locks.insert(
            output_ref,
            FakeLock {
                owner: LockOwner::new([0xf3; 32]),
                expiry: BlockHeight::from_u32(u32::MAX),
            },
        );
        let mut bridge = OutputLockStoreBridge::new(
            FakeNoteSource {
                notes: vec![note(13)],
            },
            store,
        );
        assert!(matches!(
            CoppiceLockBackend::ensure_coppice_lock(
                &mut bridge,
                &output_id,
                tag(13),
                BlockHeight::from_u32(u32::MAX),
            ),
            Err(OutputLockBackendError::LockConflict(output)) if output == output_ref
        ));

        let mut storage_bridge = OutputLockStoreBridge::new(
            FakeNoteSource {
                notes: vec![note(13)],
            },
            FakeOutputLockStore {
                fail_storage: true,
                ..FakeOutputLockStore::new()
            },
        );
        assert!(matches!(
            CoppiceLockBackend::ensure_coppice_lock(
                &mut storage_bridge,
                &output_id,
                tag(13),
                BlockHeight::from_u32(u32::MAX),
            ),
            Err(OutputLockBackendError::Storage(FakeStoreError::Storage))
        ));
    }

    #[test]
    fn output_lock_store_bridge_unlocks_only_exact_owner_and_false_is_harmless() {
        let output_id = note(14).output_id;
        let output_ref = output_id.as_output_ref();
        let foreign = LockOwner::new([0xf4; 32]);
        let mut store = FakeOutputLockStore::new();
        store.locks.insert(
            output_ref,
            FakeLock {
                owner: foreign,
                expiry: BlockHeight::from_u32(u32::MAX),
            },
        );
        let mut bridge = OutputLockStoreBridge::new(
            FakeNoteSource {
                notes: vec![note(14)],
            },
            store,
        );

        assert!(
            !CoppiceLockBackend::remove_coppice_lock(&mut bridge, &output_id, tag(14),).unwrap()
        );
        assert_eq!(bridge.lock_store().locks[&output_ref].owner, foreign);

        let mut own_bridge = OutputLockStoreBridge::new(
            FakeNoteSource {
                notes: vec![note(14)],
            },
            FakeOutputLockStore::new(),
        );
        CoppiceLockBackend::ensure_coppice_lock(
            &mut own_bridge,
            &output_id,
            tag(14),
            BlockHeight::from_u32(u32::MAX),
        )
        .unwrap();
        assert!(
            CoppiceLockBackend::remove_coppice_lock(&mut own_bridge, &output_id, tag(14),).unwrap()
        );
        assert!(
            !CoppiceLockBackend::remove_coppice_lock(&mut own_bridge, &output_id, tag(14),)
                .unwrap()
        );
    }

    #[test]
    fn reconciliation_through_bridge_never_calls_generic_clear() {
        let output_id = note(15).output_id;
        let old_tag = tag(15);
        let mut store = FakeOutputLockStore::new();
        store.locks.insert(
            output_id.as_output_ref(),
            FakeLock {
                owner: lock_owner_for_bond(old_tag),
                expiry: BlockHeight::from_u32(u32::MAX),
            },
        );
        let mut bridge = OutputLockStoreBridge::new(
            FakeNoteSource {
                notes: vec![note(15)],
            },
            store,
        );
        let report = reconcile_locks(
            &BTreeSet::new(),
            &empty_pending(),
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut bridge,
        )
        .unwrap();
        assert_eq!(report.removed_locks, 1);
        assert!(bridge.lock_store().locks.is_empty());
        assert_eq!(bridge.lock_store().clear_calls, 0);
    }
}
