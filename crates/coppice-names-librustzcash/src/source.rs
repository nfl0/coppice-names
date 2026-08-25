use std::{collections::BTreeSet, fmt::Debug};

use orchard::keys::FullViewingKey;
use zcash_client_backend::{
    data_api::{
        InputSource, OutputLockStore,
        wallet::{TargetHeight, input_selection::LockFilter},
    },
    wallet::{Note, ReceivedNote},
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::{PoolType, ShieldedPool, value::BalanceError};

use crate::{
    IronwoodOutputId, IronwoodViewingCapability, OwnedIronwoodNote,
    inventory::OwnedIronwoodNoteSource,
};

/// Conversion failures for a public librustzcash received Ironwood note.
///
/// These diagnostics contain only the ephemeral output identity and public
/// conversion errors. They never carry note plaintext, nullifiers, or key
/// material.
#[derive(Debug)]
pub enum IronwoodNoteConversionError {
    InvalidValue {
        output_id: IronwoodOutputId,
        source: BalanceError,
    },
    InvalidPosition {
        output_id: IronwoodOutputId,
        position: u64,
    },
    NonCanonicalNullifier {
        output_id: IronwoodOutputId,
        source: coppice::bond_tag::BondTagError,
    },
}

/// Errors returned by [`InputSourceIronwoodNoteSource`].
#[derive(Debug)]
pub enum IronwoodNoteSourceError<WalletError, LockError> {
    InsufficientViewingCapability,
    MissingOrchardFullViewingKey,
    WalletInventoryBackend(WalletError),
    WalletLockBackend(LockError),
    UnexpectedPool {
        output_id: IronwoodOutputId,
        pool: ShieldedPool,
    },
    InconsistentSpendableNote {
        output_id: IronwoodOutputId,
    },
    NoteConversion(IronwoodNoteConversionError),
}

/// A read-only owned Ironwood-note source composed from the pinned public
/// `InputSource` and `OutputLockStore` traits.
///
/// `InputSource::select_unspent_notes` is called for Ironwood only with
/// `LockFilter::Unfiltered`, so already-locked notes remain reconstructible.
/// Lock membership is read once from `OutputLockStore::get_locked_outputs`;
/// ownership is intentionally not inspected here.
pub struct InputSourceIronwoodNoteSource<'a, Source, Locks>
where
    Source: InputSource,
    Locks: OutputLockStore<AccountId = Source::AccountId>,
{
    input_source: &'a Source,
    lock_store: &'a Locks,
    account: Source::AccountId,
    target_height: TargetHeight,
    orchard_fvk: &'a FullViewingKey,
    capability: IronwoodViewingCapability,
}

impl<'a, Source, Locks> InputSourceIronwoodNoteSource<'a, Source, Locks>
where
    Source: InputSource,
    Locks: OutputLockStore<AccountId = Source::AccountId>,
{
    /// Constructs a source from the actual Orchard full viewing key used for
    /// local nullifier derivation. The spending key is not required.
    pub fn new(
        input_source: &'a Source,
        lock_store: &'a Locks,
        account: Source::AccountId,
        target_height: TargetHeight,
        orchard_fvk: &'a FullViewingKey,
        capability: IronwoodViewingCapability,
    ) -> Self {
        Self {
            input_source,
            lock_store,
            account,
            target_height,
            orchard_fvk,
            capability,
        }
    }

    /// Constructs a source from the pinned public Orchard component of a
    /// unified full viewing key. An incoming viewing key is not accepted by
    /// this API and cannot be mistaken for an FVK.
    pub fn from_ufvk(
        input_source: &'a Source,
        lock_store: &'a Locks,
        account: Source::AccountId,
        target_height: TargetHeight,
        ufvk: &'a UnifiedFullViewingKey,
        capability: IronwoodViewingCapability,
    ) -> Result<Self, IronwoodNoteSourceError<Source::Error, Locks::Error>> {
        let orchard_fvk = ufvk
            .orchard()
            .ok_or(IronwoodNoteSourceError::MissingOrchardFullViewingKey)?;
        Ok(Self::new(
            input_source,
            lock_store,
            account,
            target_height,
            orchard_fvk,
            capability,
        ))
    }
}

impl<'a, Source, Locks> OwnedIronwoodNoteSource for InputSourceIronwoodNoteSource<'a, Source, Locks>
where
    Source: InputSource,
    Source::Error: Debug,
    Locks: OutputLockStore<AccountId = Source::AccountId>,
    Locks::Error: Debug,
{
    type Error = IronwoodNoteSourceError<Source::Error, Locks::Error>;

    fn owned_unspent_ironwood_notes(&self) -> Result<Vec<OwnedIronwoodNote>, Self::Error> {
        // This check is intentionally before both public backend reads. An
        // incoming-only key must not be turned into an empty inventory.
        if self.capability == IronwoodViewingCapability::IncomingOnly {
            return Err(IronwoodNoteSourceError::InsufficientViewingCapability);
        }

        let locked_outputs = self
            .lock_store
            .get_locked_outputs(self.account)
            .map_err(IronwoodNoteSourceError::WalletLockBackend)?
            .into_iter()
            .filter(|output| output.pool() == PoolType::IRONWOOD)
            .collect::<BTreeSet<_>>();

        let received = self
            .input_source
            .select_unspent_notes(
                self.account,
                &[ShieldedPool::Ironwood],
                self.target_height,
                &[],
                LockFilter::Unfiltered,
            )
            .map_err(IronwoodNoteSourceError::WalletInventoryBackend)?;

        let mut notes = Vec::with_capacity(received.ironwood().len());
        for received_note in received.ironwood() {
            let output_id = output_id_from_received(received_note);
            let spendable = self
                .input_source
                .get_spendable_note(
                    received_note.txid(),
                    ShieldedPool::Ironwood,
                    u32::from(received_note.output_index()),
                    self.target_height,
                    LockFilter::Unfiltered,
                )
                .map_err(IronwoodNoteSourceError::WalletInventoryBackend)?
                .map(|spendable_note| {
                    ensure_spendable_note_matches(received_note, &spendable_note, output_id)
                        .map_err(|error| match error {
                            SpendableNoteError::UnexpectedPool { output_id, pool } => {
                                IronwoodNoteSourceError::UnexpectedPool { output_id, pool }
                            }
                            SpendableNoteError::Inconsistent { output_id } => {
                                IronwoodNoteSourceError::InconsistentSpendableNote { output_id }
                            }
                        })
                        .map(|()| true)
                })
                .transpose()?
                .unwrap_or(false);

            notes.push(
                convert_ironwood_received_note(
                    received_note,
                    self.orchard_fvk,
                    locked_outputs.contains(&output_id.as_output_ref()),
                    spendable,
                )
                .map_err(IronwoodNoteSourceError::NoteConversion)?,
            );
        }

        notes.sort_by_key(|note| note.output_id);
        Ok(notes)
    }
}

fn output_id_from_received<NoteRef, NoteT>(
    received: &ReceivedNote<NoteRef, NoteT>,
) -> IronwoodOutputId {
    let txid = *received.txid().as_ref();
    IronwoodOutputId::new(txid, u32::from(received.output_index()))
}

fn convert_ironwood_received_note<NoteRef>(
    received: &ReceivedNote<NoteRef, orchard::note::Note>,
    orchard_fvk: &FullViewingKey,
    locked: bool,
    spendable: bool,
) -> Result<OwnedIronwoodNote, IronwoodNoteConversionError> {
    let output_id = output_id_from_received(received);
    let value_zat = received
        .note_value()
        .map_err(|source| IronwoodNoteConversionError::InvalidValue { output_id, source })?
        .into_u64();
    let raw_position = u64::from(received.note_commitment_tree_position());
    let position =
        u32::try_from(raw_position).map_err(|_| IronwoodNoteConversionError::InvalidPosition {
            output_id,
            position: raw_position,
        })?;
    let nullifier = received.note().nullifier(orchard_fvk).to_bytes();
    coppice::bond_tag::derive_v1_bond_tag(&nullifier).map_err(|source| {
        IronwoodNoteConversionError::NonCanonicalNullifier { output_id, source }
    })?;

    Ok(OwnedIronwoodNote {
        output_id,
        value_zat,
        nullifier,
        position: Some(position),
        locked,
        spendable,
    })
}

#[derive(Debug)]
enum SpendableNoteError {
    UnexpectedPool {
        output_id: IronwoodOutputId,
        pool: ShieldedPool,
    },
    Inconsistent {
        output_id: IronwoodOutputId,
    },
}

fn ensure_spendable_note_matches<NoteRef, NoteT>(
    enumerated: &ReceivedNote<NoteRef, NoteT>,
    spendable: &ReceivedNote<NoteRef, Note>,
    output_id: IronwoodOutputId,
) -> Result<(), SpendableNoteError>
where
    NoteRef: Eq,
{
    if spendable.note().pool() != ShieldedPool::Ironwood {
        return Err(SpendableNoteError::UnexpectedPool {
            output_id,
            pool: spendable.note().pool(),
        });
    }

    if spendable.internal_note_id() != enumerated.internal_note_id()
        || spendable.txid() != enumerated.txid()
        || spendable.output_index() != enumerated.output_index()
    {
        return Err(SpendableNoteError::Inconsistent { output_id });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, collections::BTreeMap};

    use incrementalmerkletree::Position;
    use orchard::{
        ValuePool,
        keys::{FullViewingKey, SpendingKey},
        note::{Note, NoteVersion, RandomSeed, Rho},
        value::NoteValue,
    };
    use zcash_client_backend::{
        data_api::{
            AccountMeta, InputSource, NoteFilter, OutputLockStore, ReceivedNotes, TargetValue,
            error::LockError,
            wallet::{ConfirmationsPolicy, TargetHeight},
        },
        wallet::{Note as WalletNote, OutputRef, ReceivedNote},
    };
    use zcash_protocol::{PoolType, ShieldedPool, TxId, consensus::BlockHeight};
    use zip32::Scope;

    use super::*;

    #[derive(Default)]
    struct FakeSource {
        notes: Vec<ReceivedNote<u32, Note>>,
        spendable: BTreeMap<(TxId, u32), Option<ReceivedNote<u32, WalletNote>>>,
        select_calls: Cell<usize>,
        select_target: Cell<Option<u32>>,
        spendable_calls: Cell<usize>,
    }

    impl InputSource for FakeSource {
        type Error = ();
        type AccountId = u32;
        type NoteRef = u32;

        fn get_spendable_note(
            &self,
            txid: &TxId,
            _protocol: ShieldedPool,
            index: u32,
            _target_height: TargetHeight,
            _lock_filter: LockFilter<'_>,
        ) -> Result<Option<ReceivedNote<Self::NoteRef, WalletNote>>, Self::Error> {
            self.spendable_calls.set(self.spendable_calls.get() + 1);
            Ok(self.spendable.get(&(*txid, index)).cloned().flatten())
        }

        fn anchor_computable(
            &self,
            _protocol: ShieldedPool,
            _height: BlockHeight,
        ) -> Result<bool, Self::Error> {
            Ok(false)
        }

        fn select_spendable_notes(
            &self,
            _account: Self::AccountId,
            _target_value: TargetValue,
            _sources: &[ShieldedPool],
            _target_height: TargetHeight,
            _confirmations_policy: ConfirmationsPolicy,
            _exclude: &[Self::NoteRef],
            _lock_filter: LockFilter<'_>,
        ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
            Ok(ReceivedNotes::empty())
        }

        fn select_unspent_notes(
            &self,
            _account: Self::AccountId,
            _sources: &[ShieldedPool],
            target_height: TargetHeight,
            _exclude: &[Self::NoteRef],
            _lock_filter: LockFilter<'_>,
        ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
            self.select_calls.set(self.select_calls.get() + 1);
            self.select_target
                .set(Some(BlockHeight::from(target_height).into()));
            Ok(ReceivedNotes::new(vec![], vec![], self.notes.clone()))
        }

        fn get_account_metadata(
            &self,
            _account: Self::AccountId,
            _selector: &NoteFilter,
            _target_height: TargetHeight,
            _exclude: &[Self::NoteRef],
            _lock_filter: LockFilter<'_>,
        ) -> Result<AccountMeta, Self::Error> {
            Err(())
        }
    }

    #[derive(Default)]
    struct FakeLocks {
        locked: Vec<OutputRef>,
        reads: Cell<usize>,
    }

    impl OutputLockStore for FakeLocks {
        type Error = ();
        type AccountId = u32;

        fn lock_outputs(
            &mut self,
            _outputs: &[OutputRef],
            _owner: zcash_client_backend::wallet::LockOwner,
            _lock_expiry_height: BlockHeight,
        ) -> Result<usize, LockError<Self::Error>> {
            Ok(0)
        }

        fn unlock_output(
            &mut self,
            _output: &OutputRef,
            _owner: zcash_client_backend::wallet::LockOwner,
        ) -> Result<bool, Self::Error> {
            Ok(false)
        }

        fn clear_locked_outputs(
            &mut self,
            _account: Self::AccountId,
        ) -> Result<usize, Self::Error> {
            Ok(0)
        }

        fn get_locked_outputs(
            &self,
            _account: Self::AccountId,
        ) -> Result<Vec<OutputRef>, Self::Error> {
            self.reads.set(self.reads.get() + 1);
            Ok(self.locked.clone())
        }
    }

    #[derive(Default)]
    struct CombinedWallet {
        source: FakeSource,
        locks: BTreeMap<OutputRef, (zcash_client_backend::wallet::LockOwner, BlockHeight)>,
        lock_reads: Cell<usize>,
    }

    impl InputSource for CombinedWallet {
        type Error = ();
        type AccountId = u32;
        type NoteRef = u32;

        fn get_spendable_note(
            &self,
            txid: &TxId,
            protocol: ShieldedPool,
            index: u32,
            target_height: TargetHeight,
            lock_filter: LockFilter<'_>,
        ) -> Result<Option<ReceivedNote<Self::NoteRef, WalletNote>>, Self::Error> {
            self.source
                .get_spendable_note(txid, protocol, index, target_height, lock_filter)
        }

        fn anchor_computable(
            &self,
            protocol: ShieldedPool,
            height: BlockHeight,
        ) -> Result<bool, Self::Error> {
            self.source.anchor_computable(protocol, height)
        }

        fn select_spendable_notes(
            &self,
            account: Self::AccountId,
            target_value: TargetValue,
            sources: &[ShieldedPool],
            target_height: TargetHeight,
            confirmations_policy: ConfirmationsPolicy,
            exclude: &[Self::NoteRef],
            lock_filter: LockFilter<'_>,
        ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
            self.source.select_spendable_notes(
                account,
                target_value,
                sources,
                target_height,
                confirmations_policy,
                exclude,
                lock_filter,
            )
        }

        fn select_unspent_notes(
            &self,
            account: Self::AccountId,
            sources: &[ShieldedPool],
            target_height: TargetHeight,
            exclude: &[Self::NoteRef],
            lock_filter: LockFilter<'_>,
        ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
            self.source
                .select_unspent_notes(account, sources, target_height, exclude, lock_filter)
        }

        fn get_account_metadata(
            &self,
            account: Self::AccountId,
            selector: &NoteFilter,
            target_height: TargetHeight,
            exclude: &[Self::NoteRef],
            lock_filter: LockFilter<'_>,
        ) -> Result<AccountMeta, Self::Error> {
            self.source
                .get_account_metadata(account, selector, target_height, exclude, lock_filter)
        }
    }

    impl OutputLockStore for CombinedWallet {
        type Error = ();
        type AccountId = u32;

        fn lock_outputs(
            &mut self,
            outputs: &[OutputRef],
            owner: zcash_client_backend::wallet::LockOwner,
            expiry: BlockHeight,
        ) -> Result<usize, LockError<Self::Error>> {
            if let Some(conflict) = outputs.iter().find(|output| {
                self.locks
                    .get(output)
                    .is_some_and(|(existing, _)| *existing != owner)
            }) {
                return Err(LockError::LockFailure(*conflict));
            }
            for output in outputs {
                self.locks.insert(*output, (owner, expiry));
            }
            Ok(outputs.len())
        }

        fn unlock_output(
            &mut self,
            output: &OutputRef,
            owner: zcash_client_backend::wallet::LockOwner,
        ) -> Result<bool, Self::Error> {
            if self
                .locks
                .get(output)
                .is_some_and(|(existing, _)| *existing == owner)
            {
                self.locks.remove(output);
                Ok(true)
            } else {
                Ok(false)
            }
        }

        fn clear_locked_outputs(
            &mut self,
            _account: Self::AccountId,
        ) -> Result<usize, Self::Error> {
            panic!("Coppice must never call clear_locked_outputs")
        }

        fn get_locked_outputs(
            &self,
            _account: Self::AccountId,
        ) -> Result<Vec<OutputRef>, Self::Error> {
            self.lock_reads.set(self.lock_reads.get() + 1);
            Ok(self.locks.keys().copied().collect())
        }
    }

    fn fvk() -> FullViewingKey {
        let spending_key = SpendingKey::from_bytes([7; 32]).unwrap();
        FullViewingKey::from(&spending_key)
    }

    fn note(fvk: &FullViewingKey, id: u32, value: u64) -> ReceivedNote<u32, Note> {
        let rho = Rho::from_bytes(&[id as u8 + 1; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([id as u8 + 2; 32], &rho).unwrap();
        let note = Note::from_parts(
            fvk.address_at(id, Scope::External),
            NoteValue::from_raw(value),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        ReceivedNote::from_parts(
            id,
            TxId::from_bytes([id as u8; 32]),
            id as u16,
            note,
            Scope::External,
            Position::from(u64::from(id)),
            Some(BlockHeight::from_u32(1)),
            None,
        )
    }

    fn wallet_note(
        received: &ReceivedNote<u32, Note>,
        pool: ValuePool,
    ) -> ReceivedNote<u32, WalletNote> {
        received
            .clone()
            .map_note(|note| WalletNote::Orchard { note, pool })
    }

    fn source<'a>(
        input: &'a FakeSource,
        locks: &'a FakeLocks,
        fvk: &'a FullViewingKey,
        capability: IronwoodViewingCapability,
    ) -> InputSourceIronwoodNoteSource<'a, FakeSource, FakeLocks> {
        InputSourceIronwoodNoteSource::new(
            input,
            locks,
            0,
            TargetHeight::from(BlockHeight::from_u32(10)),
            fvk,
            capability,
        )
    }

    #[test]
    fn one_wallet_facade_reuses_inventory_and_mutates_the_same_lock_store() {
        use crate::{CoppiceLockBackend, WalletCoppiceLockBackend, lock_owner_for_bond};

        let key = fvk();
        let received = note(&key, 4, 500);
        let mut wallet = CombinedWallet::default();
        wallet.source.notes.push(received.clone());
        wallet.source.spendable.insert(
            (*received.txid(), u32::from(received.output_index())),
            Some(wallet_note(&received, ValuePool::Ironwood)),
        );
        let target = TargetHeight::from(BlockHeight::from_u32(77));
        let mut facade = WalletCoppiceLockBackend::new(
            &mut wallet,
            0,
            target,
            &key,
            IronwoodViewingCapability::FullViewing,
        );
        assert_eq!(facade.target_height(), target);
        let notes = facade.owned_unspent_ironwood_notes().unwrap();
        assert_eq!(notes.len(), 1);
        let output = notes[0].output_id;
        let tag = coppice::bond_tag::derive_v1_bond_tag(&notes[0].nullifier).unwrap();
        facade
            .ensure_coppice_lock(&output, tag, facade.max_lock_expiry_height())
            .unwrap();
        assert_eq!(
            facade.wallet_db_mut().locks[&output.as_output_ref()].0,
            lock_owner_for_bond(tag)
        );
        assert!(facade.remove_coppice_lock(&output, tag).unwrap());
        assert!(facade.wallet_db_mut().locks.is_empty());
        assert_eq!(facade.wallet_db_mut().lock_reads.get(), 1);
        assert_eq!(facade.wallet_db_mut().source.select_target.get(), Some(77));
    }

    #[test]
    fn output_ref_round_trip_preserves_exact_ironwood_identity() {
        let output_id = IronwoodOutputId::new([9; 32], u32::from(u16::MAX) + 1);
        let output = output_id.as_output_ref();
        assert_eq!(*output.txid(), TxId::from_bytes([9; 32]));
        assert_eq!(output.pool(), PoolType::IRONWOOD);
        assert_eq!(output.output_index(), u32::from(u16::MAX) + 1);
    }

    #[test]
    fn source_derives_canonical_nullifier_and_orders_notes() {
        let key = fvk();
        let first = note(&key, 1, 100);
        let second = note(&key, 2, 200);
        let mut input = FakeSource {
            notes: vec![second.clone(), first.clone()],
            ..Default::default()
        };
        input.spendable.insert(
            (*first.txid(), u32::from(first.output_index())),
            Some(wallet_note(&first, ValuePool::Ironwood)),
        );
        input.spendable.insert(
            (*second.txid(), u32::from(second.output_index())),
            Some(wallet_note(&second, ValuePool::Ironwood)),
        );
        let locks = FakeLocks::default();
        let notes = source(&input, &locks, &key, IronwoodViewingCapability::FullViewing)
            .owned_unspent_ironwood_notes()
            .unwrap();

        assert_eq!(notes.len(), 2);
        assert!(
            notes
                .windows(2)
                .all(|window| window[0].output_id < window[1].output_id)
        );
        assert_eq!(notes[0].value_zat, 100);
        assert_eq!(notes[1].value_zat, 200);
        for (owned, received) in notes.iter().zip([first, second]) {
            let expected = received.note().nullifier(&key).to_bytes();
            assert_eq!(owned.nullifier, expected);
            assert_eq!(
                coppice::bond_tag::derive_v1_bond_tag(&owned.nullifier).unwrap(),
                coppice::bond_tag::derive_v1_bond_tag(&expected).unwrap()
            );
            assert_eq!(
                owned.position,
                Some(u32::try_from(u64::from(received.note_commitment_tree_position())).unwrap())
            );
        }
    }

    #[test]
    fn full_viewing_and_spending_use_the_same_explicit_fvk() {
        let key = fvk();
        let received = note(&key, 5, 321);
        let mut input = FakeSource {
            notes: vec![received.clone()],
            ..Default::default()
        };
        input.spendable.insert(
            (*received.txid(), u32::from(received.output_index())),
            Some(wallet_note(&received, ValuePool::Ironwood)),
        );
        let locks = FakeLocks::default();

        let full = source(&input, &locks, &key, IronwoodViewingCapability::FullViewing)
            .owned_unspent_ironwood_notes()
            .unwrap();
        let spending = source(&input, &locks, &key, IronwoodViewingCapability::Spending)
            .owned_unspent_ironwood_notes()
            .unwrap();
        assert_eq!(full, spending);
    }

    #[test]
    fn locked_outputs_are_included_and_pool_filtered() {
        let key = fvk();
        let received = note(&key, 3, 100);
        let output = IronwoodOutputId::new(
            *received.txid().as_ref(),
            u32::from(received.output_index()),
        );
        let other_pool = OutputRef::new(*received.txid(), PoolType::ORCHARD, output.output_index());
        let mut input = FakeSource {
            notes: vec![received.clone()],
            ..Default::default()
        };
        input.spendable.insert(
            (*received.txid(), u32::from(received.output_index())),
            Some(wallet_note(&received, ValuePool::Ironwood)),
        );
        let locks = FakeLocks {
            locked: vec![other_pool, output.as_output_ref()],
            ..Default::default()
        };
        let notes = source(&input, &locks, &key, IronwoodViewingCapability::Spending)
            .owned_unspent_ironwood_notes()
            .unwrap();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].locked);
        assert!(notes[0].spendable);
        assert_eq!(input.select_calls.get(), 1);
        assert_eq!(locks.reads.get(), 1);
    }

    #[test]
    fn incoming_only_fails_before_source_or_lock_reads() {
        let key = fvk();
        let input = FakeSource::default();
        let locks = FakeLocks::default();
        let error = source(
            &input,
            &locks,
            &key,
            IronwoodViewingCapability::IncomingOnly,
        )
        .owned_unspent_ironwood_notes()
        .unwrap_err();
        assert!(matches!(
            error,
            IronwoodNoteSourceError::InsufficientViewingCapability
        ));
        assert_eq!(input.select_calls.get(), 0);
        assert_eq!(locks.reads.get(), 0);
    }

    #[test]
    fn non_ironwood_spendable_result_is_rejected() {
        let key = fvk();
        let received = note(&key, 4, 100);
        let mut input = FakeSource {
            notes: vec![received.clone()],
            ..Default::default()
        };
        input.spendable.insert(
            (*received.txid(), u32::from(received.output_index())),
            Some(wallet_note(&received, ValuePool::Orchard)),
        );
        let locks = FakeLocks::default();
        let error = source(&input, &locks, &key, IronwoodViewingCapability::FullViewing)
            .owned_unspent_ironwood_notes()
            .unwrap_err();
        assert!(matches!(
            error,
            IronwoodNoteSourceError::UnexpectedPool {
                pool: ShieldedPool::Orchard,
                ..
            }
        ));
    }

    #[test]
    fn an_unspent_note_without_a_spendable_result_is_not_spendable() {
        let key = fvk();
        let received = note(&key, 6, 100);
        let input = FakeSource {
            notes: vec![received],
            ..Default::default()
        };
        let locks = FakeLocks::default();
        let notes = source(&input, &locks, &key, IronwoodViewingCapability::FullViewing)
            .owned_unspent_ironwood_notes()
            .unwrap();
        assert_eq!(notes.len(), 1);
        assert!(!notes[0].spendable);
    }
}
