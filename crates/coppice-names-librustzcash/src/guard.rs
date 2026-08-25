use std::fmt::Debug;

use coppice::names_runtime::{CoreReplayTip, NamesRuntime};

use crate::{
    CoppiceLockBackend, IronwoodViewingCapability, PendingRegistrationCollection,
    ReconciliationError, ReconciliationReport, WalletAccountId, active_canonical_bond_tags,
    reconcile_locks,
};

/// The host wallet's selected canonical chain tip.
///
/// The hash is kept in canonical byte order. This type contains no display or
/// UI representation of a block hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletCanonicalTip {
    pub height: u32,
    pub block_hash: [u8; 32],
}

impl From<CoreReplayTip> for WalletCanonicalTip {
    fn from(tip: CoreReplayTip) -> Self {
        Self {
            height: tip.height,
            block_hash: tip.block_hash,
        }
    }
}

/// Reads the host wallet's already-selected canonical tip.
pub trait HostCanonicalTipSource {
    type Error: Debug;

    fn canonical_tip(&self) -> Result<WalletCanonicalTip, Self::Error>;
}

/// Exact canonical-tip comparison shared by every mutation-capable adapter
/// workflow.
#[derive(Debug)]
pub enum ExactCanonicalTipError<E> {
    HostTipUnavailable(E),
    HeightMismatch {
        host_height: u32,
        coppice_height: u32,
    },
    BlockHashMismatch {
        height: u32,
        host_block_hash: [u8; 32],
        coppice_block_hash: [u8; 32],
    },
}

pub fn require_exact_canonical_tip<Host: HostCanonicalTipSource>(
    host_tip_source: &Host,
    runtime: &NamesRuntime,
) -> Result<WalletCanonicalTip, ExactCanonicalTipError<Host::Error>> {
    let host_tip = host_tip_source
        .canonical_tip()
        .map_err(ExactCanonicalTipError::HostTipUnavailable)?;
    let coppice_tip = WalletCanonicalTip::from(runtime.tip());
    if host_tip.height != coppice_tip.height {
        return Err(ExactCanonicalTipError::HeightMismatch {
            host_height: host_tip.height,
            coppice_height: coppice_tip.height,
        });
    }
    if host_tip.block_hash != coppice_tip.block_hash {
        return Err(ExactCanonicalTipError::BlockHashMismatch {
            height: host_tip.height,
            host_block_hash: host_tip.block_hash,
            coppice_block_hash: coppice_tip.block_hash,
        });
    }
    Ok(host_tip)
}

/// Runtime protection mode at the adapter boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoppiceProtectionMode {
    /// Full Coppice functionality and ordinary-send protection.
    Enabled,
    /// Management UI may be hidden, but ordinary-send protection remains on.
    GuardOnly,
    /// Coppice is not participating in this spend path.
    Off,
}

impl CoppiceProtectionMode {
    fn protects_spend(self) -> bool {
        matches!(self, Self::Enabled | Self::GuardOnly)
    }
}

/// Fail-closed errors from the protected proposal boundary.
#[derive(Debug)]
pub enum SpendGuardError<HostError, BackendError: Debug> {
    HostTipUnavailable(HostError),
    HeightMismatch {
        host_height: u32,
        coppice_height: u32,
    },
    BlockHashMismatch {
        height: u32,
        host_block_hash: [u8; 32],
        coppice_block_hash: [u8; 32],
    },
    ReconciliationFailed(ReconciliationError<BackendError>),
}

/// Runs a proposal callback only after the protected Coppice preconditions
/// have succeeded.
///
/// `Off` deliberately does not read the host tip, runtime state, or lock
/// backend. `Enabled` and `GuardOnly` always perform exact tip comparison and
/// a fresh lock reconciliation before invoking `proposal_fn`; this also repairs
/// locks that were cleared by an external generic wallet recovery operation.
/// The callback receives that same reconciled mutable backend, allowing one
/// concrete wallet object to continue directly into proposal construction.
#[allow(clippy::type_complexity)]
// The explicit account/capability/backend arguments are security boundaries;
// grouping them would make it easier to compose facts from different accounts.
#[allow(clippy::too_many_arguments)]
pub fn with_coppice_spend_guard<Host, Backend, Proposal>(
    mode: CoppiceProtectionMode,
    host_tip_source: &Host,
    runtime: &NamesRuntime,
    pending: &PendingRegistrationCollection,
    account_id: WalletAccountId,
    capability: IronwoodViewingCapability,
    lock_backend: &mut Backend,
    proposal_fn: impl FnOnce(&mut Backend) -> Proposal,
) -> Result<(Proposal, Option<ReconciliationReport>), SpendGuardError<Host::Error, Backend::Error>>
where
    Host: HostCanonicalTipSource,
    Backend: CoppiceLockBackend,
{
    if !mode.protects_spend() {
        return Ok((proposal_fn(lock_backend), None));
    }

    require_exact_canonical_tip(host_tip_source, runtime).map_err(|error| match error {
        ExactCanonicalTipError::HostTipUnavailable(error) => {
            SpendGuardError::HostTipUnavailable(error)
        }
        ExactCanonicalTipError::HeightMismatch {
            host_height,
            coppice_height,
        } => SpendGuardError::HeightMismatch {
            host_height,
            coppice_height,
        },
        ExactCanonicalTipError::BlockHashMismatch {
            height,
            host_block_hash,
            coppice_block_hash,
        } => SpendGuardError::BlockHashMismatch {
            height,
            host_block_hash,
            coppice_block_hash,
        },
    })?;

    let active_tags = active_canonical_bond_tags(runtime);
    let report = reconcile_locks(&active_tags, pending, account_id, capability, lock_backend)
        .map_err(SpendGuardError::ReconciliationFailed)?;
    Ok((proposal_fn(lock_backend), Some(report)))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use coppice::{
        config::{DeploymentParameters, REGTEST, Rendezvous},
        constants::REGTEST_ACTIVATION_HEIGHT,
        names_runtime::{CoreReplayActivationCheckpoint, IronwoodFrontier, NamesRuntime},
        owner::{OwnerSigningKey, owner_key_bytes},
        registration::registration_commitment,
    };
    use zcash_client_backend::wallet::LockOwner;
    use zcash_protocol::consensus::{BlockHeight, NetworkType};

    use super::*;
    use crate::{
        IronwoodOutputId, OwnedIronwoodNote, PendingRegistration, PendingRegistrationCollection,
        lock_owner_for_bond,
    };

    const ADDRESS: &[u8] = b"uregtest15zjdhgeu9vfwkrgxvxyuynkprgryyww0cl668tpj0ykhl7nvvh7v7ln89f0v8c36vwyffxglg24zh5d4622ela80w065cc28mv7gf423";

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FakeLock {
        owner: LockOwner,
        expiry: BlockHeight,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum BackendError {
        ForeignLock,
        Storage,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct FakeBackend {
        notes: Vec<OwnedIronwoodNote>,
        locks: BTreeMap<IronwoodOutputId, FakeLock>,
        fail_inventory: bool,
        fail_lock: bool,
    }

    impl FakeBackend {
        fn new(notes: Vec<OwnedIronwoodNote>) -> Self {
            Self {
                notes,
                locks: BTreeMap::new(),
                fail_inventory: false,
                fail_lock: false,
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
            self
        }
    }

    impl CoppiceLockBackend for FakeBackend {
        type Error = BackendError;

        fn owned_unspent_ironwood_notes(&self) -> Result<Vec<OwnedIronwoodNote>, Self::Error> {
            if self.fail_inventory {
                Err(BackendError::Storage)
            } else {
                Ok(self.notes.clone())
            }
        }

        fn ensure_coppice_lock(
            &mut self,
            output_id: &IronwoodOutputId,
            bond_tag: [u8; 32],
            expiry_height: BlockHeight,
        ) -> Result<(), Self::Error> {
            if self.fail_lock {
                return Err(BackendError::Storage);
            }
            let owner = lock_owner_for_bond(bond_tag);
            if self
                .locks
                .get(output_id)
                .is_some_and(|lock| lock.owner != owner)
            {
                return Err(BackendError::ForeignLock);
            }
            self.locks.insert(
                *output_id,
                FakeLock {
                    owner,
                    expiry: expiry_height,
                },
            );
            Ok(())
        }

        fn remove_coppice_lock(
            &mut self,
            output_id: &IronwoodOutputId,
            bond_tag: [u8; 32],
        ) -> Result<bool, Self::Error> {
            let owner = lock_owner_for_bond(bond_tag);
            if self
                .locks
                .get(output_id)
                .is_some_and(|lock| lock.owner == owner)
            {
                self.locks.remove(output_id);
                Ok(true)
            } else {
                Ok(false)
            }
        }

        fn max_lock_expiry_height(&self) -> BlockHeight {
            BlockHeight::from_u32(u32::MAX)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct HostError;

    struct FakeHost {
        result: Result<WalletCanonicalTip, HostError>,
    }

    impl HostCanonicalTipSource for FakeHost {
        type Error = HostError;

        fn canonical_tip(&self) -> Result<WalletCanonicalTip, Self::Error> {
            self.result
        }
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

    fn runtime() -> NamesRuntime {
        NamesRuntime::new(
            deployment(),
            CoreReplayActivationCheckpoint {
                height: REGTEST_ACTIVATION_HEIGHT - 1,
                block_hash: [9; 32],
                ironwood_frontier: IronwoodFrontier::empty(),
                ironwood_tree_size: 0,
            },
        )
        .unwrap()
    }

    fn matching_host(runtime: &NamesRuntime) -> FakeHost {
        FakeHost {
            result: Ok(runtime.tip().into()),
        }
    }

    fn account_id() -> WalletAccountId {
        WalletAccountId::from_bytes([0x11; 32])
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

    fn pending_for(bond_tag: [u8; 32]) -> PendingRegistration {
        let deployment = deployment();
        let key = OwnerSigningKey::try_from([1; 32]).unwrap();
        let owner_pk = owner_key_bytes(&(&key).into());
        let secret = [0xa5; 32];
        let commitment =
            registration_commitment(&deployment, "alice", owner_pk, bond_tag, ADDRESS, secret)
                .unwrap();
        PendingRegistration::new(
            &deployment,
            account_id(),
            "alice".to_owned(),
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

    fn tag(id: u8) -> [u8; 32] {
        coppice::bond_tag::derive_v1_bond_tag(&[id; 32]).unwrap()
    }

    fn run<Proposal>(
        mode: CoppiceProtectionMode,
        host: &FakeHost,
        pending: &PendingRegistrationCollection,
        backend: &mut FakeBackend,
        proposal: impl FnOnce(&mut FakeBackend) -> Proposal,
    ) -> Result<(Proposal, Option<ReconciliationReport>), SpendGuardError<HostError, BackendError>>
    {
        let runtime = runtime();
        with_coppice_spend_guard(
            mode,
            host,
            &runtime,
            pending,
            account_id(),
            IronwoodViewingCapability::FullViewing,
            backend,
            proposal,
        )
    }

    #[test]
    fn host_tip_failure_does_not_call_proposal() {
        let host = FakeHost {
            result: Err(HostError),
        };
        let mut backend = FakeBackend::new(Vec::new());
        let called = std::cell::Cell::new(0);
        let result = run(
            CoppiceProtectionMode::Enabled,
            &host,
            &empty_pending(),
            &mut backend,
            |_| {
                called.set(called.get() + 1);
            },
        );
        assert!(matches!(
            result,
            Err(SpendGuardError::HostTipUnavailable(_))
        ));
        assert_eq!(called.get(), 0);
    }

    #[test]
    fn height_mismatch_does_not_call_proposal() {
        let runtime = runtime();
        let host = FakeHost {
            result: Ok(WalletCanonicalTip {
                height: runtime.tip().height + 1,
                block_hash: runtime.tip().block_hash,
            }),
        };
        let mut backend = FakeBackend::new(Vec::new());
        let called = std::cell::Cell::new(0);
        let result = run(
            CoppiceProtectionMode::Enabled,
            &host,
            &empty_pending(),
            &mut backend,
            |_| called.set(called.get() + 1),
        );
        assert!(matches!(
            result,
            Err(SpendGuardError::HeightMismatch { .. })
        ));
        assert_eq!(called.get(), 0);
    }

    #[test]
    fn hash_mismatch_at_equal_height_does_not_call_proposal() {
        let runtime = runtime();
        let host = FakeHost {
            result: Ok(WalletCanonicalTip {
                height: runtime.tip().height,
                block_hash: [8; 32],
            }),
        };
        let mut backend = FakeBackend::new(Vec::new());
        let called = std::cell::Cell::new(0);
        let result = run(
            CoppiceProtectionMode::Enabled,
            &host,
            &empty_pending(),
            &mut backend,
            |_| called.set(called.get() + 1),
        );
        assert!(matches!(
            result,
            Err(SpendGuardError::BlockHashMismatch { .. })
        ));
        assert_eq!(called.get(), 0);
    }

    #[test]
    fn exact_tip_and_reconciliation_call_proposal_once() {
        let runtime = runtime();
        let host = matching_host(&runtime);
        let mut backend = FakeBackend::new(Vec::new());
        let called = std::cell::Cell::new(0);
        let result = run(
            CoppiceProtectionMode::Enabled,
            &host,
            &empty_pending(),
            &mut backend,
            |backend| {
                assert!(backend.locks.is_empty());
                called.set(called.get() + 1);
                42
            },
        )
        .unwrap();
        assert_eq!(called.get(), 1);
        assert_eq!(result.0, 42);
        assert!(result.1.is_some());
    }

    #[test]
    fn guard_only_has_the_same_proposal_gate_as_enabled() {
        let runtime = runtime();
        let host = FakeHost {
            result: Ok(WalletCanonicalTip {
                height: runtime.tip().height,
                block_hash: [8; 32],
            }),
        };
        let mut backend = FakeBackend::new(Vec::new());
        let called = std::cell::Cell::new(0);
        let result = run(
            CoppiceProtectionMode::GuardOnly,
            &host,
            &empty_pending(),
            &mut backend,
            |_| called.set(called.get() + 1),
        );
        assert!(matches!(
            result,
            Err(SpendGuardError::BlockHashMismatch { .. })
        ));
        assert_eq!(called.get(), 0);
    }

    #[test]
    fn off_bypasses_tip_and_reconciliation() {
        let host = FakeHost {
            result: Err(HostError),
        };
        let mut backend = FakeBackend {
            notes: Vec::new(),
            locks: BTreeMap::new(),
            fail_inventory: true,
            fail_lock: true,
        };
        let called = std::cell::Cell::new(0);
        let result = run(
            CoppiceProtectionMode::Off,
            &host,
            &empty_pending(),
            &mut backend,
            |backend| {
                assert!(backend.fail_inventory);
                assert!(backend.fail_lock);
                called.set(called.get() + 1);
                7
            },
        )
        .unwrap();
        assert_eq!(called.get(), 1);
        assert_eq!(result, (7, None));
    }

    #[test]
    fn incoming_only_fails_closed_before_proposal() {
        let runtime = runtime();
        let host = matching_host(&runtime);
        let mut backend = FakeBackend::new(Vec::new());
        let called = std::cell::Cell::new(0);
        let result = with_coppice_spend_guard(
            CoppiceProtectionMode::Enabled,
            &host,
            &runtime,
            &empty_pending(),
            account_id(),
            IronwoodViewingCapability::IncomingOnly,
            &mut backend,
            |_| called.set(called.get() + 1),
        );
        assert!(matches!(
            result,
            Err(SpendGuardError::ReconciliationFailed(
                ReconciliationError::Inventory(_)
            ))
        ));
        assert_eq!(called.get(), 0);
    }

    #[test]
    fn missing_pending_note_fails_closed_before_proposal() {
        let runtime = runtime();
        let host = matching_host(&runtime);
        let pending = collection_with(pending_for(tag(1)));
        let mut backend = FakeBackend::new(Vec::new());
        let called = std::cell::Cell::new(0);
        let result = with_coppice_spend_guard(
            CoppiceProtectionMode::Enabled,
            &host,
            &runtime,
            &pending,
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
            |_| called.set(called.get() + 1),
        );
        assert!(matches!(
            result,
            Err(SpendGuardError::ReconciliationFailed(
                ReconciliationError::MissingPendingBond { .. }
            ))
        ));
        assert_eq!(called.get(), 0);
    }

    #[test]
    fn generic_backend_failure_fails_closed_before_proposal() {
        let runtime = runtime();
        let host = matching_host(&runtime);
        let mut backend = FakeBackend {
            notes: Vec::new(),
            locks: BTreeMap::new(),
            fail_inventory: true,
            fail_lock: false,
        };
        let called = std::cell::Cell::new(0);
        let result = run(
            CoppiceProtectionMode::Enabled,
            &host,
            &empty_pending(),
            &mut backend,
            |_| called.set(called.get() + 1),
        );
        assert!(matches!(
            result,
            Err(SpendGuardError::ReconciliationFailed(
                ReconciliationError::Backend(BackendError::Storage)
            ))
        ));
        assert_eq!(called.get(), 0);
    }

    #[test]
    fn foreign_lock_conflict_fails_closed_and_preserves_foreign_lock() {
        let runtime = runtime();
        let host = matching_host(&runtime);
        let bond_tag = tag(2);
        let output_id = note(2).output_id;
        let foreign = LockOwner::new([0xf2; 32]);
        let pending = collection_with(pending_for(bond_tag));
        let mut backend = FakeBackend::new(vec![note(2)]).with_lock(output_id, foreign);
        let before = backend.clone();
        let called = std::cell::Cell::new(0);
        let result = with_coppice_spend_guard(
            CoppiceProtectionMode::Enabled,
            &host,
            &runtime,
            &pending,
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
            |_| called.set(called.get() + 1),
        );
        assert!(matches!(
            result,
            Err(SpendGuardError::ReconciliationFailed(
                ReconciliationError::Backend(BackendError::ForeignLock)
            ))
        ));
        assert_eq!(called.get(), 0);
        assert_eq!(backend, before);
    }

    #[test]
    fn callback_observes_unrelated_foreign_lock_on_same_backend() {
        let runtime = runtime();
        let host = matching_host(&runtime);
        let output_id = note(9).output_id;
        let foreign = LockOwner::new([0xa9; 32]);
        let mut backend = FakeBackend::new(vec![note(9)]).with_lock(output_id, foreign);
        with_coppice_spend_guard(
            CoppiceProtectionMode::Enabled,
            &host,
            &runtime,
            &empty_pending(),
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
            |backend| assert_eq!(backend.locks[&output_id].owner, foreign),
        )
        .unwrap();
        assert_eq!(backend.locks[&output_id].owner, foreign);
    }

    #[test]
    fn protected_guard_repairs_an_externally_cleared_lock_before_proposal() {
        let runtime = runtime();
        let host = matching_host(&runtime);
        let bond_tag = tag(3);
        let output_id = note(3).output_id;
        let pending = collection_with(pending_for(bond_tag));
        let mut backend = FakeBackend::new(vec![note(3)]);
        with_coppice_spend_guard(
            CoppiceProtectionMode::Enabled,
            &host,
            &runtime,
            &pending,
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
            |_| (),
        )
        .unwrap();
        assert_eq!(
            backend.locks[&output_id].owner,
            lock_owner_for_bond(bond_tag)
        );

        backend.locks.clear();
        let called = std::cell::Cell::new(0);
        with_coppice_spend_guard(
            CoppiceProtectionMode::GuardOnly,
            &host,
            &runtime,
            &pending,
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
            |backend| {
                assert_eq!(
                    backend.locks[&output_id].owner,
                    lock_owner_for_bond(bond_tag)
                );
                called.set(called.get() + 1);
            },
        )
        .unwrap();
        assert_eq!(called.get(), 1);
        assert_eq!(
            backend.locks[&output_id].owner,
            lock_owner_for_bond(bond_tag)
        );
    }
}
