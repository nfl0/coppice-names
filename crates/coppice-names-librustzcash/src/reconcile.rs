//! Host-authoritative canonical-chain reconciliation for Coppice.
//!
//! This module performs no fork choice. [`CanonicalBlockSource`] exposes the
//! history the host has already selected as canonical.

use std::fmt::Debug;

use coppice_core::{replay::CoreReplayTip, runtime::CanonicalRuntime};
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_protocol::consensus::Parameters;

use crate::{CompactBlockApplyError, FullTransactionSource, apply_compact_block};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalTip {
    pub height: u32,
    pub block_hash: [u8; 32],
}

impl From<CoreReplayTip> for CanonicalTip {
    fn from(tip: CoreReplayTip) -> Self {
        Self {
            height: tip.height,
            block_hash: tip.block_hash,
        }
    }
}

/// Supplies history that the host has already selected as canonical.
pub trait CanonicalBlockSource {
    type Error: Debug;

    fn canonical_tip(&mut self) -> Result<CanonicalTip, Self::Error>;

    fn compact_block(&mut self, height: u32) -> Result<Option<CompactBlock>, Self::Error>;
}

/// Freezes canonical authority to a host-selected tip while retaining an
/// untrusted source only as block transport.
///
/// This prevents a transport server's advancing tip from changing the target
/// of a reconciliation pass after the host wallet has completed scanning.
pub struct FrozenCanonicalBlockSource<S> {
    source: S,
    tip: CanonicalTip,
}

impl<S> FrozenCanonicalBlockSource<S> {
    pub const fn new(source: S, tip: CanonicalTip) -> Self {
        Self { source, tip }
    }

    pub fn source(&self) -> &S {
        &self.source
    }

    pub fn into_source(self) -> S {
        self.source
    }
}

impl<S: CanonicalBlockSource> CanonicalBlockSource for FrozenCanonicalBlockSource<S> {
    type Error = S::Error;

    fn canonical_tip(&mut self) -> Result<CanonicalTip, Self::Error> {
        Ok(self.tip)
    }

    fn compact_block(&mut self, height: u32) -> Result<Option<CompactBlock>, Self::Error> {
        self.source.compact_block(height)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcileKind {
    AlreadyCurrent,
    Forward,
    Reorg,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconcileOutcome {
    pub kind: ReconcileKind,
    pub original_tip: CoreReplayTip,
    pub observed_host_tip: CanonicalTip,
    pub common_ancestor: Option<CoreReplayTip>,
    pub blocks_rewound: u32,
    pub blocks_applied: u32,
    pub final_tip: CoreReplayTip,
}

#[derive(Debug)]
pub enum ReconcileError<
    CanonicalError: Debug,
    FullTxError: Debug,
    RuntimeApplyError: Debug,
    RuntimeRewindError: Debug,
> {
    CanonicalBlockSource(CanonicalError),
    MissingCanonicalBlock {
        height: u32,
    },
    InvalidCanonicalIdentity {
        requested_height: u32,
    },
    CanonicalHistoryChanged {
        observed: CanonicalTip,
        current: CanonicalTip,
    },
    NoRetainedCommonAncestor,
    Rewind(RuntimeRewindError),
    CompactBlockApply {
        height: u32,
        error: CompactBlockApplyError<FullTxError, RuntimeApplyError>,
    },
    ProgressPersistenceFailed,
    ArithmeticOverflow,
}

pub type ReconcileResult<C, F, A, W> = Result<ReconcileOutcome, ReconcileError<C, F, A, W>>;

fn block_identity(block: &CompactBlock, requested_height: u32) -> Option<CanonicalTip> {
    let height = u32::try_from(block.height).ok()?;
    let block_hash: [u8; 32] = block.hash.as_slice().try_into().ok()?;
    (height == requested_height).then_some(CanonicalTip { height, block_hash })
}

fn checked_block<C, F, A, W>(
    source: &mut C,
    height: u32,
) -> Result<CompactBlock, ReconcileError<C::Error, F, A, W>>
where
    C: CanonicalBlockSource,
    C::Error: Debug,
    F: Debug,
    A: Debug,
    W: Debug,
{
    let block = source
        .compact_block(height)
        .map_err(ReconcileError::CanonicalBlockSource)?
        .ok_or(ReconcileError::MissingCanonicalBlock { height })?;
    block_identity(&block, height).ok_or(ReconcileError::InvalidCanonicalIdentity {
        requested_height: height,
    })?;
    Ok(block)
}

fn canonical_hash_at<C, F, A, W>(
    source: &mut C,
    observed_tip: CanonicalTip,
    activation_height: u32,
    height: u32,
) -> Result<[u8; 32], ReconcileError<C::Error, F, A, W>>
where
    C: CanonicalBlockSource,
    C::Error: Debug,
    F: Debug,
    A: Debug,
    W: Debug,
{
    if height == observed_tip.height {
        return Ok(observed_tip.block_hash);
    }
    let activation_base = activation_height
        .checked_sub(1)
        .ok_or(ReconcileError::ArithmeticOverflow)?;
    if height == activation_base {
        // Never request a pre-activation CompactBlock. The activation block's
        // predecessor identifies the host-selected activation base.
        let block = checked_block::<C, F, A, W>(source, activation_height)?;
        return block.prev_hash.as_slice().try_into().map_err(|_| {
            ReconcileError::InvalidCanonicalIdentity {
                requested_height: activation_height,
            }
        });
    }
    checked_block::<C, F, A, W>(source, height)?
        .hash
        .as_slice()
        .try_into()
        .map_err(|_| ReconcileError::InvalidCanonicalIdentity {
            requested_height: height,
        })
}

/// Reconciles to the host-selected tip observed at the beginning of this call.
/// Ancestor discovery is mutation-free; after a rewind, replay is deliberately
/// block-atomic and resumable rather than range-transactional.
pub fn reconcile_canonical_chain<P, R, C, F>(
    params: &P,
    runtime: &mut R,
    canonical_source: &mut C,
    full_tx_source: &mut F,
) -> ReconcileResult<C::Error, F::Error, R::ApplyError, R::RewindError>
where
    P: Parameters,
    R: CanonicalRuntime,
    C: CanonicalBlockSource,
    F: FullTransactionSource,
{
    reconcile_canonical_chain_with_progress(
        params,
        runtime,
        canonical_source,
        full_tx_source,
        |_| true,
    )
}

/// Reconciles while invoking `persist_progress` after a successful rewind and
/// after each successfully applied canonical block. Returning `false` stops
/// immediately at that durable boundary; the runtime remains at exactly the
/// state presented to the callback.
pub fn reconcile_canonical_chain_with_progress<P, R, C, F>(
    params: &P,
    runtime: &mut R,
    canonical_source: &mut C,
    full_tx_source: &mut F,
    mut persist_progress: impl FnMut(&R) -> bool,
) -> ReconcileResult<C::Error, F::Error, R::ApplyError, R::RewindError>
where
    P: Parameters,
    R: CanonicalRuntime,
    C: CanonicalBlockSource,
    F: FullTransactionSource,
{
    let original_tip = runtime.tip();
    let observed_host_tip = canonical_source
        .canonical_tip()
        .map_err(ReconcileError::CanonicalBlockSource)?;
    if original_tip.height == observed_host_tip.height
        && original_tip.block_hash == observed_host_tip.block_hash
    {
        return Ok(ReconcileOutcome {
            kind: ReconcileKind::AlreadyCurrent,
            original_tip,
            observed_host_tip,
            common_ancestor: None,
            blocks_rewound: 0,
            blocks_applied: 0,
            final_tip: original_tip,
        });
    }

    let activation_height = runtime
        .core_parameters()
        .parameters()
        .runtime_activation_height;
    let activation_base = activation_height
        .checked_sub(1)
        .ok_or(ReconcileError::ArithmeticOverflow)?;
    let local_is_ancestor = if original_tip.height < observed_host_tip.height {
        canonical_hash_at::<C, F::Error, R::ApplyError, R::RewindError>(
            canonical_source,
            observed_host_tip,
            activation_height,
            original_tip.height,
        )? == original_tip.block_hash
    } else {
        false
    };

    let (kind, common_ancestor, blocks_rewound) = if local_is_ancestor {
        (ReconcileKind::Forward, None, 0)
    } else {
        let search_top = original_tip.height.min(observed_host_tip.height);
        let search_floor = runtime.oldest_rewind_height().max(activation_base);
        let mut common = None;
        for height in (search_floor..=search_top).rev() {
            let Some(local) = runtime.retained_tip_at(height) else {
                continue;
            };
            let canonical_hash = canonical_hash_at::<C, F::Error, R::ApplyError, R::RewindError>(
                canonical_source,
                observed_host_tip,
                activation_height,
                height,
            )?;
            if local.block_hash == canonical_hash {
                common = Some(local);
                break;
            }
        }
        let common = common.ok_or(ReconcileError::NoRetainedCommonAncestor)?;
        let rewound = original_tip
            .height
            .checked_sub(common.height)
            .ok_or(ReconcileError::ArithmeticOverflow)?;
        runtime
            .rewind_canonical_to(common.height)
            .map_err(ReconcileError::Rewind)?;
        if !persist_progress(runtime) {
            return Err(ReconcileError::ProgressPersistenceFailed);
        }
        (ReconcileKind::Reorg, Some(common), rewound)
    };

    let mut blocks_applied = 0u32;
    let start = runtime
        .tip()
        .height
        .checked_add(1)
        .ok_or(ReconcileError::ArithmeticOverflow)?;
    if start <= observed_host_tip.height {
        for height in start..=observed_host_tip.height {
            // Ownership is deliberately per iteration: after application this
            // protobuf block is dropped before the next height is fetched.
            let block = checked_block::<C, F::Error, R::ApplyError, R::RewindError>(
                canonical_source,
                height,
            )?;
            if height == observed_host_tip.height
                && block_identity(&block, height).map(|id| id.block_hash)
                    != Some(observed_host_tip.block_hash)
            {
                return Err(ReconcileError::CanonicalHistoryChanged {
                    observed: observed_host_tip,
                    current: block_identity(&block, height).ok_or(
                        ReconcileError::InvalidCanonicalIdentity {
                            requested_height: height,
                        },
                    )?,
                });
            }
            apply_compact_block(params, runtime, &block, full_tx_source)
                .map_err(|error| ReconcileError::CompactBlockApply { height, error })?;
            if !persist_progress(runtime) {
                return Err(ReconcileError::ProgressPersistenceFailed);
            }
            blocks_applied = blocks_applied
                .checked_add(1)
                .ok_or(ReconcileError::ArithmeticOverflow)?;
        }
    }

    let current_host_tip = canonical_source
        .canonical_tip()
        .map_err(ReconcileError::CanonicalBlockSource)?;
    if current_host_tip.height < observed_host_tip.height {
        return Err(ReconcileError::CanonicalHistoryChanged {
            observed: observed_host_tip,
            current: current_host_tip,
        });
    }
    if current_host_tip != observed_host_tip {
        let current_observed_hash = canonical_hash_at::<C, F::Error, R::ApplyError, R::RewindError>(
            canonical_source,
            current_host_tip,
            activation_height,
            observed_host_tip.height,
        )?;
        if current_observed_hash != observed_host_tip.block_hash {
            return Err(ReconcileError::CanonicalHistoryChanged {
                observed: observed_host_tip,
                current: CanonicalTip {
                    height: observed_host_tip.height,
                    block_hash: current_observed_hash,
                },
            });
        }
    }

    Ok(ReconcileOutcome {
        kind,
        original_tip,
        observed_host_tip,
        common_ancestor,
        blocks_rewound,
        blocks_applied,
        final_tip: runtime.tip(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use coppice::{
        config::{DeploymentParameters, REGTEST, Rendezvous},
        names_runtime::{CoreReplayActivationCheckpoint, IronwoodFrontier, NamesRuntime},
    };
    use orchard::{
        note::{ExtractedNoteCommitment, Note, NoteVersion, Nullifier, RandomSeed, Rho},
        note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
        value::NoteValue,
    };
    use zcash_client_backend::proto::compact_formats::{CompactOrchardAction, CompactTx};
    use zcash_note_encryption::Domain;
    use zcash_protocol::{
        consensus::{BlockHeight, NetworkType},
        local_consensus::LocalNetwork,
    };

    use super::*;

    fn params() -> LocalNetwork {
        let active = Some(BlockHeight::from_u32(1));
        LocalNetwork {
            overwinter: active,
            sapling: active,
            blossom: active,
            heartwood: active,
            canopy: active,
            nu5: active,
            nu6: active,
            nu6_1: active,
            nu6_2: active,
            nu6_3: active,
        }
    }

    fn deployment() -> DeploymentParameters {
        DeploymentParameters {
            network_id: REGTEST.network_id.to_vec(),
            address_network: NetworkType::Regtest,
            activation_height: 1,
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

    fn new_runtime() -> NamesRuntime {
        let deployment = deployment();
        NamesRuntime::new(
            deployment.clone(),
            CoreReplayActivationCheckpoint {
                height: deployment.activation_height - 1,
                block_hash: [9; 32],
                ironwood_frontier: IronwoodFrontier::empty(),
                ironwood_tree_size: 0,
            },
        )
        .unwrap()
    }

    fn canonical_nf(marker: u8) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[0] = marker;
        Option::<Nullifier>::from(Nullifier::from_bytes(&bytes))
            .unwrap()
            .to_bytes()
    }

    fn canonical_cmx(marker: u8) -> [u8; 32] {
        for suffix in 0..=u8::MAX {
            let mut bytes = [0; 32];
            bytes[0] = marker;
            bytes[31] = suffix;
            if Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&bytes))
                .is_some()
            {
                return bytes;
            }
        }
        panic!("test marker must yield a canonical commitment")
    }

    fn action(marker: u8) -> CompactOrchardAction {
        CompactOrchardAction {
            nullifier: canonical_nf(marker).to_vec(),
            cmx: canonical_cmx(marker).to_vec(),
            ephemeral_key: vec![0; 32],
            ciphertext: vec![0; 52],
        }
    }

    fn candidate_action() -> CompactOrchardAction {
        let recipient =
            orchard::Address::from_raw_address_bytes(&REGTEST.rendezvous.orchard_receiver).unwrap();
        let nf = Nullifier::from_bytes(&[0; 32]).unwrap();
        let rho = Rho::from_bytes(&nf.to_bytes()).unwrap();
        let rseed = (0u8..=u8::MAX)
            .find_map(|byte| Option::from(RandomSeed::from_bytes([byte; 32], &rho)))
            .unwrap();
        let note = Note::from_parts(
            recipient,
            NoteValue::from_raw(0),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        let encryptor = IronwoodNoteEncryption::new(None, note, [0; 512]);
        let ciphertext = encryptor.encrypt_note_plaintext();
        CompactOrchardAction {
            nullifier: nf.to_bytes().to_vec(),
            cmx: ExtractedNoteCommitment::from(note.commitment())
                .to_bytes()
                .to_vec(),
            ephemeral_key: IronwoodDomain::epk_bytes(encryptor.epk()).0.to_vec(),
            ciphertext: ciphertext[..52].to_vec(),
        }
    }

    fn block(height: u32, hash: u8, prev_hash: [u8; 32], marker: u8) -> CompactBlock {
        CompactBlock {
            height: u64::from(height),
            hash: vec![hash; 32],
            prev_hash: prev_hash.to_vec(),
            vtx: vec![CompactTx {
                index: 2,
                txid: vec![hash; 32],
                ironwood_actions: vec![action(marker)],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn chain(spec: &[(u32, u8, u8)]) -> BTreeMap<u32, CompactBlock> {
        let mut result = BTreeMap::new();
        let mut prev = [9; 32];
        for &(height, hash, marker) in spec {
            result.insert(height, block(height, hash, prev, marker));
            prev = [hash; 32];
        }
        result
    }

    fn retained_horizon_chain(branch: u8) -> BTreeMap<u32, CompactBlock> {
        let mut result = BTreeMap::new();
        let mut prev = [9; 32];
        for height in 1..=150 {
            let hash = if height == 1 {
                1
            } else {
                branch.wrapping_mul(0x40).wrapping_add(height as u8)
            };
            let marker = if height == 1 {
                11
            } else {
                branch.wrapping_mul(0x40).wrapping_add(11)
            };
            result.insert(height, block(height, hash, prev, marker));
            prev = [hash; 32];
        }
        result
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SourceError {
        Failed(u32),
    }

    struct Source {
        blocks: BTreeMap<u32, CompactBlock>,
        initial_tip: CanonicalTip,
        later_tip: Option<CanonicalTip>,
        later_blocks: Option<BTreeMap<u32, CompactBlock>>,
        tip_calls: usize,
        block_calls: Vec<u32>,
        fail_at: Option<u32>,
    }

    impl Source {
        fn new(blocks: BTreeMap<u32, CompactBlock>, tip: CanonicalTip) -> Self {
            Self {
                blocks,
                initial_tip: tip,
                later_tip: None,
                later_blocks: None,
                tip_calls: 0,
                block_calls: vec![],
                fail_at: None,
            }
        }
    }

    impl CanonicalBlockSource for Source {
        type Error = SourceError;

        fn canonical_tip(&mut self) -> Result<CanonicalTip, Self::Error> {
            let result = if self.tip_calls == 0 {
                self.initial_tip
            } else {
                self.later_tip.unwrap_or(self.initial_tip)
            };
            self.tip_calls += 1;
            Ok(result)
        }

        fn compact_block(&mut self, height: u32) -> Result<Option<CompactBlock>, Self::Error> {
            self.block_calls.push(height);
            if self.fail_at == Some(height) {
                return Err(SourceError::Failed(height));
            }
            let blocks = if self.tip_calls >= 2 {
                self.later_blocks.as_ref().unwrap_or(&self.blocks)
            } else {
                &self.blocks
            };
            Ok(blocks.get(&height).cloned())
        }
    }

    #[derive(Default)]
    struct FullSource {
        calls: usize,
    }

    impl FullTransactionSource for FullSource {
        type Error = &'static str;

        fn full_transaction(&mut self, _txid: [u8; 32]) -> Result<Option<Vec<u8>>, Self::Error> {
            self.calls += 1;
            Ok(None)
        }
    }

    #[derive(Debug)]
    struct EmptyLockBackend;

    struct TestHost(crate::WalletCanonicalTip);

    impl crate::HostCanonicalTipSource for TestHost {
        type Error = std::convert::Infallible;

        fn canonical_tip(&self) -> Result<crate::WalletCanonicalTip, Self::Error> {
            Ok(self.0)
        }
    }

    impl crate::CoppiceLockBackend for EmptyLockBackend {
        type Error = std::convert::Infallible;

        fn owned_unspent_ironwood_notes(
            &self,
        ) -> Result<Vec<crate::OwnedIronwoodNote>, Self::Error> {
            Ok(vec![])
        }

        fn ensure_coppice_lock(
            &mut self,
            _: &crate::IronwoodOutputId,
            _: [u8; 32],
            _: BlockHeight,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn remove_coppice_lock(
            &mut self,
            _: &crate::IronwoodOutputId,
            _: [u8; 32],
        ) -> Result<bool, Self::Error> {
            Ok(false)
        }

        fn max_lock_expiry_height(&self) -> BlockHeight {
            BlockHeight::from_u32(u32::MAX)
        }
    }

    fn apply_history(runtime: &mut NamesRuntime, blocks: &BTreeMap<u32, CompactBlock>) {
        let mut full = FullSource::default();
        for block in blocks.values() {
            apply_compact_block(&params(), runtime, block, &mut full).unwrap();
        }
        assert_eq!(full.calls, 0);
    }

    fn tip(height: u32, hash: u8) -> CanonicalTip {
        CanonicalTip {
            height,
            block_hash: [hash; 32],
        }
    }

    fn assert_same_runtime(left: &NamesRuntime, right: &NamesRuntime) {
        assert_eq!(left.tip(), right.tip());
        assert_eq!(left.state(), right.state());
        assert_eq!(
            left.ironwood_frontier().root(),
            right.ironwood_frontier().root()
        );
        assert_eq!(
            left.ironwood_frontier().size(),
            right.ironwood_frontier().size()
        );
        assert_eq!(left.ironwood_checkpoints(), right.ironwood_checkpoints());
        assert_eq!(left.oldest_rewind_height(), right.oldest_rewind_height());
        for height in left.oldest_rewind_height()..=left.tip().height {
            assert_eq!(left.retained_tip_at(height), right.retained_tip_at(height));
        }
    }

    #[test]
    fn already_current_does_no_history_or_full_transaction_work() {
        let mut runtime = new_runtime();
        let mut source = Source::new(BTreeMap::new(), runtime.tip().into());
        let mut full = FullSource::default();
        let outcome =
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full).unwrap();
        assert_eq!(outcome.kind, ReconcileKind::AlreadyCurrent);
        assert!(source.block_calls.is_empty());
        assert_eq!(source.tip_calls, 1);
        assert_eq!(full.calls, 0);
    }

    #[test]
    fn activation_and_forward_catch_up_are_ascending_and_complete() {
        let history = chain(&[(1, 1, 11), (2, 2, 12), (3, 3, 13)]);
        let mut runtime = new_runtime();
        let mut source = Source::new(history.clone(), tip(3, 3));
        let mut full = FullSource::default();
        let outcome =
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full).unwrap();
        assert_eq!(outcome.kind, ReconcileKind::Forward);
        assert_eq!(outcome.blocks_applied, 3);
        assert_eq!(source.block_calls, vec![1, 1, 2, 3]);
        assert!(!source.block_calls.contains(&0));
        assert_eq!(runtime.tip().height, 3);
        assert_eq!(runtime.ironwood_frontier().size(), 3);

        let mut source = Source::new(
            chain(&[(1, 1, 11), (2, 2, 12), (3, 3, 13), (4, 4, 14)]),
            tip(4, 4),
        );
        let outcome =
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full).unwrap();
        assert_eq!(outcome.kind, ReconcileKind::Forward);
        assert_eq!(outcome.blocks_applied, 1);
        assert_eq!(runtime.tip().height, 4);
    }

    #[test]
    fn progress_callback_exposes_each_durable_block_boundary_and_can_stop() {
        let history = chain(&[(1, 1, 11), (2, 2, 12), (3, 3, 13)]);
        let mut runtime = new_runtime();
        let mut source = Source::new(history, tip(3, 3));
        let mut full = FullSource::default();
        let mut persisted = vec![];
        let error = reconcile_canonical_chain_with_progress(
            &params(),
            &mut runtime,
            &mut source,
            &mut full,
            |progress: &NamesRuntime| {
                persisted.push(progress.tip().height);
                progress.tip().height < 2
            },
        )
        .unwrap_err();
        assert!(matches!(error, ReconcileError::ProgressPersistenceFailed));
        assert_eq!(persisted, vec![1, 2]);
        assert_eq!(runtime.tip().height, 2);
        assert!(!source.block_calls.contains(&3));
    }

    #[test]
    fn one_block_reorg_removes_old_effects_and_applies_replacement() {
        let old = chain(&[(1, 10, 20)]);
        let replacement = chain(&[(1, 11, 21)]);
        let mut runtime = new_runtime();
        apply_history(&mut runtime, &old);
        let old_root = runtime.ironwood_frontier().root();
        let mut source = Source::new(replacement.clone(), tip(1, 11));
        let mut full = FullSource::default();
        let outcome =
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full).unwrap();
        assert_eq!(outcome.common_ancestor.unwrap().height, 0);
        assert_eq!(outcome.blocks_rewound, 1);
        assert_ne!(runtime.ironwood_frontier().root(), old_root);
        let mut fresh = new_runtime();
        apply_history(&mut fresh, &replacement);
        assert_same_runtime(&runtime, &fresh);
    }

    #[test]
    fn highest_common_ancestor_is_not_unnecessarily_deep() {
        let old = chain(&[(1, 1, 31), (2, 2, 32), (3, 3, 33), (4, 40, 34)]);
        let replacement = chain(&[(1, 1, 31), (2, 2, 32), (3, 3, 33), (4, 41, 44), (5, 5, 45)]);
        let mut runtime = new_runtime();
        apply_history(&mut runtime, &old);
        let mut source = Source::new(replacement.clone(), tip(5, 5));
        let mut full = FullSource::default();
        let outcome =
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full).unwrap();
        assert_eq!(outcome.common_ancestor.unwrap().height, 3);
        assert_eq!(outcome.blocks_rewound, 1);
        assert_eq!(outcome.blocks_applied, 2);
        let mut fresh = new_runtime();
        apply_history(&mut fresh, &replacement);
        assert_same_runtime(&runtime, &fresh);
    }

    #[test]
    fn multi_block_reorg_replays_replacement_branch_and_equals_fresh_replay() {
        let old = chain(&[(1, 1, 141), (2, 2, 142), (3, 3, 143), (4, 4, 144)]);
        let replacement = chain(&[
            (1, 1, 141),
            (2, 12, 152),
            (3, 13, 153),
            (4, 14, 154),
            (5, 15, 155),
        ]);
        let mut runtime = new_runtime();
        apply_history(&mut runtime, &old);
        let mut source = Source::new(replacement.clone(), tip(5, 15));
        let mut full = FullSource::default();
        let outcome =
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full).unwrap();
        assert_eq!(outcome.common_ancestor.unwrap().height, 1);
        assert_eq!(outcome.blocks_rewound, 3);
        assert_eq!(outcome.blocks_applied, 4);
        let mut fresh = new_runtime();
        apply_history(&mut fresh, &replacement);
        assert_same_runtime(&runtime, &fresh);
    }

    #[test]
    fn runtime_ahead_rewinds_to_host_tip_without_replay() {
        let history = chain(&[(1, 1, 51), (2, 2, 52), (3, 3, 53)]);
        let mut runtime = new_runtime();
        apply_history(&mut runtime, &history);
        let mut source = Source::new(history, tip(2, 2));
        let mut full = FullSource::default();
        let outcome =
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full).unwrap();
        assert_eq!(outcome.common_ancestor.unwrap().height, 2);
        assert_eq!(outcome.blocks_rewound, 1);
        assert_eq!(outcome.blocks_applied, 0);
        assert_eq!(runtime.tip().height, 2);
    }

    #[test]
    fn divergence_below_activation_base_requires_rebuild_without_mutation() {
        let old = chain(&[(1, 1, 61)]);
        let mut foreign = chain(&[(1, 2, 62)]);
        foreign.get_mut(&1).unwrap().prev_hash = vec![8; 32];
        let mut runtime = new_runtime();
        apply_history(&mut runtime, &old);
        let before_tip = runtime.tip();
        let before_root = runtime.ironwood_frontier().root();
        let mut source = Source::new(foreign, tip(1, 2));
        let mut full = FullSource::default();
        assert!(matches!(
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full),
            Err(ReconcileError::NoRetainedCommonAncestor)
        ));
        assert_eq!(runtime.tip(), before_tip);
        assert_eq!(runtime.ironwood_frontier().root(), before_root);
    }

    #[test]
    fn phase6_fork_beyond_retained_horizon_requires_atomic_rebuild() {
        let old = retained_horizon_chain(1);
        let replacement = retained_horizon_chain(2);
        let mut runtime = new_runtime();
        apply_history(&mut runtime, &old);
        assert_eq!(runtime.reorg_retention_blocks(), 121);
        assert_eq!(runtime.oldest_rewind_height(), 29);
        assert_eq!(runtime.tip().height - 1, 149);

        let before = runtime.save_snapshot().unwrap();
        let mut source = Source::new(
            replacement.clone(),
            tip(150, 2u8.wrapping_mul(0x40).wrapping_add(150u8)),
        );
        let mut full = FullSource::default();
        assert!(matches!(
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full),
            Err(ReconcileError::NoRetainedCommonAncestor)
        ));
        assert_eq!(runtime.save_snapshot().unwrap(), before);

        // Rebuild from the activation checkpoint, then independently replay
        // the same replacement chain to establish deterministic equivalence.
        let mut rebuilt = new_runtime();
        apply_history(&mut rebuilt, &replacement);
        let mut clean = new_runtime();
        apply_history(&mut clean, &replacement);
        assert_eq!(
            rebuilt.save_snapshot().unwrap(),
            clean.save_snapshot().unwrap()
        );
        assert_same_runtime(&rebuilt, &clean);
    }

    #[test]
    fn ancestor_source_failure_is_pre_rewind_atomic() {
        let old = chain(&[(1, 1, 71), (2, 2, 72), (3, 3, 73)]);
        let replacement = chain(&[(1, 1, 71), (2, 20, 82), (3, 30, 83)]);
        let mut runtime = new_runtime();
        apply_history(&mut runtime, &old);
        let before_tip = runtime.tip();
        let before_state = runtime.state().clone();
        let before_root = runtime.ironwood_frontier().root();
        let before_checkpoints = runtime.ironwood_checkpoints().clone();
        let mut source = Source::new(replacement, tip(3, 30));
        source.fail_at = Some(2);
        let mut full = FullSource::default();
        assert!(matches!(
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full),
            Err(ReconcileError::CanonicalBlockSource(SourceError::Failed(2)))
        ));
        assert_eq!(runtime.tip(), before_tip);
        assert_eq!(runtime.state(), &before_state);
        assert_eq!(runtime.ironwood_frontier().root(), before_root);
        assert_eq!(runtime.ironwood_checkpoints(), &before_checkpoints);
        assert_eq!(full.calls, 0);
    }

    #[test]
    fn post_rewind_failure_keeps_only_successful_canonical_progress_and_retry_converges() {
        let old = chain(&[(1, 1, 91), (2, 2, 92), (3, 3, 93)]);
        let replacement = chain(&[(1, 10, 101), (2, 20, 102), (3, 30, 103)]);
        let mut runtime = new_runtime();
        apply_history(&mut runtime, &old);
        let mut broken = replacement.clone();
        broken.get_mut(&2).unwrap().vtx[0].ironwood_actions[0].cmx = vec![0; 31];
        let mut source = Source::new(broken, tip(3, 30));
        let mut full = FullSource::default();
        assert!(matches!(
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full),
            Err(ReconcileError::CompactBlockApply { height: 2, .. })
        ));
        assert_eq!(
            runtime.tip(),
            CoreReplayTip {
                height: 1,
                block_hash: [10; 32]
            }
        );
        assert!(!runtime.has_rewind_snapshot(2));

        let mut retry = Source::new(replacement.clone(), tip(3, 30));
        reconcile_canonical_chain(&params(), &mut runtime, &mut retry, &mut full).unwrap();
        let mut fresh = new_runtime();
        apply_history(&mut fresh, &replacement);
        assert_same_runtime(&runtime, &fresh);
    }

    #[test]
    fn first_replacement_failure_leaves_common_ancestor() {
        let old = chain(&[(1, 1, 111)]);
        let mut replacement = chain(&[(1, 10, 112)]);
        replacement.get_mut(&1).unwrap().vtx[0].ironwood_actions[0].cmx = vec![0; 31];
        let mut runtime = new_runtime();
        apply_history(&mut runtime, &old);
        let mut source = Source::new(replacement, tip(1, 10));
        let mut full = FullSource::default();
        assert!(matches!(
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full),
            Err(ReconcileError::CompactBlockApply { height: 1, .. })
        ));
        assert_eq!(runtime.tip().height, 0);
        assert_ne!(runtime.tip().block_hash, [1; 32]);
    }

    #[test]
    fn benign_host_tip_advancement_keeps_the_completed_pass_successful() {
        let history = chain(&[(1, 1, 121)]);
        let mut runtime = new_runtime();
        let mut source = Source::new(history.clone(), tip(1, 1));
        source.later_tip = Some(tip(2, 2));
        let mut full = FullSource::default();
        let outcome =
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full).unwrap();
        assert_eq!(outcome.observed_host_tip, tip(1, 1));
        assert_eq!(runtime.tip().height, 1);
        assert!(!source.block_calls.contains(&2));
    }

    #[test]
    fn frozen_host_tip_never_chases_an_advancing_transport() {
        let history = chain(&[(1, 1, 131), (2, 2, 132), (3, 3, 133), (4, 4, 134)]);
        let mut runtime = new_runtime();
        let mut transport = Source::new(history.clone(), tip(4, 4));
        transport.later_tip = Some(tip(5, 5));
        let mut source = FrozenCanonicalBlockSource::new(transport, tip(3, 3));
        let mut full = FullSource::default();
        let outcome =
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full).unwrap();
        assert_eq!(outcome.observed_host_tip, tip(3, 3));
        assert_eq!(runtime.tip().height, 3);
        assert!(!source.source().block_calls.contains(&4));
        assert_eq!(source.source().tip_calls, 0);
        let host = crate::WalletCanonicalTip::from(runtime.tip());
        let mut backend = EmptyLockBackend;
        crate::with_coppice_spend_guard(
            crate::CoppiceProtectionMode::Enabled,
            &TestHost(host),
            &runtime,
            &crate::PendingRegistrationCollection::new(),
            crate::WalletAccountId::from_bytes([0x11; 32]),
            crate::IronwoodViewingCapability::FullViewing,
            &mut backend,
            |_| (),
        )
        .unwrap();

        let transport = Source::new(history, tip(4, 4));
        let mut source = FrozenCanonicalBlockSource::new(transport, tip(4, 4));
        let outcome =
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full).unwrap();
        assert_eq!(outcome.blocks_applied, 1);
        assert_eq!(runtime.tip().height, 4);
    }

    #[test]
    fn observed_tip_reorg_and_host_rollback_are_explicit() {
        let initial = chain(&[(1, 1, 122)]);
        let replacement = chain(&[(1, 10, 123), (2, 20, 124)]);
        let mut runtime = new_runtime();
        let mut source = Source::new(initial, tip(1, 1));
        source.later_tip = Some(tip(2, 20));
        source.later_blocks = Some(replacement);
        let mut full = FullSource::default();
        assert!(matches!(
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full),
            Err(ReconcileError::CanonicalHistoryChanged { .. })
        ));
        assert_eq!(
            runtime.tip(),
            CoreReplayTip {
                height: 1,
                block_hash: [1; 32]
            }
        );

        let initial = chain(&[(1, 1, 125)]);
        let mut runtime = new_runtime();
        let mut source = Source::new(initial, tip(1, 1));
        source.later_tip = Some(tip(0, 9));
        assert!(matches!(
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full),
            Err(ReconcileError::CanonicalHistoryChanged { .. })
        ));
        assert_eq!(runtime.tip().height, 1);
    }

    #[test]
    fn rendezvous_candidate_uses_existing_full_transaction_path_once() {
        let mut history = chain(&[(1, 1, 131)]);
        history.get_mut(&1).unwrap().vtx[0].ironwood_actions = vec![candidate_action()];
        let mut runtime = new_runtime();
        let mut source = Source::new(history, tip(1, 1));
        let mut full = FullSource::default();
        assert!(matches!(
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full),
            Err(ReconcileError::CompactBlockApply {
                height: 1,
                error: CompactBlockApplyError::Prepare(
                    crate::CompactBlockAdapterError::RequiredFullTransactionMissing { .. }
                )
            })
        ));
        assert_eq!(full.calls, 1);
        assert_eq!(runtime.tip().height, 0);
    }

    #[test]
    fn long_forward_replay_fetches_and_applies_one_height_at_a_time() {
        let mut history = BTreeMap::new();
        let mut prev = [9; 32];
        for height in 1..=200u32 {
            let hash = height as u8;
            history.insert(height, block(height, hash, prev, hash));
            prev = [hash; 32];
        }
        let mut runtime = new_runtime();
        let mut source = Source::new(history, tip(200, 200));
        let mut full = FullSource::default();
        let outcome =
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full).unwrap();
        assert_eq!(outcome.blocks_applied, 200);
        assert_eq!(runtime.ironwood_frontier().size(), 200);
        // The activation block is intentionally refetched after base-identity
        // discovery; every replay iteration then owns only its current block.
        assert_eq!(source.block_calls.len(), 201);
        assert_eq!(&source.block_calls[..3], &[1, 1, 2]);
        assert_eq!(source.block_calls.last(), Some(&200));
    }

    #[test]
    fn malformed_source_identity_errors_are_typed_and_panic_free() {
        let mut full = FullSource::default();

        let mut runtime = new_runtime();
        let before = runtime.tip();
        let mut missing = Source::new(BTreeMap::new(), tip(1, 1));
        assert!(matches!(
            reconcile_canonical_chain(&params(), &mut runtime, &mut missing, &mut full),
            Err(ReconcileError::MissingCanonicalBlock { height: 1 })
        ));
        assert_eq!(runtime.tip(), before);

        let mut wrong_height_blocks = chain(&[(1, 1, 161)]);
        wrong_height_blocks.get_mut(&1).unwrap().height = 2;
        let mut wrong_height = Source::new(wrong_height_blocks, tip(1, 1));
        assert!(matches!(
            reconcile_canonical_chain(&params(), &mut runtime, &mut wrong_height, &mut full),
            Err(ReconcileError::InvalidCanonicalIdentity {
                requested_height: 1
            })
        ));

        let mut bad_hash_blocks = chain(&[(1, 1, 162)]);
        bad_hash_blocks.get_mut(&1).unwrap().hash = vec![0; 31];
        let mut bad_hash = Source::new(bad_hash_blocks, tip(1, 1));
        assert!(matches!(
            reconcile_canonical_chain(&params(), &mut runtime, &mut bad_hash, &mut full),
            Err(ReconcileError::InvalidCanonicalIdentity {
                requested_height: 1
            })
        ));

        let mut bad_prev_blocks = chain(&[(1, 1, 163)]);
        bad_prev_blocks.get_mut(&1).unwrap().prev_hash = vec![0; 31];
        let mut bad_prev = Source::new(bad_prev_blocks, tip(1, 1));
        assert!(matches!(
            reconcile_canonical_chain(&params(), &mut runtime, &mut bad_prev, &mut full),
            Err(ReconcileError::InvalidCanonicalIdentity {
                requested_height: 1
            })
        ));
        assert_eq!(runtime.tip(), before);
        assert_eq!(full.calls, 0);
    }

    #[test]
    fn missing_block_after_rewind_keeps_canonical_progress() {
        let old = chain(&[(1, 1, 171), (2, 2, 172), (3, 3, 173)]);
        let mut replacement = chain(&[(1, 1, 171), (2, 12, 182), (3, 13, 183), (4, 14, 184)]);
        replacement.remove(&4);
        let mut runtime = new_runtime();
        apply_history(&mut runtime, &old);
        let mut source = Source::new(replacement, tip(4, 14));
        let mut full = FullSource::default();
        assert!(matches!(
            reconcile_canonical_chain(&params(), &mut runtime, &mut source, &mut full),
            Err(ReconcileError::MissingCanonicalBlock { height: 4 })
        ));
        assert_eq!(
            runtime.tip(),
            CoreReplayTip {
                height: 3,
                block_hash: [13; 32]
            }
        );
        assert_eq!(runtime.retained_tip_at(2).unwrap().block_hash, [12; 32]);
    }
}
