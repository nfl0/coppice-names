//! Wallet mechanics for preparing an exact-minimum Coppice bond note.
//!
//! Coppice consensus only checks that a bonded Ironwood note is worth at least
//! the deployment minimum. This adapter deliberately makes the normal wallet
//! path exact-minimum-first: if an exact note is not available, the caller may
//! explicitly use the self-send workflow below to create one and receive the
//! remainder as ordinary Ironwood change.

use std::fmt::Debug;

use coppice::{config::DeploymentParameters, names_runtime::NamesRuntime};
use sapling::prover::{OutputProver, SpendProver};
use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::{
        InputSource, WalletCommitmentTrees, WalletRead, WalletWrite,
        locking::LockedInputPolicy,
        wallet::{
            ConfirmationsPolicy, CreateErrT, LockRequest, ProposeTransferErrT, SpendingKeys,
            create_proposed_transactions,
            input_selection::{InputSelector, NoteSelection, SpendPolicy},
            propose_transfer, unlock_proposal_inputs,
        },
    },
    fees::ChangeStrategy,
    proposal::Proposal,
    wallet::OvkPolicy,
};
use zcash_primitives::transaction::{Transaction, TxId, fees::FeeRule};
use zcash_protocol::{
    PoolType,
    consensus::{self, BlockHeight, NetworkUpgrade},
    value::Zatoshis,
};
use zip321::{Payment, TransactionRequest, Zip321Error};

use crate::{
    CoppiceProtectionMode, HostCanonicalTipSource, IronwoodViewingCapability,
    PendingRegistrationCollection, SpendGuardError, WalletCoppiceLockBackend,
    WalletCoppiceLockError, with_coppice_spend_guard,
};

/// A value-only plan for splitting a larger eligible note into the exact bond
/// minimum and ordinary change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BondNoteSplitPlan {
    pub source_value_zat: u64,
    pub bond_value_zat: u64,
    pub change_value_zat: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BondNoteSplitError {
    InsufficientFunds,
    AlreadyExactMinimum,
}

/// Computes the non-bond remainder before transaction fees are deducted.
pub fn plan_bond_note_split(
    source_value_zat: u64,
    minimum_bond_value: u64,
) -> Result<BondNoteSplitPlan, BondNoteSplitError> {
    if source_value_zat < minimum_bond_value {
        return Err(BondNoteSplitError::InsufficientFunds);
    }
    if source_value_zat == minimum_bond_value {
        return Err(BondNoteSplitError::AlreadyExactMinimum);
    }
    Ok(BondNoteSplitPlan {
        source_value_zat,
        bond_value_zat: minimum_bond_value,
        change_value_zat: source_value_zat - minimum_bond_value,
    })
}

#[derive(Debug)]
pub enum BondNotePreparationRequestError {
    InvalidDeployment,
    InvalidBondValue,
    InvalidRequest(Zip321Error),
}

/// Builds the ordinary self-send request used to create an exact-minimum
/// Ironwood bond note. The recipient must be an Ironwood-capable wallet
/// address; proposal validation below confirms the selected output pool.
pub fn bond_note_preparation_request(
    deployment: &DeploymentParameters,
    recipient: ZcashAddress,
) -> Result<TransactionRequest, BondNotePreparationRequestError> {
    deployment
        .validate()
        .map_err(|_| BondNotePreparationRequestError::InvalidDeployment)?;
    let amount = Zatoshis::from_u64(deployment.minimum_bond_value)
        .map_err(|_| BondNotePreparationRequestError::InvalidBondValue)?;
    TransactionRequest::new(vec![Payment::without_memo(recipient, amount)])
        .map_err(BondNotePreparationRequestError::InvalidRequest)
}

/// The only spend policy used by the preparation workflow: Ironwood inputs,
/// locked outputs excluded, and a single-note preference so a larger note is
/// normally split without accumulating unrelated wallet funds.
pub fn bond_note_preparation_spend_policy() -> SpendPolicy {
    SpendPolicy::shielded_pools([zcash_protocol::ShieldedPool::Ironwood])
        .with_locked_input_policy(LockedInputPolicy::Exclude)
        .with_note_selection(NoteSelection::PreferSingle)
}

/// Validation performed after the normal wallet proposal API returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BondNotePreparationValidationError {
    UnexpectedTargetHeight { expected: u32, actual: u32 },
    MultiStepProposalUnsupported { steps: usize },
    BondPaymentNotIronwood,
    BondPaymentAmountMismatch { expected: u64, actual: Option<u64> },
    NoShieldedInputs,
    NonIronwoodChange { index: usize, pool: PoolType },
    ChangeValueOverflow,
}

/// A normal wallet proposal that creates the exact-minimum Ironwood output.
/// The proposal remains available for the caller to pass to the pinned
/// `create_proposed_transactions` API.
pub struct PreparedBondNoteProposal<FeeRuleT, NoteRef> {
    proposal: Proposal<FeeRuleT, NoteRef>,
    bond_value_zat: u64,
    proposed_change_zat: u64,
}

impl<FeeRuleT, NoteRef> PreparedBondNoteProposal<FeeRuleT, NoteRef> {
    pub fn proposal(&self) -> &Proposal<FeeRuleT, NoteRef> {
        &self.proposal
    }

    pub const fn bond_value_zat(&self) -> u64 {
        self.bond_value_zat
    }

    /// Returns Ironwood change after the wallet's fee/change strategy has been
    /// applied. The value-only split plan reports the pre-fee remainder.
    pub const fn proposed_change_zat(&self) -> u64 {
        self.proposed_change_zat
    }
}

fn validate_proposal<FeeRuleT, NoteRef>(
    proposal: &Proposal<FeeRuleT, NoteRef>,
    expected_height: u32,
    bond_value_zat: u64,
) -> Result<u64, BondNotePreparationValidationError> {
    let actual_height: u32 = BlockHeight::from(proposal.min_target_height()).into();
    if actual_height != expected_height {
        return Err(BondNotePreparationValidationError::UnexpectedTargetHeight {
            expected: expected_height,
            actual: actual_height,
        });
    }
    if proposal.steps().len() != 1 {
        return Err(
            BondNotePreparationValidationError::MultiStepProposalUnsupported {
                steps: proposal.steps().len(),
            },
        );
    }
    let step = proposal.steps().first();
    if step.payment_pools().len() != 1 || step.payment_pools().get(&0) != Some(&PoolType::IRONWOOD)
    {
        return Err(BondNotePreparationValidationError::BondPaymentNotIronwood);
    }
    let actual_amount = step
        .transaction_request()
        .payments()
        .get(&0)
        .and_then(|payment| payment.amount())
        .map(Zatoshis::into_u64);
    if actual_amount != Some(bond_value_zat) {
        return Err(
            BondNotePreparationValidationError::BondPaymentAmountMismatch {
                expected: bond_value_zat,
                actual: actual_amount,
            },
        );
    }
    if step.shielded_inputs().is_none() {
        return Err(BondNotePreparationValidationError::NoShieldedInputs);
    }
    step.balance()
        .proposed_change()
        .iter()
        .enumerate()
        .try_fold(0u64, |total, (index, change)| {
            if change.output_pool() != PoolType::IRONWOOD {
                return Err(BondNotePreparationValidationError::NonIronwoodChange {
                    index,
                    pool: change.output_pool(),
                });
            }
            total
                .checked_add(change.value().into_u64())
                .ok_or(BondNotePreparationValidationError::ChangeValueOverflow)
        })
}

#[derive(Debug)]
pub enum BondNotePreparationProposalError<HostError, LockError: Debug, ProposalError, CleanupError>
{
    Request(BondNotePreparationRequestError),
    NetworkMismatch,
    TargetHeightOverflow,
    IronwoodNotActive {
        target_height: u32,
    },
    SpendGuard(SpendGuardError<HostError, LockError>),
    Proposal(ProposalError),
    PostProposalValidation(BondNotePreparationValidationError),
    ProposalCleanup {
        validation: BondNotePreparationValidationError,
        error: CleanupError,
    },
}

fn cleanup_rejected_bond_proposal<E>(
    validation: BondNotePreparationValidationError,
    lock_request: Option<LockRequest>,
    cleanup: impl FnOnce(zcash_client_backend::wallet::LockOwner) -> Result<(), E>,
) -> Result<BondNotePreparationValidationError, (BondNotePreparationValidationError, E)> {
    if let Some(lock_request) = lock_request {
        cleanup(lock_request.owner()).map_err(|error| (validation, error))?;
    }
    Ok(validation)
}

/// Proposes a normal, Ironwood-only self-send for the deployment minimum.
///
/// This function does not automatically call registration or reserve a bond.
/// A wallet or frontend can first inspect [`crate::prepare_bond_note`] and ask
/// for user confirmation before invoking this workflow.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn propose_bond_note_preparation<Host, DbT, ParamsT, InputsT, ChangeT, CommitmentTreeErrT>(
    mode: CoppiceProtectionMode,
    host_tip_source: &Host,
    runtime: &NamesRuntime,
    pending: &PendingRegistrationCollection,
    capability: IronwoodViewingCapability,
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_from_account: <DbT as InputSource>::AccountId,
    orchard_fvk: &orchard::keys::FullViewingKey,
    input_selector: &InputsT,
    change_strategy: &ChangeT,
    confirmations_policy: ConfirmationsPolicy,
    lock_inputs: Option<LockRequest>,
    recipient: ZcashAddress,
) -> Result<
    PreparedBondNoteProposal<ChangeT::FeeRule, DbT::NoteRef>,
    BondNotePreparationProposalError<
        Host::Error,
        WalletCoppiceLockError<DbT>,
        ProposeTransferErrT<DbT, CommitmentTreeErrT, InputsT, ChangeT>,
        <DbT as WalletRead>::Error,
    >,
>
where
    Host: HostCanonicalTipSource,
    DbT: WalletWrite
        + InputSource<Error = <DbT as WalletRead>::Error, AccountId = <DbT as WalletRead>::AccountId>,
    DbT::NoteRef: Copy + Eq + Ord,
    ParamsT: consensus::Parameters + Clone,
    InputsT: InputSelector<InputSource = DbT>,
    ChangeT: ChangeStrategy<MetaSource = DbT>,
{
    if params.network_type() != runtime.deployment().address_network {
        return Err(BondNotePreparationProposalError::NetworkMismatch);
    }
    let expected_height = runtime
        .tip()
        .height
        .checked_add(1)
        .ok_or(BondNotePreparationProposalError::TargetHeightOverflow)?;
    if !params.is_nu_active(
        NetworkUpgrade::Nu6_3,
        BlockHeight::from_u32(expected_height),
    ) {
        return Err(BondNotePreparationProposalError::IronwoodNotActive {
            target_height: expected_height,
        });
    }
    let bond_value_zat = runtime.deployment().minimum_bond_value;
    let request = bond_note_preparation_request(runtime.deployment(), recipient)
        .map_err(BondNotePreparationProposalError::Request)?;
    let spend_policy = bond_note_preparation_spend_policy();
    let target_height = zcash_client_backend::data_api::wallet::TargetHeight::from(expected_height);
    let mut backend = WalletCoppiceLockBackend::new(
        wallet_db,
        spend_from_account,
        target_height,
        orchard_fvk,
        capability,
    );
    let account_id = crate::WalletAccountId::from_orchard_fvk(orchard_fvk);
    let (proposal_result, _) = with_coppice_spend_guard(
        mode,
        host_tip_source,
        runtime,
        pending,
        account_id,
        backend.capability(),
        &mut backend,
        |backend| {
            propose_transfer(
                backend.wallet_db_mut(),
                params,
                spend_from_account,
                input_selector,
                change_strategy,
                request,
                confirmations_policy,
                &spend_policy,
                lock_inputs,
                None,
            )
        },
    )
    .map_err(BondNotePreparationProposalError::SpendGuard)?;
    let proposal = proposal_result.map_err(BondNotePreparationProposalError::Proposal)?;
    let proposed_change_zat = match validate_proposal(&proposal, expected_height, bond_value_zat) {
        Ok(change) => change,
        Err(validation) => {
            let validation = cleanup_rejected_bond_proposal(validation, lock_inputs, |owner| {
                unlock_proposal_inputs(backend.wallet_db_mut(), &proposal, owner)
            })
            .map_err(|(validation, error)| {
                BondNotePreparationProposalError::ProposalCleanup { validation, error }
            })?;
            return Err(BondNotePreparationProposalError::PostProposalValidation(
                validation,
            ));
        }
    };
    Ok(PreparedBondNoteProposal {
        proposal,
        bond_value_zat,
        proposed_change_zat,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConstructedBondNotePreparation {
    pub txid: TxId,
    pub bond_value_zat: u64,
    pub proposed_change_zat: u64,
}

#[derive(Debug)]
pub enum BondNotePreparationConstructionError<DbError, ConstructionError> {
    Construction(ConstructionError),
    UnexpectedTransactionCount { count: usize },
    ConstructedTransactionUnavailable(DbError),
    MissingConstructedTransaction,
    MissingIronwoodBundle,
}

/// Creates and stores the self-send represented by a prepared proposal using
/// the normal pinned librustzcash transaction-construction path.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn create_bond_note_preparation_transaction<DbT, ParamsT, InputsErrT, FeeRuleT, ChangeErrT, N>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_prover: &impl SpendProver,
    output_prover: &impl OutputProver,
    spending_keys: &SpendingKeys,
    ovk_policy: OvkPolicy,
    prepared: PreparedBondNoteProposal<FeeRuleT, N>,
    expiry_height: Option<BlockHeight>,
) -> Result<
    ConstructedBondNotePreparation,
    BondNotePreparationConstructionError<
        <DbT as WalletRead>::Error,
        CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>,
    >,
>
where
    DbT: WalletWrite + WalletCommitmentTrees,
    ParamsT: consensus::Parameters + Clone,
    FeeRuleT: FeeRule,
{
    let txids = create_proposed_transactions(
        wallet_db,
        params,
        spend_prover,
        output_prover,
        spending_keys,
        ovk_policy,
        &prepared.proposal,
        expiry_height,
    )
    .map_err(BondNotePreparationConstructionError::Construction)?;
    if txids.len() != 1 {
        return Err(
            BondNotePreparationConstructionError::UnexpectedTransactionCount { count: txids.len() },
        );
    }
    let txid = *txids.first();
    let tx: Transaction = wallet_db
        .get_transaction(txid)
        .map_err(BondNotePreparationConstructionError::ConstructedTransactionUnavailable)?
        .ok_or(BondNotePreparationConstructionError::MissingConstructedTransaction)?;
    if tx.ironwood_bundle().is_none() {
        return Err(BondNotePreparationConstructionError::MissingIronwoodBundle);
    }
    Ok(ConstructedBondNotePreparation {
        txid,
        bond_value_zat: prepared.bond_value_zat,
        proposed_change_zat: prepared.proposed_change_zat,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use coppice::constants::REGTEST_ACTIVATION_HEIGHT;
    use zcash_keys::address::UnifiedAddress;
    use zcash_protocol::consensus::NetworkType;

    fn deployment() -> DeploymentParameters {
        let input: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/deployment.json")).unwrap();
        let input = &input["input"];
        DeploymentParameters {
            network_id: hex::decode(input["network_id_hex"].as_str().unwrap()).unwrap(),
            address_network: NetworkType::Regtest,
            activation_height: REGTEST_ACTIVATION_HEIGHT,
            minimum_bond_value: input["minimum_bond_value"].as_u64().unwrap(),
            commit_ttl_blocks: input["commit_ttl_blocks"].as_u64().unwrap() as u32,
            reuse_delay_blocks: input["reuse_delay_blocks"].as_u64().unwrap() as u32,
            bond_note_max_age_blocks: input["bond_note_max_age_blocks"].as_u64().unwrap() as u32,
            rendezvous: coppice::config::Rendezvous {
                orchard_ivk: hex::decode(input["rendezvous_ivk_hex"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                orchard_receiver: hex::decode(input["rendezvous_receiver_hex"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            },
        }
    }

    #[test]
    fn split_plan_preserves_non_bond_remainder() {
        let plan = plan_bond_note_split(250_000_000, 100_000_000).unwrap();
        assert_eq!(plan.bond_value_zat, 100_000_000);
        assert_eq!(plan.change_value_zat, 150_000_000);
    }

    #[test]
    fn split_plan_rejects_insufficient_or_exact_sources() {
        assert_eq!(
            plan_bond_note_split(99_999_999, 100_000_000),
            Err(BondNoteSplitError::InsufficientFunds)
        );
        assert_eq!(
            plan_bond_note_split(100_000_000, 100_000_000),
            Err(BondNoteSplitError::AlreadyExactMinimum)
        );
    }

    #[test]
    fn request_targets_the_deployment_minimum() {
        let deployment = deployment();
        let orchard = coppice::carrier::bulletin_address(deployment.rendezvous).unwrap();
        let recipient = UnifiedAddress::from_receivers(Some(orchard), None, None)
            .unwrap()
            .to_zcash_address(deployment.address_network);
        let request = bond_note_preparation_request(&deployment, recipient).unwrap();
        let payment = request.payments().get(&0).unwrap();
        assert_eq!(
            payment.amount(),
            Some(Zatoshis::const_from_u64(deployment.minimum_bond_value))
        );
        assert_eq!(request.payments().len(), 1);
    }

    #[test]
    fn preparation_policy_is_ironwood_single_note_and_lock_excluding() {
        let policy = bond_note_preparation_spend_policy();
        assert_eq!(
            policy.shielded().iter().copied().collect::<Vec<_>>(),
            vec![zcash_protocol::ShieldedPool::Ironwood]
        );
        assert_eq!(policy.note_selection(), NoteSelection::PreferSingle);
        assert_eq!(*policy.locked_input_policy(), LockedInputPolicy::Exclude);
    }
}
