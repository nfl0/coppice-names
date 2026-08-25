//! Dedicated Coppice carrier transactions through the normal librustzcash
//! proposal and transaction-construction path.

use std::fmt::Debug;

use coppice::{
    config::DeploymentParameters, envelope, names_application::names_v1_application_key,
    names_runtime::NamesRuntime,
};
use coppice_core::{
    identity::ValidatedCoreRuntimeParameters,
    replay::MAX_FULL_TRANSACTION_LEN,
    runtime::{ApplicationMessageStatus, inspect_transaction},
};
use sapling::prover::{OutputProver, SpendProver};
use zcash_client_backend::{
    data_api::{
        InputSource, WalletCommitmentTrees, WalletRead, WalletWrite,
        wallet::{
            ConfirmationsPolicy, CreateErrT, LockRequest, ProposeTransferErrT, SpendingKeys,
            create_proposed_transactions,
            input_selection::{InputSelector, SpendPolicy},
            propose_transfer, unlock_proposal_inputs,
        },
    },
    fees::ChangeStrategy,
    proposal::Proposal,
    wallet::OvkPolicy,
};
use zcash_keys::address::UnifiedAddress;
use zcash_primitives::transaction::{Transaction, TxId, fees::FeeRule};
use zcash_protocol::{
    PoolType,
    consensus::{self, BlockHeight, NetworkUpgrade},
    memo::{Error as MemoBytesError, MemoBytes},
    value::Zatoshis,
};
use zip321::{Payment, PaymentError, TransactionRequest, Zip321Error};

use crate::{
    CoppiceProtectionMode, HostCanonicalTipSource, IronwoodViewingCapability,
    PendingRegistrationCollection, PreparedCarrier, SpendGuardError, WalletCoppiceLockBackend,
    WalletCoppiceLockError, with_coppice_spend_guard,
};

#[derive(Debug)]
pub enum CarrierTransactionRequestError {
    InvalidDeployment,
    InvalidRendezvous,
    InvalidFrameMemo(MemoBytesError),
    InvalidPayment(PaymentError),
    InvalidRequest(Zip321Error),
}

/// Purely maps one prepared frame to one zero-valued rendezvous payment.
pub fn carrier_transaction_request(
    deployment: &DeploymentParameters,
    prepared: &PreparedCarrier,
) -> Result<TransactionRequest, CarrierTransactionRequestError> {
    deployment
        .validate()
        .map_err(|_| CarrierTransactionRequestError::InvalidDeployment)?;
    let orchard = coppice::carrier::bulletin_address(deployment.rendezvous)
        .map_err(|_| CarrierTransactionRequestError::InvalidRendezvous)?;
    let ua = UnifiedAddress::from_receivers(Some(orchard), None, None)
        .ok_or(CarrierTransactionRequestError::InvalidRendezvous)?;
    if ua.orchard().map(orchard::Address::to_raw_address_bytes)
        != Some(deployment.rendezvous.orchard_receiver)
    {
        return Err(CarrierTransactionRequestError::InvalidRendezvous);
    }
    let recipient = ua.to_zcash_address(deployment.address_network);
    let payments = prepared
        .frames()
        .iter()
        .map(|frame| {
            let memo = MemoBytes::from_bytes(frame)
                .map_err(CarrierTransactionRequestError::InvalidFrameMemo)?;
            Payment::new(
                recipient.clone(),
                Some(Zatoshis::ZERO),
                Some(memo),
                None,
                None,
                vec![],
            )
            .map_err(CarrierTransactionRequestError::InvalidPayment)
        })
        .collect::<Result<Vec<_>, _>>()?;
    TransactionRequest::new(payments).map_err(CarrierTransactionRequestError::InvalidRequest)
}

/// A proposal tied to the unpublished carrier material it must construct.
/// This intentionally has no `Debug`.
pub struct PreparedCarrierProposal<'a, FeeRuleT, NoteRef> {
    proposal: Proposal<FeeRuleT, NoteRef>,
    prepared: &'a PreparedCarrier,
    runtime_parameters: ValidatedCoreRuntimeParameters,
}

impl<FeeRuleT, NoteRef> PreparedCarrierProposal<'_, FeeRuleT, NoteRef> {
    pub fn proposal(&self) -> &Proposal<FeeRuleT, NoteRef> {
        &self.proposal
    }

    pub fn frame_count(&self) -> usize {
        self.prepared.frames().len()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrierProposalValidationError {
    UnexpectedTargetHeight { expected: u32, actual: u32 },
    CarrierPaymentNotIronwood { payment_index: usize },
    MultiStepCarrierProposalUnsupported { steps: usize },
}

fn cleanup_rejected_proposal<E>(
    validation: CarrierProposalValidationError,
    lock_request: Option<LockRequest>,
    cleanup: impl FnOnce(zcash_client_backend::wallet::LockOwner) -> Result<(), E>,
) -> Result<CarrierProposalValidationError, (CarrierProposalValidationError, E)> {
    if let Some(lock_request) = lock_request {
        cleanup(lock_request.owner()).map_err(|error| (validation, error))?;
    }
    Ok(validation)
}

#[derive(Debug)]
pub enum CarrierProposalError<HostError, LockError: Debug, ProposalError, CleanupError> {
    Request(CarrierTransactionRequestError),
    NetworkMismatch,
    LockedInputsPermitted,
    SpendGuard(SpendGuardError<HostError, LockError>),
    Proposal(ProposalError),
    TargetHeightOverflow,
    IronwoodNotActive {
        target_height: u32,
    },
    PostProposalValidation(CarrierProposalValidationError),
    ProposalCleanup {
        validation: CarrierProposalValidationError,
        error: CleanupError,
    },
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn propose_carrier_transaction<'a, Host, DbT, ParamsT, InputsT, ChangeT, CommitmentTreeErrT>(
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
    spend_policy: &SpendPolicy,
    lock_inputs: Option<LockRequest>,
    prepared: &'a PreparedCarrier,
) -> Result<
    PreparedCarrierProposal<'a, ChangeT::FeeRule, DbT::NoteRef>,
    CarrierProposalError<
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
        return Err(CarrierProposalError::NetworkMismatch);
    }
    if spend_policy.locked_input_policy().admits_locked() {
        return Err(CarrierProposalError::LockedInputsPermitted);
    }
    let request = carrier_transaction_request(runtime.deployment(), prepared)
        .map_err(CarrierProposalError::Request)?;
    let expected_height = runtime
        .tip()
        .height
        .checked_add(1)
        .ok_or(CarrierProposalError::TargetHeightOverflow)?;
    if !params.is_nu_active(
        NetworkUpgrade::Nu6_3,
        BlockHeight::from_u32(expected_height),
    ) {
        return Err(CarrierProposalError::IronwoodNotActive {
            target_height: expected_height,
        });
    }
    let target_height = zcash_client_backend::data_api::wallet::TargetHeight::from(expected_height);
    let mut backend = WalletCoppiceLockBackend::new(
        wallet_db,
        spend_from_account,
        target_height,
        orchard_fvk,
        capability,
    );
    let reconcile_capability = backend.capability();
    let account_id = crate::WalletAccountId::from_orchard_fvk(orchard_fvk);
    let (proposal_result, _) = with_coppice_spend_guard(
        mode,
        host_tip_source,
        runtime,
        pending,
        account_id,
        reconcile_capability,
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
                spend_policy,
                lock_inputs,
                None,
            )
        },
    )
    .map_err(CarrierProposalError::SpendGuard)?;
    let proposal = proposal_result.map_err(CarrierProposalError::Proposal)?;
    let actual_target_height: u32 = BlockHeight::from(proposal.min_target_height()).into();
    let validation = if actual_target_height != expected_height {
        Some(CarrierProposalValidationError::UnexpectedTargetHeight {
            expected: expected_height,
            actual: actual_target_height,
        })
    } else if proposal.steps().len() != 1 {
        Some(
            CarrierProposalValidationError::MultiStepCarrierProposalUnsupported {
                steps: proposal.steps().len(),
            },
        )
    } else {
        let step = proposal.steps().first();
        (0..prepared.frames().len()).find_map(|index| {
            (step.payment_pools().get(&index) != Some(&PoolType::IRONWOOD)).then_some(
                CarrierProposalValidationError::CarrierPaymentNotIronwood {
                    payment_index: index,
                },
            )
        })
    };
    if let Some(validation) = validation {
        let validation = cleanup_rejected_proposal(validation, lock_inputs, |owner| {
            unlock_proposal_inputs(backend.wallet_db_mut(), &proposal, owner)
        })
        .map_err(
            |(validation, error)| CarrierProposalError::ProposalCleanup { validation, error },
        )?;
        return Err(CarrierProposalError::PostProposalValidation(validation));
    }
    Ok(PreparedCarrierProposal {
        proposal,
        prepared,
        runtime_parameters: runtime.core().parameters().clone(),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConstructedCarrierTransaction {
    pub txid: TxId,
    pub frame_count: usize,
    pub serialized_size: usize,
}

#[derive(Debug)]
pub enum CarrierConstructionError<DbError, ConstructionError> {
    InvalidExpectedPayload,
    Construction(ConstructionError),
    UnexpectedTransactionCount {
        count: usize,
    },
    PostBuildInvariant {
        txid: TxId,
        reason: PostBuildInvariantError<DbError>,
    },
}

#[derive(Debug)]
pub enum PostBuildInvariantError<DbError> {
    ConstructedTransactionUnavailable(DbError),
    MissingConstructedTransaction,
    MissingIronwoodBundle,
    BulletinDecode(PostBuildRoutingError),
    BulletinFrameCountMismatch { expected: usize, actual: usize },
    BulletinFrameMismatch { index: usize },
    PayloadMismatch,
    Serialization,
    TransactionTooLarge { size: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostBuildRoutingError {
    NotFound,
    MalformedTransport,
    MalformedEnvelope,
    WrongApplication,
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn create_carrier_transaction<DbT, ParamsT, InputsErrT, FeeRuleT, ChangeErrT, N>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_prover: &impl SpendProver,
    output_prover: &impl OutputProver,
    spending_keys: &SpendingKeys,
    ovk_policy: OvkPolicy,
    prepared: PreparedCarrierProposal<'_, FeeRuleT, N>,
    expiry_height: Option<BlockHeight>,
) -> Result<
    ConstructedCarrierTransaction,
    CarrierConstructionError<
        <DbT as WalletRead>::Error,
        CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>,
    >,
>
where
    DbT: WalletWrite + WalletCommitmentTrees,
    ParamsT: consensus::Parameters + Clone,
    FeeRuleT: FeeRule,
{
    let expected_operation = envelope::decode_operation(prepared.prepared.payload())
        .map_err(|_| CarrierConstructionError::InvalidExpectedPayload)?;
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
    .map_err(CarrierConstructionError::Construction)?;
    if txids.len() != 1 {
        return Err(CarrierConstructionError::UnexpectedTransactionCount { count: txids.len() });
    }
    let txid = *txids.first();
    let tx: Transaction = wallet_db
        .get_transaction(txid)
        .map_err(|error| CarrierConstructionError::PostBuildInvariant {
            txid,
            reason: PostBuildInvariantError::ConstructedTransactionUnavailable(error),
        })?
        .ok_or(CarrierConstructionError::PostBuildInvariant {
            txid,
            reason: PostBuildInvariantError::MissingConstructedTransaction,
        })?;
    if tx.ironwood_bundle().is_none() {
        return Err(CarrierConstructionError::PostBuildInvariant {
            txid,
            reason: PostBuildInvariantError::MissingIronwoodBundle,
        });
    }
    let inspection = inspect_transaction(&tx, &prepared.runtime_parameters);
    if inspection.frames().len() != prepared.prepared.frames().len() {
        return Err(CarrierConstructionError::PostBuildInvariant {
            txid,
            reason: PostBuildInvariantError::BulletinFrameCountMismatch {
                expected: prepared.prepared.frames().len(),
                actual: inspection.frames().len(),
            },
        });
    }
    for (index, expected) in prepared.prepared.frames().iter().enumerate() {
        if !inspection.frames().contains(expected) {
            return Err(CarrierConstructionError::PostBuildInvariant {
                txid,
                reason: PostBuildInvariantError::BulletinFrameMismatch { index },
            });
        }
    }
    let message = match inspection.message() {
        ApplicationMessageStatus::Message(message)
            if message.key() == names_v1_application_key() =>
        {
            message
        }
        ApplicationMessageStatus::Message(_) => {
            return Err(CarrierConstructionError::PostBuildInvariant {
                txid,
                reason: PostBuildInvariantError::BulletinDecode(
                    PostBuildRoutingError::WrongApplication,
                ),
            });
        }
        ApplicationMessageStatus::MalformedTransport(_) => {
            return Err(CarrierConstructionError::PostBuildInvariant {
                txid,
                reason: PostBuildInvariantError::BulletinDecode(
                    PostBuildRoutingError::MalformedTransport,
                ),
            });
        }
        ApplicationMessageStatus::MalformedEnvelope(_) => {
            return Err(CarrierConstructionError::PostBuildInvariant {
                txid,
                reason: PostBuildInvariantError::BulletinDecode(
                    PostBuildRoutingError::MalformedEnvelope,
                ),
            });
        }
        ApplicationMessageStatus::NotCandidate | ApplicationMessageStatus::NoMessage => {
            return Err(CarrierConstructionError::PostBuildInvariant {
                txid,
                reason: PostBuildInvariantError::BulletinDecode(PostBuildRoutingError::NotFound),
            });
        }
    };
    if envelope::decode_operation(message.payload()).ok().as_ref() != Some(&expected_operation)
        || message.payload() != prepared.prepared.payload()
        || message.encode() != prepared.prepared.application_envelope()
    {
        return Err(CarrierConstructionError::PostBuildInvariant {
            txid,
            reason: PostBuildInvariantError::PayloadMismatch,
        });
    }
    let mut encoded = Vec::new();
    tx.write(&mut encoded)
        .map_err(|_| CarrierConstructionError::PostBuildInvariant {
            txid,
            reason: PostBuildInvariantError::Serialization,
        })?;
    let serialized_size = encoded.len();
    if serialized_size > MAX_FULL_TRANSACTION_LEN {
        return Err(CarrierConstructionError::PostBuildInvariant {
            txid,
            reason: PostBuildInvariantError::TransactionTooLarge {
                size: serialized_size,
            },
        });
    }
    Ok(ConstructedCarrierTransaction {
        txid,
        frame_count: prepared.prepared.frames().len(),
        serialized_size,
    })
}

#[cfg(test)]
mod tests {
    use coppice::{
        config::DeploymentParameters,
        constants::{MAX_ADDRESS_LEN, MAX_BOND_PROOF_LEN, REGTEST_ACTIVATION_HEIGHT},
        envelope::Operation,
    };
    use std::cell::Cell;
    use zcash_client_backend::wallet::LockOwner;
    use zcash_protocol::consensus::NetworkType;

    use super::*;

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

    fn prepared(deployment: &DeploymentParameters, operation: Operation) -> PreparedCarrier {
        let parameters =
            coppice::names_application::names_v1_core_runtime_parameters(deployment).unwrap();
        PreparedCarrier::from_operation(parameters.core_runtime_id(), &operation).unwrap()
    }

    fn assert_request(operation: Operation, expected_frames: usize) {
        let deployment = deployment();
        let prepared = prepared(&deployment, operation);
        assert_eq!(prepared.frames().len(), expected_frames);
        let request = carrier_transaction_request(&deployment, &prepared).unwrap();
        assert_eq!(request.payments().len(), expected_frames);

        let orchard = coppice::carrier::bulletin_address(deployment.rendezvous).unwrap();
        let ua = UnifiedAddress::from_receivers(Some(orchard), None, None).unwrap();
        assert_eq!(
            ua.orchard().unwrap().to_raw_address_bytes(),
            deployment.rendezvous.orchard_receiver
        );
        let expected_recipient = ua.to_zcash_address(deployment.address_network);
        for (index, payment) in request.payments() {
            assert_eq!(payment.recipient_address(), &expected_recipient);
            assert_eq!(payment.amount(), Some(Zatoshis::ZERO));
            let memo = payment.memo().unwrap();
            assert_eq!(memo.as_array(), &prepared.frames()[*index]);
            assert_eq!(memo.as_array()[0], 0xff);
        }
    }

    #[test]
    fn commit_maps_one_frame_to_one_exact_zero_valued_payment() {
        assert_request(
            Operation::Commit {
                commitment: [7; 32],
            },
            1,
        );
    }

    #[test]
    fn reveal_maps_twelve_frames_without_memo_mutation() {
        assert_request(
            Operation::Reveal {
                name: "carrier".to_owned(),
                owner_pk: [1; 32],
                bond_tag: [2; 32],
                bond_anchor_height: 100,
                bond_anchor: [3; 32],
                bond_proof: vec![4; 4_960],
                address: vec![5; MAX_ADDRESS_LEN],
                secret: [6; 32],
            },
            12,
        );
    }

    #[test]
    fn syntactic_max_reveal_maps_eighteen_distinct_payments() {
        assert_request(
            Operation::Reveal {
                name: "n".repeat(coppice::constants::MAX_NAME_LEN),
                owner_pk: [1; 32],
                bond_tag: [2; 32],
                bond_anchor_height: u32::MAX,
                bond_anchor: [3; 32],
                bond_proof: vec![4; MAX_BOND_PROOF_LEN],
                address: vec![5; MAX_ADDRESS_LEN],
                secret: [6; 32],
            },
            18,
        );
    }

    #[test]
    fn rejected_proposal_cleanup_is_exact_owner_scoped_and_optional() {
        let owner = LockOwner::new([9; 32]);
        let request = LockRequest::new(owner, 10);
        let calls = Cell::new(0);
        let observed = Cell::new(None);
        let validation =
            CarrierProposalValidationError::CarrierPaymentNotIronwood { payment_index: 2 };
        assert_eq!(
            cleanup_rejected_proposal(validation, Some(request), |actual| {
                calls.set(calls.get() + 1);
                observed.set(Some(actual));
                Ok::<_, ()>(())
            }),
            Ok(validation)
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(observed.get(), Some(owner));

        let no_lock_calls = Cell::new(0);
        assert_eq!(
            cleanup_rejected_proposal(validation, None, |_| {
                no_lock_calls.set(no_lock_calls.get() + 1);
                Ok::<_, ()>(())
            }),
            Ok(validation)
        );
        assert_eq!(no_lock_calls.get(), 0);
    }

    #[test]
    fn rejected_proposal_cleanup_failure_is_explicit() {
        let validation = CarrierProposalValidationError::UnexpectedTargetHeight {
            expected: 10,
            actual: 11,
        };
        let owner = LockOwner::new([8; 32]);
        assert_eq!(
            cleanup_rejected_proposal(validation, Some(LockRequest::new(owner, 10)), |actual| {
                assert_eq!(actual, owner);
                Err("storage")
            }),
            Err((validation, "storage"))
        );
    }
}
