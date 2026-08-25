//! Wallet preparation for canonical v1 UPDATE, RELEASE, explicit bond spend,
//! and fail-closed payment resolution.

use std::fmt::Debug;

use coppice::{
    authorization,
    envelope::{self, Operation},
    names_runtime::NamesRuntime,
    owner::{self, OwnerSigningKey, owner_key_bytes},
    owner_kdf::{OwnerKdfError, derive_v1_owner_signing_key},
    record::{NameRecord, NameStatus},
    reveal::{RevealValidationError, canonical_v1_address},
};
use zcash_client_backend::data_api::{
    locking::LockedInputPolicy,
    wallet::input_selection::{NonEmptyBTreeSet, SpendPolicy},
};
use zcash_protocol::ShieldedPool;

use crate::{
    CarrierPreparationError, CoppiceLockBackend, ExactCanonicalTipError, HostCanonicalTipSource,
    InventoryError, IronwoodOutputId, IronwoodViewingCapability, PreparedCarrier,
    classify_owned_bonds, lock_owner_for_bond, require_exact_canonical_tip,
};

/// Owner authority supplied transiently by the host key-management layer.
pub enum OwnerAuthority<'a> {
    External(&'a OwnerSigningKey),
    DefaultSoftware(&'a [u8; 32]),
}

/// A signed canonical owner operation and its exact carrier bytes.
///
/// This intentionally has no `Debug`; it is unpublished transaction material.
pub struct PreparedOwnerOperation {
    pub name: String,
    pub sequence: u64,
    operation: Operation,
    carrier: PreparedCarrier,
}

impl PreparedOwnerOperation {
    pub fn operation(&self) -> &Operation {
        &self.operation
    }

    pub fn carrier(&self) -> &PreparedCarrier {
        &self.carrier
    }
}

#[derive(Debug)]
pub enum OwnerOperationError<HostError> {
    Tip(ExactCanonicalTipError<HostError>),
    InvalidName,
    NameNotFound,
    NameNotActive,
    SequenceOverflow,
    InvalidAddress(RevealValidationError),
    OwnerDerivation(OwnerKdfError),
    OwnerKeyMismatch,
    Authorization,
    Carrier(CarrierPreparationError),
}

fn owner_signing_key<'a>(
    runtime: &NamesRuntime,
    name: &str,
    record: &NameRecord,
    authority: OwnerAuthority<'a>,
    derived: &'a mut Option<OwnerSigningKey>,
) -> Result<&'a OwnerSigningKey, OwnerKdfError> {
    match authority {
        OwnerAuthority::External(key) => Ok(key),
        OwnerAuthority::DefaultSoftware(account_key) => {
            *derived = Some(derive_v1_owner_signing_key(
                *account_key,
                runtime.names_deployment_id().to_bytes(),
                owner::name_id(name),
                record.bond_tag,
            )?);
            Ok(derived.as_ref().expect("derived key was just installed"))
        }
    }
}

fn sign_and_frame<HostError>(
    runtime: &NamesRuntime,
    name: &str,
    previous: &NameRecord,
    mut operation: Operation,
    authority: OwnerAuthority<'_>,
) -> Result<PreparedOwnerOperation, OwnerOperationError<HostError>> {
    if previous.status != NameStatus::Active {
        return Err(OwnerOperationError::NameNotActive);
    }
    let mut derived = None;
    let signing_key = owner_signing_key(runtime, name, previous, authority, &mut derived)
        .map_err(OwnerOperationError::OwnerDerivation)?;
    let verification_key = owner_key_bytes(&signing_key.into());
    if verification_key != previous.owner_pk {
        return Err(OwnerOperationError::OwnerKeyMismatch);
    }
    let signature = authorization::sign_v1(
        runtime.names_deployment_id().to_bytes(),
        signing_key,
        &operation,
        previous,
    )
    .map_err(|_| OwnerOperationError::Authorization)?;
    match &mut operation {
        Operation::Update {
            signature: target, ..
        }
        | Operation::Release {
            signature: target, ..
        } => *target = signature.to_vec(),
        _ => return Err(OwnerOperationError::Authorization),
    }
    if !authorization::verify_v1(
        runtime.names_deployment_id().to_bytes(),
        &operation,
        previous,
    ) {
        return Err(OwnerOperationError::Authorization);
    }
    let sequence = match &operation {
        Operation::Update { sequence, .. } | Operation::Release { sequence, .. } => *sequence,
        _ => return Err(OwnerOperationError::Authorization),
    };
    let carrier = PreparedCarrier::from_operation(runtime.core().runtime_id(), &operation)
        .map_err(OwnerOperationError::Carrier)?;
    Ok(PreparedOwnerOperation {
        name: name.to_owned(),
        sequence,
        operation,
        carrier,
    })
}

pub fn prepare_update<Host: HostCanonicalTipSource>(
    host: &Host,
    runtime: &NamesRuntime,
    name: &str,
    new_address: &[u8],
    authority: OwnerAuthority<'_>,
) -> Result<PreparedOwnerOperation, OwnerOperationError<Host::Error>> {
    require_exact_canonical_tip(host, runtime).map_err(OwnerOperationError::Tip)?;
    let name = envelope::normalize_name(name).map_err(|_| OwnerOperationError::InvalidName)?;
    let previous = runtime
        .state()
        .names
        .get(&name)
        .ok_or(OwnerOperationError::NameNotFound)?;
    if previous.status != NameStatus::Active {
        return Err(OwnerOperationError::NameNotActive);
    }
    let address = canonical_v1_address(new_address, runtime.deployment())
        .map_err(OwnerOperationError::InvalidAddress)?;
    let sequence = previous
        .sequence
        .checked_add(1)
        .ok_or(OwnerOperationError::SequenceOverflow)?;
    sign_and_frame(
        runtime,
        &name,
        previous,
        Operation::Update {
            name: name.clone(),
            sequence,
            address,
            signature: vec![],
        },
        authority,
    )
}

pub fn prepare_release<Host: HostCanonicalTipSource>(
    host: &Host,
    runtime: &NamesRuntime,
    name: &str,
    authority: OwnerAuthority<'_>,
) -> Result<PreparedOwnerOperation, OwnerOperationError<Host::Error>> {
    require_exact_canonical_tip(host, runtime).map_err(OwnerOperationError::Tip)?;
    let name = envelope::normalize_name(name).map_err(|_| OwnerOperationError::InvalidName)?;
    let previous = runtime
        .state()
        .names
        .get(&name)
        .ok_or(OwnerOperationError::NameNotFound)?;
    if previous.status != NameStatus::Active {
        return Err(OwnerOperationError::NameNotActive);
    }
    let sequence = previous
        .sequence
        .checked_add(1)
        .ok_or(OwnerOperationError::SequenceOverflow)?;
    sign_and_frame(
        runtime,
        &name,
        previous,
        Operation::Release {
            name: name.clone(),
            sequence,
            signature: vec![],
        },
        authority,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDestination {
    pub name: String,
    pub address: Vec<u8>,
    pub sequence: u64,
}

#[derive(Debug)]
pub enum PaymentResolutionError<HostError> {
    Tip(ExactCanonicalTipError<HostError>),
    InvalidName,
    NameNotFound,
    NameNotActive,
    InvalidCanonicalAddress(RevealValidationError),
}

fn verified_destination<HostError>(
    runtime: &NamesRuntime,
    name: &str,
    record: &NameRecord,
) -> Result<VerifiedDestination, PaymentResolutionError<HostError>> {
    if record.status != NameStatus::Active {
        return Err(PaymentResolutionError::NameNotActive);
    }
    let address = canonical_v1_address(&record.address, runtime.deployment())
        .map_err(PaymentResolutionError::InvalidCanonicalAddress)?;
    Ok(VerifiedDestination {
        name: name.to_owned(),
        address,
        sequence: record.sequence,
    })
}

pub fn resolve_for_payment<Host: HostCanonicalTipSource>(
    host: &Host,
    runtime: &NamesRuntime,
    name: &str,
) -> Result<VerifiedDestination, PaymentResolutionError<Host::Error>> {
    require_exact_canonical_tip(host, runtime).map_err(PaymentResolutionError::Tip)?;
    let name = envelope::normalize_name(name).map_err(|_| PaymentResolutionError::InvalidName)?;
    let record = runtime
        .state()
        .names
        .get(&name)
        .ok_or(PaymentResolutionError::NameNotFound)?;
    verified_destination(runtime, &name, record)
}

/// Exact note and owner-scoped policy for an explicit Break Bond transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BreakBondPlan {
    pub name: String,
    pub output_id: IronwoodOutputId,
    pub bond_tag: [u8; 32],
}

impl BreakBondPlan {
    pub fn spend_policy(&self) -> SpendPolicy {
        SpendPolicy::shielded_pools([ShieldedPool::Ironwood]).with_locked_input_policy(
            LockedInputPolicy::PreferLocked(NonEmptyBTreeSet::singleton(lock_owner_for_bond(
                self.bond_tag,
            ))),
        )
    }
}

#[derive(Debug)]
pub enum BreakBondError<HostError, BackendError: Debug> {
    Tip(ExactCanonicalTipError<HostError>),
    InvalidName,
    NameNotFound,
    NameNotActive,
    Inventory(BackendError),
    Classification(InventoryError),
    MissingBondNote,
    AmbiguousBondNote,
}

pub fn prepare_break_bond<Host, Backend>(
    host: &Host,
    runtime: &NamesRuntime,
    name: &str,
    capability: IronwoodViewingCapability,
    backend: &Backend,
) -> Result<BreakBondPlan, BreakBondError<Host::Error, Backend::Error>>
where
    Host: HostCanonicalTipSource,
    Backend: CoppiceLockBackend,
{
    require_exact_canonical_tip(host, runtime).map_err(BreakBondError::Tip)?;
    let name = envelope::normalize_name(name).map_err(|_| BreakBondError::InvalidName)?;
    let record = runtime
        .state()
        .names
        .get(&name)
        .ok_or(BreakBondError::NameNotFound)?;
    if record.status != NameStatus::Active {
        return Err(BreakBondError::NameNotActive);
    }
    let notes = backend
        .owned_unspent_ironwood_notes()
        .map_err(BreakBondError::Inventory)?;
    let active = [record.bond_tag].into_iter().collect();
    let matching = classify_owned_bonds(&active, &notes, capability)
        .map_err(BreakBondError::Classification)?;
    match matching.as_slice() {
        [] => Err(BreakBondError::MissingBondNote),
        [bond] => Ok(BreakBondPlan {
            name,
            output_id: bond.output_id,
            bond_tag: bond.bond_tag,
        }),
        _ => Err(BreakBondError::AmbiguousBondNote),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coppice::{
        config::{DeploymentParameters, REGTEST},
        names_runtime::{CoreReplayActivationCheckpoint, IronwoodFrontier},
        owner_kdf::derive_v1_owner_signing_key,
    };
    use std::convert::Infallible;
    use zcash_protocol::consensus::NetworkType;

    const ADDRESS: &[u8] = b"uregtest15zjdhgeu9vfwkrgxvxyuynkprgryyww0cl668tpj0ykhl7nvvh7v7ln89f0v8c36vwyffxglg24zh5d4622ela80w065cc28mv7gf423";

    fn runtime() -> NamesRuntime {
        NamesRuntime::new(
            DeploymentParameters {
                network_id: REGTEST.network_id.to_vec(),
                address_network: NetworkType::Regtest,
                activation_height: 100,
                minimum_bond_value: REGTEST.minimum_bond_value,
                commit_ttl_blocks: 20,
                reuse_delay_blocks: 10,
                bond_note_max_age_blocks: 100,
                rendezvous: REGTEST.rendezvous,
            },
            CoreReplayActivationCheckpoint {
                height: 99,
                block_hash: [9; 32],
                ironwood_frontier: IronwoodFrontier::empty(),
                ironwood_tree_size: 0,
            },
        )
        .unwrap()
    }

    fn fixture_record(
        runtime: &NamesRuntime,
        account_key: [u8; 32],
    ) -> (NameRecord, OwnerSigningKey) {
        let bond_tag = [0x42; 32];
        let key = derive_v1_owner_signing_key(
            account_key,
            runtime.names_deployment_id().to_bytes(),
            owner::name_id("alice"),
            bond_tag,
        )
        .unwrap();
        (
            NameRecord {
                owner_pk: owner_key_bytes(&(&key).into()),
                bond_tag,
                sequence: 7,
                address: ADDRESS.to_vec(),
                status: NameStatus::Active,
            },
            key,
        )
    }

    #[test]
    fn update_and_release_use_exact_next_sequence_and_owner_authorization() {
        let runtime = runtime();
        let (record, key) = fixture_record(&runtime, [7; 32]);
        for operation in [
            Operation::Update {
                name: "alice".to_owned(),
                sequence: 8,
                address: ADDRESS.to_vec(),
                signature: vec![],
            },
            Operation::Release {
                name: "alice".to_owned(),
                sequence: 8,
                signature: vec![],
            },
        ] {
            let prepared = sign_and_frame::<Infallible>(
                &runtime,
                "alice",
                &record,
                operation,
                OwnerAuthority::External(&key),
            )
            .unwrap();
            assert_eq!(prepared.sequence, 8);
            assert!(authorization::verify_v1(
                runtime.names_deployment_id().to_bytes(),
                prepared.operation(),
                &record,
            ));
            assert_eq!(
                envelope::decode_operation(prepared.carrier().payload()).unwrap(),
                *prepared.operation()
            );
        }
    }

    #[test]
    fn default_owner_restores_and_wrong_owner_or_terminal_record_fail_closed() {
        let runtime = runtime();
        let (record, _) = fixture_record(&runtime, [7; 32]);
        let operation = Operation::Release {
            name: "alice".to_owned(),
            sequence: 8,
            signature: vec![],
        };
        assert!(
            sign_and_frame::<Infallible>(
                &runtime,
                "alice",
                &record,
                operation.clone(),
                OwnerAuthority::DefaultSoftware(&[7; 32]),
            )
            .is_ok()
        );

        let (_, wrong_key) = fixture_record(&runtime, [8; 32]);
        assert!(matches!(
            sign_and_frame::<Infallible>(
                &runtime,
                "alice",
                &record,
                operation.clone(),
                OwnerAuthority::External(&wrong_key),
            ),
            Err(OwnerOperationError::OwnerKeyMismatch)
        ));
        let mut terminal = record;
        terminal.status = NameStatus::Released {
            terminal_height: 101,
        };
        assert!(matches!(
            sign_and_frame::<Infallible>(
                &runtime,
                "alice",
                &terminal,
                operation,
                OwnerAuthority::DefaultSoftware(&[7; 32]),
            ),
            Err(OwnerOperationError::NameNotActive)
        ));
    }

    #[test]
    fn payment_resolution_and_break_bond_policy_are_fail_closed_and_owner_scoped() {
        let runtime = runtime();
        let (record, _) = fixture_record(&runtime, [7; 32]);
        let destination = verified_destination::<Infallible>(&runtime, "alice", &record).unwrap();
        assert_eq!(destination.address, ADDRESS);
        let mut terminal = record;
        terminal.status = NameStatus::BondSpent {
            terminal_height: 102,
        };
        assert!(matches!(
            verified_destination::<Infallible>(&runtime, "alice", &terminal),
            Err(PaymentResolutionError::NameNotActive)
        ));

        let plan = BreakBondPlan {
            name: "alice".to_owned(),
            output_id: IronwoodOutputId::new([1; 32], 3),
            bond_tag: [0x42; 32],
        };
        let policy = plan.spend_policy();
        assert_eq!(
            policy.shielded(),
            &[ShieldedPool::Ironwood].into_iter().collect()
        );
        assert!(policy.locked_input_policy().prefers_locked());
        assert_eq!(
            policy.locked_input_policy().overridable_owners(),
            &[lock_owner_for_bond(plan.bond_tag)].into_iter().collect()
        );
    }
}
