use std::{collections::BTreeMap, env, fs, path::PathBuf};

use coppice_names::{
    codec::Operation,
    protocol::{CanonicalUa, CommitRef, Commitment, FieldElement, Name, Network, StateRef},
    reducer::{
        Accepted, Action, ApplyError, Block, Head, ProofVerifier, Reducer, ReferencedCommit,
        Resolution, RollbackError, Transaction,
    },
    resolver::ExactResolver,
    schedule::Parameters,
    statement::{RefreshStatement, RevealStatement},
};
use pasta_curves::{group::ff::PrimeField, pallas};
use serde::Deserialize;
use serde_json::{Map, Value, json};

#[derive(Deserialize)]
struct Corpus {
    format: String,
    network: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    activation_parent_hash_hex: String,
    parameters: CorpusParameters,
    tracked_names: Vec<String>,
    #[serde(default)]
    known_commit_refs: Vec<CorpusCommitRef>,
    steps: Vec<Step>,
}

#[derive(Clone, Deserialize)]
struct CorpusParameters {
    deployment_id_hex: String,
    activation_height: u32,
    epoch_blocks: u32,
    window_blocks: u32,
    commit_maturity_blocks: u32,
    commit_ttl_blocks: u32,
    lease_blocks: u32,
    cooldown_blocks: u32,
}

#[derive(Clone, Deserialize)]
struct CorpusCommitRef {
    height: u32,
    tx_index: u32,
    txid_hex: String,
}

#[derive(Clone, Deserialize)]
struct CorpusStateRef {
    height: u32,
    tx_index: u32,
    txid_hex: String,
    action_index: u32,
}

#[derive(Clone, Deserialize)]
struct CorpusReferencedCommit {
    reference: CorpusCommitRef,
    commitment: CorpusField,
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum CorpusField {
    Small(u64),
    LittleEndianHex(String),
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Step {
    AdvanceEmpty {
        label: String,
        through_height: u32,
        branch_byte: u8,
    },
    Apply {
        label: String,
        block: CorpusBlock,
        #[serde(default)]
        referenced_commits: Vec<CorpusReferencedCommit>,
    },
    Rollback {
        label: String,
        height: u32,
        branch_byte: u8,
        expected_hash_hex: Option<String>,
    },
}

#[derive(Clone, Deserialize)]
struct CorpusBlock {
    height: u32,
    branch_byte: u8,
    prev_hash_hex: Option<String>,
    #[serde(default)]
    transactions: Vec<CorpusTransaction>,
}

#[derive(Clone, Deserialize)]
struct CorpusTransaction {
    tx_index: u32,
    txid_hex: String,
    #[serde(default)]
    actions: Vec<CorpusAction>,
    operation: Option<CorpusOperation>,
}

#[derive(Clone, Deserialize)]
struct CorpusAction {
    action_index: u32,
    nullifier: CorpusField,
    commitment: CorpusField,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum CorpusOperation {
    Commit {
        commitment: CorpusField,
    },
    Reveal {
        name: String,
        commit: CorpusCommitRef,
        ua: String,
        action_index: u32,
        successor_future_nf: CorpusField,
        proof_valid: bool,
    },
    Refresh {
        name: String,
        predecessor: CorpusStateRef,
        ua: String,
        action_index: u32,
        successor_future_nf: CorpusField,
        proof_valid: bool,
    },
}

#[derive(Clone, Copy)]
struct ExplicitProofVerdicts;

impl ProofVerifier for ExplicitProofVerdicts {
    fn verify_reveal(&self, _: &RevealStatement, proof: &[u8]) -> bool {
        proof == [1]
    }

    fn verify_refresh(&self, _: &RefreshStatement, proof: &[u8]) -> bool {
        proof == [1]
    }
}

fn bytes32(hex_value: &str) -> Result<[u8; 32], String> {
    hex::decode(hex_value)
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| format!("expected 32 bytes: {hex_value}"))
}

fn field_bytes(value: &CorpusField) -> Result<[u8; 32], String> {
    match value {
        CorpusField::Small(value) => Ok(pallas::Base::from(*value).to_repr()),
        CorpusField::LittleEndianHex(value) => bytes32(value),
    }
}

fn field(value: &CorpusField) -> Result<FieldElement, String> {
    FieldElement::from_bytes(field_bytes(value)?)
        .map_err(|error| format!("invalid field: {error:?}"))
}

fn commitment(value: &CorpusField) -> Result<Commitment, String> {
    Commitment::from_bytes(field_bytes(value)?)
        .map_err(|error| format!("invalid commitment: {error:?}"))
}

fn hash(branch_byte: u8, height: u32) -> [u8; 32] {
    let mut value = [branch_byte; 32];
    value[28..].copy_from_slice(&height.to_be_bytes());
    value
}

fn parameters(value: &CorpusParameters) -> Result<Parameters, String> {
    Ok(Parameters {
        deployment_id: bytes32(&value.deployment_id_hex)?,
        activation_height: value.activation_height,
        epoch_blocks: value.epoch_blocks,
        window_blocks: value.window_blocks,
        commit_maturity_blocks: value.commit_maturity_blocks,
        commit_ttl_blocks: value.commit_ttl_blocks,
        lease_blocks: value.lease_blocks,
        cooldown_blocks: value.cooldown_blocks,
    })
}

fn commit_ref(value: &CorpusCommitRef) -> Result<CommitRef, String> {
    Ok(CommitRef {
        height: value.height,
        tx_index: value.tx_index,
        txid: bytes32(&value.txid_hex)?,
    })
}

fn state_ref(value: &CorpusStateRef) -> Result<StateRef, String> {
    Ok(StateRef {
        height: value.height,
        tx_index: value.tx_index,
        txid: bytes32(&value.txid_hex)?,
        action_index: value.action_index,
    })
}

fn operation(value: &CorpusOperation, network: Network) -> Result<Operation, String> {
    Ok(match value {
        CorpusOperation::Commit { commitment: value } => Operation::Commit {
            commitment: commitment(value)?,
        },
        CorpusOperation::Reveal {
            name,
            commit,
            ua,
            action_index,
            successor_future_nf,
            proof_valid,
        } => Operation::Reveal {
            name: Name::parse(name).map_err(|error| format!("invalid name: {error:?}"))?,
            commit: commit_ref(commit)?,
            ua: CanonicalUa::parse(network, ua)
                .map_err(|error| format!("invalid UA: {error:?}"))?,
            action_index: *action_index,
            successor_future_nf: field(successor_future_nf)?,
            proof: vec![u8::from(*proof_valid)],
        },
        CorpusOperation::Refresh {
            name,
            predecessor,
            ua,
            action_index,
            successor_future_nf,
            proof_valid,
        } => Operation::Refresh {
            name: Name::parse(name).map_err(|error| format!("invalid name: {error:?}"))?,
            predecessor: state_ref(predecessor)?,
            ua: CanonicalUa::parse(network, ua)
                .map_err(|error| format!("invalid UA: {error:?}"))?,
            action_index: *action_index,
            successor_future_nf: field(successor_future_nf)?,
            proof: vec![u8::from(*proof_valid)],
        },
    })
}

fn transaction(value: &CorpusTransaction, network: Network) -> Result<Transaction, String> {
    Ok(Transaction {
        tx_index: value.tx_index,
        txid: bytes32(&value.txid_hex)?,
        actions: value
            .actions
            .iter()
            .map(|action| {
                Ok(Action {
                    action_index: action.action_index,
                    nullifier: field(&action.nullifier)?,
                    commitment: field(&action.commitment)?,
                })
            })
            .collect::<Result<_, String>>()?,
        operation: value
            .operation
            .as_ref()
            .map(|operation_value| operation(operation_value, network))
            .transpose()?,
    })
}

fn block(value: &CorpusBlock, previous_hash: [u8; 32], network: Network) -> Result<Block, String> {
    Ok(Block {
        height: value.height,
        hash: hash(value.branch_byte, value.height),
        prev_hash: value
            .prev_hash_hex
            .as_deref()
            .map(bytes32)
            .transpose()?
            .unwrap_or(previous_hash),
        transactions: value
            .transactions
            .iter()
            .map(|transaction_value| transaction(transaction_value, network))
            .collect::<Result<_, _>>()?,
    })
}

fn referenced(values: &[CorpusReferencedCommit]) -> Result<Vec<ReferencedCommit>, String> {
    values
        .iter()
        .map(|value| {
            Ok(ReferencedCommit {
                reference: commit_ref(&value.reference)?,
                commitment: commitment(&value.commitment)?,
            })
        })
        .collect()
}

fn accepted(values: &[Accepted]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|value| Value::String(format!("{value:?}")))
            .collect(),
    )
}

fn operation_kind(value: Option<&CorpusOperation>, exact_name: Option<&Name>) -> &'static str {
    match value {
        None => "inert",
        Some(CorpusOperation::Commit { .. }) => "commit",
        Some(CorpusOperation::Reveal { name, .. }) => {
            if exact_name.is_some_and(|target| Name::parse(name).ok().as_ref() != Some(target)) {
                "inert"
            } else {
                "reveal"
            }
        }
        Some(CorpusOperation::Refresh { name, .. }) => {
            if exact_name.is_some_and(|target| Name::parse(name).ok().as_ref() != Some(target)) {
                "inert"
            } else {
                "refresh"
            }
        }
    }
}

fn producer_for(
    value: &CorpusTransaction,
    height: u32,
    operation: &CorpusOperation,
) -> Option<StateRef> {
    let action_index = match operation {
        CorpusOperation::Reveal { action_index, .. }
        | CorpusOperation::Refresh { action_index, .. } => *action_index,
        CorpusOperation::Commit { .. } => return None,
    };
    Some(StateRef {
        height,
        tx_index: value.tx_index,
        txid: bytes32(&value.txid_hex).ok()?,
        action_index,
    })
}

fn decisions(
    input: &CorpusBlock,
    accepted_block: bool,
    exact_name: Option<&Name>,
    resolve: impl Fn(&Name) -> Resolution,
) -> Value {
    Value::Array(
        input
            .transactions
            .iter()
            .map(|transaction| {
                let kind = operation_kind(transaction.operation.as_ref(), exact_name);
                let accepted = if !accepted_block {
                    Value::Null
                } else {
                    let decision = match (kind, transaction.operation.as_ref()) {
                        ("commit", _) => true,
                        ("reveal" | "refresh", Some(operation_value)) => {
                            let operation_name = match operation_value {
                                CorpusOperation::Reveal { name, .. }
                                | CorpusOperation::Refresh { name, .. } => Name::parse(name).ok(),
                                CorpusOperation::Commit { .. } => None,
                            };
                            operation_name.is_some_and(|name| {
                                resolve(&name).head.is_some_and(|head| {
                                    producer_for(transaction, input.height, operation_value)
                                        == Some(head.producer)
                                })
                            })
                        }
                        _ => false,
                    };
                    Value::Bool(decision)
                };
                json!({"tx_index": transaction.tx_index, "kind": kind, "accepted": accepted})
            })
            .collect(),
    )
}

fn apply_result<V: ProofVerifier>(
    reducer: &Reducer<V>,
    input: &CorpusBlock,
    result: Result<Vec<Accepted>, ApplyError>,
    exact_name: Option<&Name>,
) -> Value {
    match result {
        Ok(values) => json!({
            "ok": accepted(&values),
            "operations": decisions(input, true, exact_name, |name| reducer.resolve(name, input.height)),
        }),
        Err(error) => json!({
            "error": format!("{error:?}"),
            "operations": decisions(input, false, exact_name, |name| reducer.resolve(name, input.height)),
        }),
    }
}

fn exact_apply_result<V: ProofVerifier>(
    resolver: &ExactResolver<V>,
    input: &CorpusBlock,
    result: Result<Vec<Accepted>, ApplyError>,
    name: &Name,
) -> Value {
    match result {
        Ok(values) => json!({
            "ok": accepted(&values),
            "operations": decisions(input, true, Some(name), |_| resolver.resolve(input.height)),
        }),
        Err(error) => json!({
            "error": format!("{error:?}"),
            "operations": decisions(input, false, Some(name), |_| resolver.resolve(input.height)),
        }),
    }
}

fn ref_json(value: &CorpusCommitRef) -> Value {
    json!({"height": value.height, "tx_index": value.tx_index, "txid_hex": value.txid_hex})
}

fn state_ref_json(value: StateRef) -> Value {
    json!({
        "height": value.height,
        "tx_index": value.tx_index,
        "txid_hex": hex::encode(value.txid),
        "action_index": value.action_index,
    })
}

fn head_json(value: Head) -> Value {
    let future = value.future_nf.to_bytes();
    json!({
        "name": value.name.as_str(),
        "ua": value.ua.as_str(),
        "producer": state_ref_json(value.producer),
        "commitment_hex": hex::encode(value.commitment.to_bytes()),
        "future_nf_hex": hex::encode(future),
        "producer_epoch": value.producer_epoch,
        "expiry_height": value.expiry_height,
        "terminal_height": value.terminal_height,
    })
}

fn resolution_json(value: Resolution) -> Value {
    json!({
        "lifecycle": format!("{:?}", value.lifecycle),
        "ua": value.ua.map(|ua| ua.as_str().to_owned()),
        "head": value.head.map(head_json),
    })
}

fn tip_json(tip: Option<coppice_names::reducer::ReducerTip>) -> Value {
    tip.map_or(
        Value::Null,
        |tip| json!({"height": tip.height, "hash_hex": hex::encode(tip.hash)}),
    )
}

fn full_snapshot(
    reducer: &Reducer<ExplicitProofVerdicts>,
    names: &[(String, Name)],
    known_refs: &[CorpusCommitRef],
    parameters: Parameters,
) -> Result<Value, String> {
    let height = reducer
        .tip()
        .map(|tip| tip.height)
        .unwrap_or(parameters.activation_height);
    let resolutions = names
        .iter()
        .map(|(label, name)| {
            (
                label.clone(),
                resolution_json(reducer.resolve(name, height)),
            )
        })
        .collect::<Map<_, _>>();
    let pending = known_refs
        .iter()
        .map(|reference| {
            let reference_value = commit_ref(reference)?;
            Ok(json!({
                "reference": ref_json(reference),
                "commitment_hex": reducer.pending_commit(&reference_value).map(|value| hex::encode(value.to_bytes())),
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(
        json!({"tip": tip_json(reducer.tip()), "resolutions": resolutions, "pending_commits": pending}),
    )
}

fn exact_snapshot(
    resolver: &ExactResolver<ExplicitProofVerdicts>,
    label: &str,
    known_refs: &[CorpusCommitRef],
    parameters: Parameters,
) -> Result<Value, String> {
    let height = resolver
        .tip()
        .map(|tip| tip.height)
        .unwrap_or(parameters.activation_height);
    let mut resolutions = Map::new();
    resolutions.insert(label.to_owned(), resolution_json(resolver.resolve(height)));
    let pending = known_refs
        .iter()
        .map(|reference| {
            let reference_value = commit_ref(reference)?;
            Ok(json!({
                "reference": ref_json(reference),
                "commitment_hex": resolver.pending_commit(&reference_value).map(|value| hex::encode(value.to_bytes())),
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(
        json!({"tip": tip_json(resolver.tip()), "resolutions": resolutions, "pending_commits": pending}),
    )
}

fn rollback_result(result: Result<(), RollbackError>) -> Value {
    match result {
        Ok(()) => json!({"ok": true, "error": null}),
        Err(error) => json!({"ok": false, "error": format!("{error:?}")}),
    }
}

fn run_case(case: Case, network: Network) -> Result<Value, String> {
    let parameters = parameters(&case.parameters)?;
    let parent_hash = bytes32(&case.activation_parent_hash_hex)?;
    let names = case
        .tracked_names
        .iter()
        .map(|label| {
            Name::parse(label)
                .map(|name| (name.as_str().to_owned(), name))
                .map_err(|error| format!("invalid tracked name: {error:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut full = Reducer::new(parameters, parent_hash, ExplicitProofVerdicts)
        .map_err(|error| format!("invalid parameters: {error:?}"))?;
    let mut exact = names
        .iter()
        .map(|(label, name)| {
            ExactResolver::new(parameters, parent_hash, name.clone(), ExplicitProofVerdicts)
                .map(|resolver| (label.clone(), (name.clone(), resolver)))
                .map_err(|error| format!("invalid resolver: {error:?}"))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let mut trace = Vec::new();

    for step in case.steps {
        let (label, full_result, exact_results) = match step {
            Step::AdvanceEmpty {
                label,
                through_height,
                branch_byte,
            } => {
                let mut full_results = Vec::new();
                let mut exact_results: BTreeMap<String, Vec<Value>> = names
                    .iter()
                    .map(|(label, _)| (label.clone(), Vec::new()))
                    .collect();
                loop {
                    let next_height = full
                        .tip()
                        .map(|tip| tip.height.saturating_add(1))
                        .unwrap_or(parameters.activation_height);
                    if next_height > through_height {
                        break;
                    }
                    let previous_hash = full.tip().map(|tip| tip.hash).unwrap_or(parent_hash);
                    let corpus_block = CorpusBlock {
                        height: next_height,
                        branch_byte,
                        prev_hash_hex: None,
                        transactions: Vec::new(),
                    };
                    let block = block(&corpus_block, previous_hash, network)?;
                    let result = full.apply_block(&block);
                    full_results.push(apply_result(&full, &corpus_block, result, None));
                    for (name_label, (name, resolver)) in &mut exact {
                        let result = resolver.apply_block(&block);
                        exact_results
                            .get_mut(name_label)
                            .expect("initialized")
                            .push(exact_apply_result(resolver, &corpus_block, result, name));
                    }
                }
                (
                    label,
                    json!({"advance": full_results}),
                    exact_results
                        .into_iter()
                        .map(|(name, values)| (name, json!({"advance": values})))
                        .collect::<BTreeMap<_, _>>(),
                )
            }
            Step::Apply {
                label,
                block: input,
                referenced_commits,
            } => {
                let previous_hash = full.tip().map(|tip| tip.hash).unwrap_or(parent_hash);
                let materialized = block(&input, previous_hash, network)?;
                let evidence = referenced(&referenced_commits)?;
                let result = full.apply_block_with_referenced_commits(&materialized, &evidence);
                let full_result = apply_result(&full, &input, result, None);
                let mut exact_results = BTreeMap::new();
                for (name_label, (name, resolver)) in &mut exact {
                    let result =
                        resolver.apply_block_with_referenced_commits(&materialized, &evidence);
                    exact_results.insert(
                        name_label.clone(),
                        exact_apply_result(resolver, &input, result, name),
                    );
                }
                (label, full_result, exact_results)
            }
            Step::Rollback {
                label,
                height,
                branch_byte,
                expected_hash_hex,
            } => {
                let expected = expected_hash_hex
                    .as_deref()
                    .map(bytes32)
                    .transpose()?
                    .unwrap_or_else(|| hash(branch_byte, height));
                let full_result = rollback_result(full.rollback_tip(expected));
                let exact_results = exact
                    .iter_mut()
                    .map(|(name, (_, resolver))| {
                        (
                            name.clone(),
                            rollback_result(resolver.rollback_tip(expected)),
                        )
                    })
                    .collect();
                (label, full_result, exact_results)
            }
        };

        let full_state = full_snapshot(&full, &names, &case.known_commit_refs, parameters)?;
        let exact_state = exact
            .iter()
            .map(|(label, (_, resolver))| {
                exact_snapshot(resolver, label, &case.known_commit_refs, parameters)
                    .map(|value| (label.clone(), value))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        for (label_name, _) in &names {
            if full_state["resolutions"][label_name]
                != exact_state[label_name]["resolutions"][label_name]
            {
                return Err(format!(
                    "{}:{label}: full/exact resolution divergence for {label_name}",
                    case.id
                ));
            }
        }
        trace.push(json!({
            "label": label,
            "full_result": full_result,
            "exact_results": exact_results,
            "full_state": full_state,
            "exact_state": exact_state,
        }));
    }
    Ok(json!({"id": case.id, "trace": trace}))
}

fn main() -> Result<(), String> {
    let default = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/semantic_histories.json");
    let path = env::args_os().nth(1).map(PathBuf::from).unwrap_or(default);
    let corpus: Corpus =
        serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    if corpus.format != "coppice-names-semantic-history-v1" {
        return Err(format!("unsupported corpus format: {}", corpus.format));
    }
    let network = match corpus.network.as_str() {
        "main" => Network::Main,
        "test" => Network::Test,
        "regtest" => Network::Regtest,
        value => return Err(format!("unsupported network: {value}")),
    };
    let cases = corpus
        .cases
        .into_iter()
        .map(|case| run_case(case, network))
        .collect::<Result<Vec<_>, _>>()?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "format": "coppice-names-semantic-trace-v1",
            "cases": cases,
        }))
        .map_err(|error| error.to_string())?
    );
    Ok(())
}
