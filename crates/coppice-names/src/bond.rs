//! Dedicated Coppice bond-proof relation and its wallet-facing prover.
use crate::{
    bond_tag::{derive_v1_bond_tag, v1_bond_tag_domain_field},
    config::{DeploymentEncodingError, DeploymentParameters, Rendezvous},
    constants, crypto,
};
use halo2_proofs::{
    plonk::{
        ProvingKey, SingleVerifier, VerifyingKey, create_proof, keygen_pk, keygen_vk, verify_proof,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use incrementalmerkletree::Retention;
use orchard::{
    Note,
    builder::SpendInfo,
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note_encryption::IronwoodDomain,
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use pasta_curves::{group::ff::PrimeField, pallas, vesta};
use rand_chacha::ChaCha20Rng;
#[cfg(test)]
use rand_core::OsRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::Serialize;
use sha2::{Digest, Sha256};
use shardtree::{ShardTree, store::memory::MemoryShardStore};
#[cfg(test)]
use std::time::{Duration, Instant};
use zcash_address::unified::{self, Encoding};
use zcash_note_encryption::try_note_decryption;
use zcash_protocol::memo::MemoBytes;

use orchard::circuit::coppice_bond::CoppiceBondCircuit;

/// Minimum parameter size for the dedicated parallel-Merkle Coppice bond circuit.
pub const COPPICE_BOND_K: u32 = 11;
/// Exercises the inclusive `value >= B` boundary at exactly 1 ZEC.
pub const FIXTURE_VALUE: u64 = constants::MINIMUM_BOND_VALUE;
pub const FIXTURE_MINIMUM: u64 = constants::MINIMUM_BOND_VALUE;

/// Private wallet material for the dedicated Coppice v1 proof relation.
///
/// This intentionally has no `Debug` implementation because it contains spend
/// authorization material.
pub struct V1BondWitness {
    pub note: Note,
    pub full_viewing_key: FullViewingKey,
    pub spend_authorizing_key: SpendAuthorizingKey,
    pub merkle_path: MerklePath,
}

#[cfg(test)]
fn peak_memory_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn domain_field(domain: &[u8]) -> pallas::Base {
    assert!(domain.len() <= 16, "fixed binding domain is too long");
    let mut bytes = [0u8; 16];
    bytes[..domain.len()].copy_from_slice(domain);
    pallas::Base::from_u128(u128::from_le_bytes(bytes))
}

fn native_hash(domain: &[u8], value: pallas::Base) -> pallas::Base {
    halo2_gadgets::poseidon::primitives::Hash::<
        _,
        halo2_gadgets::poseidon::primitives::P128Pow5T3,
        halo2_gadgets::poseidon::primitives::ConstantLength<2>,
        3,
        2,
    >::init()
    .hash([domain_field(domain), value])
}
fn binding_32(domain: &[u8], bytes: [u8; 32]) -> pallas::Base {
    let lo = pallas::Base::from_u128(u128::from_le_bytes(bytes[..16].try_into().expect("length")));
    let hi = pallas::Base::from_u128(u128::from_le_bytes(bytes[16..].try_into().expect("length")));
    let pair = halo2_gadgets::poseidon::primitives::Hash::<
        _,
        halo2_gadgets::poseidon::primitives::P128Pow5T3,
        halo2_gadgets::poseidon::primitives::ConstantLength<2>,
        3,
        2,
    >::init()
    .hash([lo, hi]);
    native_hash(domain, pair)
}

const V1_PROTOCOL_DOMAIN: &str = "CoppiceProtoV1";
const V1_REGISTRATION_DOMAIN: &str = "CoppiceRegV1";
const V1_CONTEXT_DOMAIN: &str = "CoppiceCtxV1";
const V1_OWNER_DOMAIN: &str = "CoppiceOwnerV1";
pub const V1_BOND_VK_ID: [u8; 32] = [
    0xa1, 0x60, 0x74, 0xcf, 0xad, 0xab, 0xc4, 0xc2, 0x4b, 0xf5, 0x87, 0x32, 0x38, 0x9a, 0x4f, 0x2d,
    0x57, 0x4e, 0x25, 0xc4, 0x3f, 0x16, 0x92, 0x39, 0xec, 0x21, 0xda, 0x85, 0x2f, 0x5f, 0x7a, 0xdc,
];
const COPPICE_PUBLIC_INPUT_NAMES: [&str; 7] = [
    "anchor",
    "minimum_value",
    "position_floor",
    "protocol_binding",
    "context_binding",
    "owner_binding",
    "bond_tag",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V1BindingError {
    AddressTooLong,
    Hash(crypto::Error),
    Deployment(DeploymentEncodingError),
    InvalidPublicInput,
}

pub fn v1_protocol_binding(deployment_id: [u8; 32]) -> pallas::Base {
    binding_32(V1_PROTOCOL_DOMAIN.as_bytes(), deployment_id)
}

fn dedicated_v1_deployment_id() -> [u8; 32] {
    static DEPLOYMENT_ID: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *DEPLOYMENT_ID.get_or_init(|| {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/deployment.json"))
                .expect("deployment fixture JSON");
        let input = &fixture["input"];
        let parameters = DeploymentParameters {
            network_id: hex::decode(input["network_id_hex"].as_str().unwrap()).unwrap(),
            address_network: match input["network_type"].as_str().unwrap() {
                "Main" => zcash_protocol::consensus::NetworkType::Main,
                "Test" => zcash_protocol::consensus::NetworkType::Test,
                "Regtest" => zcash_protocol::consensus::NetworkType::Regtest,
                other => panic!("unknown network type {other}"),
            },
            activation_height: input["activation_height"]
                .as_u64()
                .unwrap()
                .try_into()
                .unwrap(),
            minimum_bond_value: input["minimum_bond_value"].as_u64().unwrap(),
            commit_ttl_blocks: input["commit_ttl_blocks"]
                .as_u64()
                .unwrap()
                .try_into()
                .unwrap(),
            reuse_delay_blocks: input["reuse_delay_blocks"]
                .as_u64()
                .unwrap()
                .try_into()
                .unwrap(),
            bond_note_max_age_blocks: input["bond_note_max_age_blocks"]
                .as_u64()
                .unwrap()
                .try_into()
                .unwrap(),
            rendezvous: Rendezvous {
                orchard_ivk: hex::decode(input["rendezvous_ivk_hex"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                orchard_receiver: hex::decode(input["rendezvous_receiver_hex"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            },
        };
        let expected: [u8; 32] =
            hex::decode(fixture["expected_deployment_id_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        let computed = parameters.deployment_id().expect("deployment fixture ID");
        assert_eq!(computed, expected, "deployment fixture ID");
        computed
    })
}

fn dedicated_v1_fixture_address() -> String {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../test-vectors/deployment.json"))
            .expect("deployment fixture JSON");
    let receiver: [u8; 43] = hex::decode(
        fixture["input"]["rendezvous_receiver_hex"]
            .as_str()
            .expect("deployment Orchard receiver"),
    )
    .expect("deployment Orchard receiver hex")
    .try_into()
    .expect("deployment Orchard receiver length");
    unified::Address::try_from_items(vec![unified::Receiver::Orchard(receiver)])
        .expect("single Orchard receiver is a valid Unified Address")
        .encode(&zcash_protocol::consensus::NetworkType::Regtest)
}

fn v1_registration_preimage(name: &str, address: &[u8]) -> Result<Vec<u8>, V1BindingError> {
    let address_len = u16::try_from(address.len()).map_err(|_| V1BindingError::AddressTooLong)?;
    let mut preimage = Vec::with_capacity(32 + 2 + address.len());
    preimage.extend_from_slice(&crate::owner::name_id(name));
    preimage.extend_from_slice(&address_len.to_be_bytes());
    preimage.extend_from_slice(address);
    Ok(preimage)
}

fn v1_registration_digest(name: &str, address: &[u8]) -> Result<[u8; 32], V1BindingError> {
    let preimage = v1_registration_preimage(name, address)?;
    crypto::hash(V1_REGISTRATION_DOMAIN, &preimage).map_err(V1BindingError::Hash)
}

pub fn v1_context_binding(name: &str, address: &[u8]) -> Result<pallas::Base, V1BindingError> {
    Ok(binding_32(
        V1_CONTEXT_DOMAIN.as_bytes(),
        v1_registration_digest(name, address)?,
    ))
}

pub fn v1_owner_binding(owner_pk: [u8; 32]) -> pallas::Base {
    binding_32(V1_OWNER_DOMAIN.as_bytes(), owner_pk)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V1BondPublicInputs {
    values: [pallas::Base; 7],
}

impl V1BondPublicInputs {
    pub fn from_runtime_facts(
        deployment: &DeploymentParameters,
        anchor: [u8; 32],
        position_floor: u32,
        name: &str,
        canonical_address: &[u8],
        owner_pk: [u8; 32],
        bond_tag: [u8; 32],
    ) -> Result<Self, V1BindingError> {
        let anchor = Option::<pallas::Base>::from(pallas::Base::from_repr(anchor))
            .ok_or(V1BindingError::InvalidPublicInput)?;
        let bond_tag = Option::<pallas::Base>::from(pallas::Base::from_repr(bond_tag))
            .ok_or(V1BindingError::InvalidPublicInput)?;
        let deployment_id = deployment
            .deployment_id()
            .map_err(V1BindingError::Deployment)?;
        Ok(Self {
            values: [
                anchor,
                pallas::Base::from(deployment.minimum_bond_value),
                pallas::Base::from(u64::from(position_floor)),
                v1_protocol_binding(deployment_id),
                v1_context_binding(name, canonical_address)?,
                v1_owner_binding(owner_pk),
                bond_tag,
            ],
        })
    }

    pub fn from_canonical_encodings(encodings: [[u8; 32]; 7]) -> Result<Self, V1BindingError> {
        let mut values = [pallas::Base::zero(); 7];
        for (output, encoding) in values.iter_mut().zip(encodings) {
            *output = Option::<pallas::Base>::from(pallas::Base::from_repr(encoding))
                .ok_or(V1BindingError::InvalidPublicInput)?;
        }
        Ok(Self { values })
    }

    fn as_slice(&self) -> &[pallas::Base] {
        &self.values
    }

    /// Returns the canonical public field encodings in protocol order.
    pub fn canonical_encodings(&self) -> [[u8; 32]; 7] {
        self.values.map(|value| value.to_repr())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V1BondVerifierError {
    KeyConstruction,
    VerifierIdentityMismatch,
}

pub struct V1BondVerifier {
    params: Params<vesta::Affine>,
    verifying_key: VerifyingKey<vesta::Affine>,
    verifier_id: [u8; 32],
}

type V1KeyMaterial = (Params<vesta::Affine>, VerifyingKey<vesta::Affine>, [u8; 32]);

fn v1_key_material() -> Result<V1KeyMaterial, V1BondVerifierError> {
    let params = Params::<vesta::Affine>::new(COPPICE_BOND_K);
    let circuit = CoppiceBondCircuit::verifier_only(v1_bond_tag_domain_field());
    let verifying_key =
        keygen_vk(&params, &circuit).map_err(|_| V1BondVerifierError::KeyConstruction)?;
    let artifact = format!("{:?}", verifying_key.pinned()).into_bytes();
    let verifier_id: [u8; 32] = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"CoppiceBondV1")
        .hash(&artifact)
        .as_bytes()
        .try_into()
        .expect("32-byte verifier identity");
    if verifier_id != V1_BOND_VK_ID {
        return Err(V1BondVerifierError::VerifierIdentityMismatch);
    }
    Ok((params, verifying_key, verifier_id))
}

impl V1BondVerifier {
    pub fn new() -> Result<Self, V1BondVerifierError> {
        let (params, verifying_key, verifier_id) = v1_key_material()?;
        Ok(Self {
            params,
            verifying_key,
            verifier_id,
        })
    }

    pub fn k(&self) -> u32 {
        COPPICE_BOND_K
    }

    pub fn verifier_id(&self) -> [u8; 32] {
        self.verifier_id
    }

    pub fn verify_v1_bond_proof(&self, proof: &[u8], inputs: &V1BondPublicInputs) -> bool {
        verify(&self.params, &self.verifying_key, proof, inputs.as_slice())
    }
}

/// Public output of dedicated v1 bond proving. No private note or key material
/// is retained here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V1BondProof {
    pub proof: Vec<u8>,
    pub anchor: [u8; 32],
    pub bond_tag: [u8; 32],
    pub position: u32,
    pub position_floor: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V1BondProverError {
    InvalidDeployment,
    InvalidName,
    InvalidAddress,
    InvalidOwnerKey,
    KeyConstruction,
    VerifierIdentityMismatch,
    FullViewingKeyMismatch,
    SpendAuthorityMismatch,
    BondTagMismatch,
    ValueBelowMinimum,
    PositionBelowFloor,
    AnchorMismatch,
    InvalidPublicInputs,
    ProvingFailed,
    SelfVerificationFailed,
    ProofTooLarge { size: usize, maximum: usize },
}

pub struct V1BondProver {
    params: Params<vesta::Affine>,
    proving_key: ProvingKey<vesta::Affine>,
    verifier_id: [u8; 32],
}

impl V1BondProver {
    pub fn new() -> Result<Self, V1BondProverError> {
        let (params, verifying_key, verifier_id) =
            v1_key_material().map_err(|error| match error {
                V1BondVerifierError::KeyConstruction => V1BondProverError::KeyConstruction,
                V1BondVerifierError::VerifierIdentityMismatch => {
                    V1BondProverError::VerifierIdentityMismatch
                }
            })?;
        let circuit = CoppiceBondCircuit::verifier_only(v1_bond_tag_domain_field());
        let proving_key = keygen_pk(&params, verifying_key, &circuit)
            .map_err(|_| V1BondProverError::KeyConstruction)?;
        Ok(Self {
            params,
            proving_key,
            verifier_id,
        })
    }

    pub fn k(&self) -> u32 {
        COPPICE_BOND_K
    }

    pub fn verifier_id(&self) -> [u8; 32] {
        self.verifier_id
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove_v1_bond<R: RngCore + CryptoRng>(
        &self,
        witness: V1BondWitness,
        deployment: &DeploymentParameters,
        name: &str,
        canonical_address: &[u8],
        owner_pk: [u8; 32],
        expected_bond_tag: [u8; 32],
        expected_anchor: [u8; 32],
        position_floor: u32,
        rng: R,
    ) -> Result<V1BondProof, V1BondProverError> {
        deployment
            .validate()
            .map_err(|_| V1BondProverError::InvalidDeployment)?;
        if !crate::envelope::valid_name(name) {
            return Err(V1BondProverError::InvalidName);
        }
        let canonical_address = crate::reveal::canonical_v1_address(canonical_address, deployment)
            .map_err(|_| V1BondProverError::InvalidAddress)?;
        crate::owner::parse_v1_owner_key(owner_pk)
            .map_err(|_| V1BondProverError::InvalidOwnerKey)?;

        let V1BondWitness {
            note,
            full_viewing_key,
            spend_authorizing_key,
            merkle_path,
        } = witness;
        let note_value = note.value().inner();
        if note_value < deployment.minimum_bond_value {
            return Err(V1BondProverError::ValueBelowMinimum);
        }
        let position = merkle_path.position();
        if position < position_floor {
            return Err(V1BondProverError::PositionBelowFloor);
        }
        let nf = note.nullifier(&full_viewing_key);
        let derived_tag = derive_v1_bond_tag(&nf.to_bytes())
            .map_err(|_| V1BondProverError::InvalidPublicInputs)?;
        if derived_tag != expected_bond_tag {
            return Err(V1BondProverError::BondTagMismatch);
        }
        let cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment());
        if merkle_path.root(cmx).to_bytes() != expected_anchor {
            return Err(V1BondProverError::AnchorMismatch);
        }
        let expected_ak: orchard::keys::SpendValidatingKey = (&spend_authorizing_key).into();
        let note_ak: orchard::keys::SpendValidatingKey = full_viewing_key.clone().into();
        let spend = SpendInfo::new(full_viewing_key, note, merkle_path)
            .ok_or(V1BondProverError::FullViewingKeyMismatch)?;
        if expected_ak != note_ak {
            return Err(V1BondProverError::SpendAuthorityMismatch);
        }
        let public_inputs = V1BondPublicInputs::from_runtime_facts(
            deployment,
            expected_anchor,
            position_floor,
            name,
            &canonical_address,
            owner_pk,
            expected_bond_tag,
        )
        .map_err(|_| V1BondProverError::InvalidPublicInputs)?;
        let values = public_inputs.as_slice();
        let circuit = CoppiceBondCircuit::from_spend(
            spend,
            spend_authorizing_key,
            deployment.minimum_bond_value,
            values[3],
            values[4],
            values[5],
            position_floor,
            v1_bond_tag_domain_field(),
        )
        .ok_or(V1BondProverError::SpendAuthorityMismatch)?;
        let proof = prove_with_rng(&self.params, &self.proving_key, circuit, values, rng)
            .map_err(|_| V1BondProverError::ProvingFailed)?;
        if proof.len() > constants::MAX_BOND_PROOF_LEN {
            return Err(V1BondProverError::ProofTooLarge {
                size: proof.len(),
                maximum: constants::MAX_BOND_PROOF_LEN,
            });
        }
        if !verify(&self.params, self.proving_key.get_vk(), &proof, values) {
            return Err(V1BondProverError::SelfVerificationFailed);
        }
        Ok(V1BondProof {
            proof,
            anchor: expected_anchor,
            bond_tag: expected_bond_tag,
            position,
            position_floor,
        })
    }
}

fn fixture_witness(
    value: u64,
    corrupt_path: bool,
    ask_override: Option<SpendAuthorizingKey>,
    note_seed: &[u8],
    position: u32,
) -> Option<V1BondWitness> {
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7; 32]))?;
    let ask = SpendAuthorizingKey::from(&sk);
    let fvk = FullViewingKey::from(&sk);
    let ivk = fvk.to_ivk(Scope::External);
    let recipient = fvk.address_at(0u32, Scope::External);
    let version = orchard::bundle::BundleVersion::ironwood_v3();
    let mut builder = orchard::builder::Builder::new(
        orchard::builder::BundleType::UNPADDED,
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .ok()?;
    builder
        .add_output(
            None,
            recipient,
            NoteValue::from_raw(value),
            MemoBytes::empty().into_bytes(),
        )
        .ok()?;
    let mut fixture_seed = Sha256::new();
    fixture_seed.update(b"CoppiceBondFixtureV1");
    fixture_seed.update(note_seed);
    let mut rng = ChaCha20Rng::from_seed(fixture_seed.finalize().into());
    let (bundle, meta) = builder.build::<i64>(&mut rng).ok()??;
    let action = bundle.actions().get(meta.output_action_index(0)?)?;
    let (note, _, _) =
        try_note_decryption(&IronwoodDomain::for_action(action), &ivk.prepare(), action)?;
    let cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment());
    let mut tree =
        ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
    for _ in 0..position {
        tree.append(MerkleHashOrchard::from_cmx(&cmx), Retention::Ephemeral)
            .ok()?;
    }
    tree.append(MerkleHashOrchard::from_cmx(&cmx), Retention::Marked)
        .ok()?;
    tree.checkpoint(1).ok()?;
    let mut path: MerklePath = tree
        .witness_at_checkpoint_depth(u64::from(position).into(), 0)
        .ok()??
        .into();
    if corrupt_path {
        let mut auth = path.auth_path();
        auth[0] = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(
            &pallas::Base::from(9).to_repr(),
        ))?;
        path = MerklePath::from_parts(path.position(), auth);
    }
    let actual_ask = ask_override.unwrap_or(ask);
    Some(V1BondWitness {
        note,
        full_viewing_key: fvk,
        spend_authorizing_key: actual_ask,
        merkle_path: path,
    })
}

#[allow(clippy::too_many_arguments)]
fn minimal_fixture(
    value: u64,
    minimum: u64,
    position: u32,
    position_floor: u32,
    corrupt_path: bool,
    ask_override: Option<SpendAuthorizingKey>,
    name: &str,
    note_seed: &[u8],
    owner_pk: [u8; 32],
    address: &[u8],
) -> Option<(CoppiceBondCircuit, Vec<pallas::Base>, [u8; 32])> {
    let V1BondWitness {
        note,
        full_viewing_key,
        spend_authorizing_key,
        merkle_path,
    } = fixture_witness(value, corrupt_path, ask_override, note_seed, position)?;
    let cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment());
    let anchor = merkle_path.root(cmx);
    let nf = note.nullifier(&full_viewing_key);
    let spend = SpendInfo::new(full_viewing_key, note, merkle_path)?;
    let protocol = v1_protocol_binding(dedicated_v1_deployment_id());
    let context = v1_context_binding(name, address).ok()?;
    let owner = v1_owner_binding(owner_pk);
    let circuit = CoppiceBondCircuit::from_spend(
        spend,
        spend_authorizing_key,
        minimum,
        protocol,
        context,
        owner,
        position_floor,
        v1_bond_tag_domain_field(),
    )?;
    let nf_bytes = nf.to_bytes();
    let tag_bytes = derive_v1_bond_tag(&nf_bytes).ok()?;
    let tag = Option::<pallas::Base>::from(pallas::Base::from_repr(tag_bytes))?;
    let anchor_field = Option::<pallas::Base>::from(pallas::Base::from_repr(anchor.to_bytes()))?;
    Some((
        circuit,
        vec![
            anchor_field,
            pallas::Base::from(minimum),
            pallas::Base::from(u64::from(position_floor)),
            protocol,
            context,
            owner,
            tag,
        ],
        nf_bytes,
    ))
}

#[derive(Serialize)]
struct PublicInputVector {
    name: &'static str,
    value: String,
}

#[derive(Serialize)]
struct FailedPublicInputMutation {
    index: usize,
    name: &'static str,
    mutated_value: String,
    accepted: bool,
}

#[derive(Serialize)]
struct BondProofVector {
    source_git_commit: String,
    halo2_proofs: &'static str,
    params: &'static str,
    commitment_scheme: &'static str,
    transcript: &'static str,
    proof_rng: &'static str,
    public_inputs: Vec<PublicInputVector>,
    verifier_artifact_format: &'static str,
    verifier_artifact: String,
    #[serde(rename = "BOND_VK_ID")]
    bond_vk_id: String,
    accepted_proof: String,
    proof_length: usize,
    accepted: bool,
    failed_public_input_mutations: Vec<FailedPublicInputMutation>,
    floor_equality_pass: bool,
    floor_minus_one_fail: bool,
}

#[derive(Serialize)]
struct BondTagVector {
    version: &'static str,
    canonical_nullifier: String,
    poseidon_bond_tag: String,
}

/// Generates the dedicated bond proof fixture and bond-tag vector.
///
/// `source_git_commit` is explicit so the generated artifact can identify the
/// source commit without creating a commit-hash cycle when the vectors themselves
/// are committed afterward.
pub fn generate_coppice_bond_vectors(
    source_git_commit: &str,
    canonical_nullifier: [u8; 32],
) -> Result<(String, String), String> {
    const PROOF_RNG_SEED: [u8; 32] = [42; 32];
    const FIXTURE_POSITION: u32 = 1;
    let owner = crate::owner::owner_key_bytes(
        &(&crate::owner::OwnerSigningKey::try_from([1; 32]).map_err(|_| "owner key")?).into(),
    );
    let fixture_address = dedicated_v1_fixture_address();
    let (circuit, instance, _) = minimal_fixture(
        FIXTURE_VALUE,
        FIXTURE_MINIMUM,
        FIXTURE_POSITION,
        FIXTURE_POSITION,
        false,
        None,
        "bonded",
        b"minimal-bond",
        owner,
        fixture_address.as_bytes(),
    )
    .ok_or("bond fixture")?;
    let params = Params::<vesta::Affine>::new(COPPICE_BOND_K);
    let vk = keygen_vk(&params, &circuit).map_err(|e| format!("vk: {e:?}"))?;
    let pk = keygen_pk(&params, vk, &circuit).map_err(|e| format!("pk: {e:?}"))?;
    let proof = prove_with_rng(
        &params,
        &pk,
        circuit,
        &instance,
        ChaCha20Rng::from_seed(PROOF_RNG_SEED),
    )
    .map_err(|e| format!("proof: {e:?}"))?;
    let accepted = verify(&params, pk.get_vk(), &proof, &instance);
    if !accepted {
        return Err("generated proof rejected".into());
    }

    let failed_public_input_mutations = COPPICE_PUBLIC_INPUT_NAMES
        .iter()
        .enumerate()
        .map(|(index, name)| {
            let mut mutated = instance.clone();
            mutated[index] += pallas::Base::one();
            FailedPublicInputMutation {
                index,
                name,
                mutated_value: hex::encode(mutated[index].to_repr()),
                accepted: verify(&params, pk.get_vk(), &proof, &mutated),
            }
        })
        .collect::<Vec<_>>();
    if failed_public_input_mutations
        .iter()
        .any(|mutation| mutation.accepted)
    {
        return Err("public input mutation accepted".into());
    }

    let failing_floor = FIXTURE_POSITION + 1;
    let (below_floor, below_floor_instance, _) = minimal_fixture(
        FIXTURE_VALUE,
        FIXTURE_MINIMUM,
        FIXTURE_POSITION,
        failing_floor,
        false,
        None,
        "bonded",
        b"minimal-bond",
        owner,
        fixture_address.as_bytes(),
    )
    .ok_or("below-floor fixture")?;
    let below_floor_proof = prove_with_rng(
        &params,
        &pk,
        below_floor,
        &below_floor_instance,
        ChaCha20Rng::from_seed(PROOF_RNG_SEED),
    )
    .map_err(|e| format!("below-floor proof: {e:?}"))?;
    let floor_minus_one_fail = !verify(
        &params,
        pk.get_vk(),
        &below_floor_proof,
        &below_floor_instance,
    );
    if !floor_minus_one_fail {
        return Err("position below floor accepted".into());
    }

    let verifier_artifact = format!("{:?}", pk.get_vk().pinned()).into_bytes();
    let bond_vk_id = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"CoppiceBondV1")
        .hash(&verifier_artifact);
    let bond = BondProofVector {
        source_git_commit: source_git_commit.to_owned(),
        halo2_proofs: "0.3.2",
        params: "Params::<vesta::Affine>::new(11)",
        commitment_scheme: "Halo2 IPA/Vesta",
        transcript: "Blake2bWrite/Blake2bRead with Challenge255",
        proof_rng: "ChaCha20Rng::from_seed([42; 32])",
        public_inputs: COPPICE_PUBLIC_INPUT_NAMES
            .iter()
            .zip(&instance)
            .map(|(name, value)| PublicInputVector {
                name,
                value: hex::encode(value.to_repr()),
            })
            .collect(),
        verifier_artifact_format: "UTF-8 Debug bytes of halo2_proofs::plonk::VerifyingKey::pinned()",
        verifier_artifact: hex::encode(verifier_artifact),
        bond_vk_id: hex::encode(bond_vk_id.as_bytes()),
        accepted_proof: hex::encode(&proof),
        proof_length: proof.len(),
        accepted,
        failed_public_input_mutations,
        floor_equality_pass: accepted,
        floor_minus_one_fail,
    };
    if bond.proof_length != 4_960 {
        return Err(format!("unexpected proof length: {}", bond.proof_length));
    }

    let bond_tag = derive_v1_bond_tag(&canonical_nullifier).map_err(|_| "canonical nullifier")?;
    let tag_vector = BondTagVector {
        version: "Coppice bond tag v1 Poseidon P128Pow5T3 ConstantLength<2>",
        canonical_nullifier: hex::encode(canonical_nullifier),
        poseidon_bond_tag: hex::encode(bond_tag),
    };

    fn json<T: Serialize>(value: &T) -> Result<String, String> {
        serde_json::to_string_pretty(value)
            .map(|json| json + "\n")
            .map_err(|e| e.to_string())
    }
    Ok((json(&bond)?, json(&tag_vector)?))
}

#[cfg(test)]
fn prove<C: halo2_proofs::plonk::Circuit<pallas::Base>>(
    params: &Params<vesta::Affine>,
    pk: &halo2_proofs::plonk::ProvingKey<vesta::Affine>,
    circuit: C,
    instance: &[pallas::Base],
) -> Result<Vec<u8>, halo2_proofs::plonk::Error> {
    prove_with_rng(params, pk, circuit, instance, OsRng)
}

fn prove_with_rng<C: halo2_proofs::plonk::Circuit<pallas::Base>, R: RngCore + CryptoRng>(
    params: &Params<vesta::Affine>,
    pk: &halo2_proofs::plonk::ProvingKey<vesta::Affine>,
    circuit: C,
    instance: &[pallas::Base],
    rng: R,
) -> Result<Vec<u8>, halo2_proofs::plonk::Error> {
    let columns: [&[pallas::Base]; 1] = [instance];
    let instances: [&[&[pallas::Base]]; 1] = [&columns];
    let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(Vec::new());
    create_proof(params, pk, &[circuit], &instances, rng, &mut transcript)?;
    Ok(transcript.finalize())
}
fn verify(
    params: &Params<vesta::Affine>,
    vk: &halo2_proofs::plonk::VerifyingKey<vesta::Affine>,
    proof: &[u8],
    instance: &[pallas::Base],
) -> bool {
    let columns: [&[pallas::Base]; 1] = [instance];
    let instances: [&[&[pallas::Base]]; 1] = [&columns];
    let strategy = SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof);
    verify_proof(params, vk, strategy, &instances, &mut transcript).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::plonk::ConstraintSystem;
    use zcash_address::unified::Container;

    fn deployment_vector_id() -> [u8; 32] {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/deployment.json")).unwrap();
        hex::decode(fixture["expected_deployment_id_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn fixture_deployment() -> DeploymentParameters {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/deployment.json")).unwrap();
        let input = &fixture["input"];
        DeploymentParameters {
            network_id: hex::decode(input["network_id_hex"].as_str().unwrap()).unwrap(),
            address_network: zcash_protocol::consensus::NetworkType::Regtest,
            activation_height: input["activation_height"].as_u64().unwrap() as u32,
            minimum_bond_value: input["minimum_bond_value"].as_u64().unwrap(),
            commit_ttl_blocks: input["commit_ttl_blocks"].as_u64().unwrap() as u32,
            reuse_delay_blocks: input["reuse_delay_blocks"].as_u64().unwrap() as u32,
            bond_note_max_age_blocks: input["bond_note_max_age_blocks"].as_u64().unwrap() as u32,
            rendezvous: Rendezvous {
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

    fn v1_witness_facts(witness: &V1BondWitness) -> ([u8; 32], [u8; 32]) {
        let tag = derive_v1_bond_tag(&witness.note.nullifier(&witness.full_viewing_key).to_bytes())
            .unwrap();
        let cmx = orchard::note::ExtractedNoteCommitment::from(witness.note.commitment());
        (tag, witness.merkle_path.root(cmx).to_bytes())
    }

    #[test]
    fn v1_binding_domains_are_exact() {
        assert_eq!(V1_PROTOCOL_DOMAIN, "CoppiceProtoV1");
        assert_eq!(V1_REGISTRATION_DOMAIN, "CoppiceRegV1");
        assert_eq!(V1_CONTEXT_DOMAIN, "CoppiceCtxV1");
        assert_eq!(V1_OWNER_DOMAIN, "CoppiceOwnerV1");
    }

    #[test]
    fn v1_protocol_binding_uses_deployment_vector_id() {
        assert_eq!(dedicated_v1_deployment_id(), deployment_vector_id());
        assert_eq!(
            v1_protocol_binding(deployment_vector_id()),
            binding_32(V1_PROTOCOL_DOMAIN.as_bytes(), deployment_vector_id())
        );
        assert_eq!(
            hex::encode(v1_protocol_binding(deployment_vector_id()).to_repr()),
            "c1f0f1ef06f5ffd8a21edcb859d46fbb55b653022a66a6d01ee4945c2cf0ae1f"
        );
        let owner = crate::owner::owner_key_bytes(
            &(&crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap()).into(),
        );
        assert_eq!(
            hex::encode(v1_owner_binding(owner).to_repr()),
            "9a89a45a3c07244e3b42f6058bdaccab77b438946c4826783e7f35955b89b514"
        );
    }

    #[test]
    fn dedicated_fixture_address_is_canonical_regtest_ua() {
        let encoded = dedicated_v1_fixture_address();
        println!("canonical-fixture-ua={encoded}");
        let (network, decoded) = unified::Address::decode(&encoded).unwrap();
        assert_eq!(network, zcash_protocol::consensus::NetworkType::Regtest);
        assert_eq!(decoded.encode(&network), encoded);

        let deployment: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/deployment.json")).unwrap();
        let expected_receiver = hex::decode(
            deployment["input"]["rendezvous_receiver_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(decoded.items().len(), 1);
        assert_eq!(
            decoded.items()[0],
            unified::Receiver::Orchard(expected_receiver.try_into().unwrap())
        );
    }

    #[test]
    fn v1_registration_digest_uses_u16_address_length() {
        let name = "bonded";
        let address = b"UA_BOND";
        let preimage = v1_registration_preimage(name, address).unwrap();
        let mut expected_preimage = crate::owner::name_id(name).to_vec();
        expected_preimage.extend_from_slice(&(address.len() as u16).to_be_bytes());
        expected_preimage.extend_from_slice(address);
        assert_eq!(preimage, expected_preimage);
        assert_eq!(
            v1_context_binding(name, address),
            v1_context_binding("bonded.zec", address)
        );
        assert_eq!(
            v1_registration_digest(name, address).unwrap(),
            crypto::hash(V1_REGISTRATION_DOMAIN, &expected_preimage).unwrap()
        );
        let too_long = vec![0; u16::MAX as usize + 1];
        assert_eq!(
            v1_registration_preimage(name, &too_long),
            Err(V1BindingError::AddressTooLong)
        );
    }

    #[test]
    fn dedicated_circuit_has_frozen_public_input_order() {
        assert_eq!(
            COPPICE_PUBLIC_INPUT_NAMES,
            [
                "anchor",
                "minimum_value",
                "position_floor",
                "protocol_binding",
                "context_binding",
                "owner_binding",
                "bond_tag",
            ]
        );
        let owner = crate::owner::owner_key_bytes(
            &(&crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap()).into(),
        );
        let fixture_address = dedicated_v1_fixture_address();
        let (_, instance, _) = minimal_fixture(
            FIXTURE_VALUE,
            FIXTURE_MINIMUM,
            1,
            1,
            false,
            None,
            "bonded",
            b"minimal-bond",
            owner,
            fixture_address.as_bytes(),
        )
        .unwrap();
        assert_eq!(instance.len(), COPPICE_PUBLIC_INPUT_NAMES.len());
    }

    const MINIMAL_TEST_POSITION: u32 = 1;

    fn minimal_good(
        value: u64,
        floor: u32,
        corrupt_path: bool,
        ask_override: Option<SpendAuthorizingKey>,
    ) -> Option<(CoppiceBondCircuit, Vec<pallas::Base>, [u8; 32])> {
        let owner = crate::owner::owner_key_bytes(
            &(&crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap()).into(),
        );
        let fixture_address = dedicated_v1_fixture_address();
        minimal_fixture(
            value,
            FIXTURE_MINIMUM,
            MINIMAL_TEST_POSITION,
            floor,
            corrupt_path,
            ask_override,
            "bonded",
            b"minimal-bond",
            owner,
            fixture_address.as_bytes(),
        )
    }

    fn circuit_stats<C: halo2_proofs::plonk::Circuit<pallas::Base>>() -> [usize; 7] {
        let mut cs = ConstraintSystem::<pallas::Base>::default();
        C::configure(&mut cs);
        let pinned = format!("{:?}", cs.pinned());
        let count = |field: &str| {
            pinned
                .split_once(field)
                .and_then(|(_, rest)| rest.split_once(','))
                .and_then(|(value, _)| value.trim().parse::<usize>().ok())
                .unwrap()
        };
        let permutation = pinned
            .split_once("permutation: Argument { columns: [")
            .and_then(|(_, rest)| rest.split_once("] }, lookups:"))
            .unwrap()
            .0;
        let permutation_columns = permutation.matches("Column {").count();
        let lookups = pinned
            .split_once("lookups: [")
            .and_then(|(_, rest)| rest.split_once("], constants:"))
            .unwrap()
            .0
            .matches("Argument { input_expressions")
            .count();
        let degree = cs.degree();
        [
            count("num_advice_columns:"),
            count("num_fixed_columns:"),
            count("num_instance_columns:"),
            lookups,
            permutation_columns,
            permutation_columns.div_ceil(degree - 2),
            degree,
        ]
    }

    #[test]
    fn minimal_bond_relation_positive_and_negative() {
        let (good, instance, _) =
            minimal_good(FIXTURE_VALUE, MINIMAL_TEST_POSITION, false, None).unwrap();
        let params = Params::<vesta::Affine>::new(11);
        let vk = keygen_vk(&params, &good).unwrap();
        let pk = keygen_pk(&params, vk, &good).unwrap();
        let proof = prove(&params, &pk, good, &instance).unwrap();
        assert!(verify(&params, pk.get_vk(), &proof, &instance));

        let (wrong_path, mut wrong_path_instance, _) =
            minimal_good(FIXTURE_VALUE, MINIMAL_TEST_POSITION, true, None).unwrap();
        let wrong_path_proof = prove(&params, &pk, wrong_path, &wrong_path_instance).unwrap();
        wrong_path_instance[0] = instance[0];
        assert!(!verify(
            &params,
            pk.get_vk(),
            &wrong_path_proof,
            &wrong_path_instance
        ));

        let wrong_sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([8; 32])).unwrap();
        assert!(
            minimal_good(
                FIXTURE_VALUE,
                MINIMAL_TEST_POSITION,
                false,
                Some(SpendAuthorizingKey::from(&wrong_sk)),
            )
            .is_none()
        );

        let (low, low_instance, _) =
            minimal_good(FIXTURE_MINIMUM - 1, MINIMAL_TEST_POSITION, false, None).unwrap();
        let low_proof = prove(&params, &pk, low, &low_instance).unwrap();
        assert!(!verify(&params, pk.get_vk(), &low_proof, &low_instance));

        for input in [3usize, 4, 5, 6] {
            let mut wrong = instance.clone();
            wrong[input] += pallas::Base::one();
            assert!(!verify(&params, pk.get_vk(), &proof, &wrong));
        }

        // Inclusive boundary: position == floor.
        assert_eq!(
            instance[2],
            pallas::Base::from(u64::from(MINIMAL_TEST_POSITION))
        );

        // position == floor - 1 must fail.
        let failing_floor = MINIMAL_TEST_POSITION + 1;
        let (below_floor, below_floor_instance, _) =
            minimal_good(FIXTURE_VALUE, failing_floor, false, None).unwrap();
        let below_floor_proof = prove(&params, &pk, below_floor, &below_floor_instance).unwrap();
        assert!(!verify(
            &params,
            pk.get_vk(),
            &below_floor_proof,
            &below_floor_instance
        ));
    }

    #[test]
    fn dedicated_bond_vectors_regenerate_byte_for_byte() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let bond_path = root.join("test-vectors/coppice_bond_v1.json");
        let tag_path = root.join("test-vectors/bond_tags.json");
        let expected_bond = std::fs::read_to_string(bond_path).expect("bond vector");
        let expected_tag = std::fs::read_to_string(tag_path).expect("tag vector");
        let frozen_bond: serde_json::Value = serde_json::from_str(&expected_bond).unwrap();
        let tag: serde_json::Value = serde_json::from_str(&expected_tag).unwrap();
        let source = frozen_bond["source_git_commit"].as_str().unwrap();
        let canonical_nullifier: [u8; 32] =
            hex::decode(tag["canonical_nullifier"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        let (generated_bond, tag) =
            generate_coppice_bond_vectors(source, canonical_nullifier).unwrap();
        let generated_bond_value: serde_json::Value =
            serde_json::from_str(&generated_bond).unwrap();
        let generated_public_inputs = generated_bond_value["public_inputs"].as_array().unwrap();
        assert_eq!(
            generated_public_inputs.len(),
            COPPICE_PUBLIC_INPUT_NAMES.len()
        );
        for index in [3usize, 4, 5] {
            println!(
                "{}={}",
                COPPICE_PUBLIC_INPUT_NAMES[index],
                generated_public_inputs[index]["value"].as_str().unwrap()
            );
        }
        assert_eq!(
            generated_bond_value["verifier_artifact"],
            frozen_bond["verifier_artifact"]
        );
        assert_eq!(
            generated_bond_value["BOND_VK_ID"],
            "a16074cfadabc4c24bf58732389a4f2d574e25c43f169239ec21da852f5f7adc"
        );
        assert_eq!(generated_bond, expected_bond);
        assert_eq!(tag, expected_tag);
    }

    #[test]
    fn frozen_dedicated_vector_uses_v1_tag_context_and_verifier_identity() {
        let frozen: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/coppice_bond_v1.json"))
                .unwrap();
        let owner = crate::owner::owner_key_bytes(
            &(&crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap()).into(),
        );
        let address = dedicated_v1_fixture_address();
        let (_, instance, nullifier) = minimal_fixture(
            FIXTURE_VALUE,
            FIXTURE_MINIMUM,
            1,
            1,
            false,
            None,
            "bonded",
            b"minimal-bond",
            owner,
            address.as_bytes(),
        )
        .unwrap();
        let public_inputs = frozen["public_inputs"].as_array().unwrap();
        assert_eq!(public_inputs.len(), COPPICE_PUBLIC_INPUT_NAMES.len());
        assert_eq!(
            public_inputs[4]["value"],
            hex::encode(
                v1_context_binding("bonded", address.as_bytes())
                    .unwrap()
                    .to_repr()
            )
        );
        assert_eq!(
            public_inputs[6]["value"],
            hex::encode(derive_v1_bond_tag(&nullifier).unwrap())
        );
        assert_eq!(
            public_inputs[6]["value"],
            hex::encode(instance[6].to_repr())
        );

        let verifier_artifact = hex::decode(frozen["verifier_artifact"].as_str().unwrap()).unwrap();
        let recomputed_id = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"CoppiceBondV1")
            .hash(&verifier_artifact);
        assert_eq!(frozen["BOND_VK_ID"], hex::encode(recomputed_id.as_bytes()));
        assert_ne!(
            frozen["BOND_VK_ID"],
            "d9e24e9de209f3256b4e3b7d0c681211792677bd3a6398bf6079cc2c581c0af3"
        );
        assert_eq!(frozen["proof_length"], 4_960);
    }

    #[test]
    fn runtime_v1_verifier_accepts_frozen_vector_and_rejects_bad_proofs() {
        let frozen: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/coppice_bond_v1.json"))
                .unwrap();
        let encodings: [[u8; 32]; 7] = frozen["public_inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|input| {
                hex::decode(input["value"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let inputs = V1BondPublicInputs::from_canonical_encodings(encodings).unwrap();
        let proof = hex::decode(frozen["accepted_proof"].as_str().unwrap()).unwrap();
        let verifier = V1BondVerifier::new().unwrap();
        assert_eq!(verifier.k(), 11);
        assert_eq!(verifier.verifier_id(), V1_BOND_VK_ID);
        assert!(verifier.verify_v1_bond_proof(&proof, &inputs));

        let mut mutated = encodings;
        let value = Option::<pallas::Base>::from(pallas::Base::from_repr(mutated[6])).unwrap()
            + pallas::Base::one();
        mutated[6] = value.to_repr();
        let mutated = V1BondPublicInputs::from_canonical_encodings(mutated).unwrap();
        assert!(!verifier.verify_v1_bond_proof(&proof, &mutated));

        let mut truncated = proof.clone();
        truncated.pop();
        assert!(!verifier.verify_v1_bond_proof(&truncated, &inputs));
        let mut corrupted = proof;
        corrupted[0] ^= 1;
        assert!(!verifier.verify_v1_bond_proof(&corrupted, &inputs));
    }

    #[test]
    fn production_v1_prover_matches_frozen_statement_and_proof_shape() {
        let frozen: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/coppice_bond_v1.json"))
                .unwrap();
        let deployment = fixture_deployment();
        let address = dedicated_v1_fixture_address();
        let owner = crate::owner::owner_key_bytes(
            &(&crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap()).into(),
        );
        let witness = fixture_witness(FIXTURE_VALUE, false, None, b"minimal-bond", 1).unwrap();
        let (tag, anchor) = v1_witness_facts(&witness);
        let inputs = V1BondPublicInputs::from_runtime_facts(
            &deployment,
            anchor,
            1,
            "bonded",
            address.as_bytes(),
            owner,
            tag,
        )
        .unwrap();
        let expected: [[u8; 32]; 7] = frozen["public_inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|input| {
                hex::decode(input["value"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        assert_eq!(inputs.canonical_encodings(), expected);

        let prover = V1BondProver::new().unwrap();
        assert_eq!(prover.k(), 11);
        assert_eq!(prover.verifier_id(), V1_BOND_VK_ID);
        let proof = prover
            .prove_v1_bond(
                witness,
                &deployment,
                "bonded",
                address.as_bytes(),
                owner,
                tag,
                anchor,
                1,
                ChaCha20Rng::from_seed([42; 32]),
            )
            .unwrap();
        assert_eq!(proof.proof.len(), 4_960);
        let verifier = V1BondVerifier::new().unwrap();
        assert!(verifier.verify_v1_bond_proof(&proof.proof, &inputs));
        for index in 0..7 {
            let mut mutated = expected;
            let value = Option::<pallas::Base>::from(pallas::Base::from_repr(mutated[index]))
                .unwrap()
                + pallas::Base::one();
            mutated[index] = value.to_repr();
            let mutated = V1BondPublicInputs::from_canonical_encodings(mutated).unwrap();
            assert!(!verifier.verify_v1_bond_proof(&proof.proof, &mutated));
        }
        let frozen_proof = hex::decode(frozen["accepted_proof"].as_str().unwrap()).unwrap();
        assert!(verifier.verify_v1_bond_proof(&frozen_proof, &inputs));
    }

    #[test]
    fn production_v1_prover_rejects_invalid_facts_before_proving() {
        let prover = V1BondProver::new().unwrap();
        let deployment = fixture_deployment();
        let address = dedicated_v1_fixture_address();
        let owner = crate::owner::owner_key_bytes(
            &(&crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap()).into(),
        );
        let prove = |witness: V1BondWitness,
                     name: &str,
                     address: &[u8],
                     owner: [u8; 32],
                     tag: [u8; 32],
                     anchor: [u8; 32],
                     floor: u32| {
            prover.prove_v1_bond(
                witness,
                &deployment,
                name,
                address,
                owner,
                tag,
                anchor,
                floor,
                ChaCha20Rng::from_seed([9; 32]),
            )
        };

        let witness = fixture_witness(FIXTURE_VALUE, false, None, b"tag", 1).unwrap();
        let (tag, anchor) = v1_witness_facts(&witness);
        let mut wrong_tag = tag;
        wrong_tag[0] ^= 1;
        assert!(matches!(
            prove(
                witness,
                "bonded",
                address.as_bytes(),
                owner,
                wrong_tag,
                anchor,
                1
            ),
            Err(V1BondProverError::BondTagMismatch)
        ));

        let witness = fixture_witness(FIXTURE_VALUE, false, None, b"anchor", 1).unwrap();
        let (tag, mut anchor) = v1_witness_facts(&witness);
        anchor[0] ^= 1;
        assert!(matches!(
            prove(witness, "bonded", address.as_bytes(), owner, tag, anchor, 1),
            Err(V1BondProverError::AnchorMismatch)
        ));

        let witness = fixture_witness(FIXTURE_MINIMUM - 1, false, None, b"value", 1).unwrap();
        let (tag, anchor) = v1_witness_facts(&witness);
        assert!(matches!(
            prove(witness, "bonded", address.as_bytes(), owner, tag, anchor, 1),
            Err(V1BondProverError::ValueBelowMinimum)
        ));

        let witness = fixture_witness(FIXTURE_VALUE, false, None, b"floor", 1).unwrap();
        let (tag, anchor) = v1_witness_facts(&witness);
        assert!(matches!(
            prove(witness, "bonded", address.as_bytes(), owner, tag, anchor, 2),
            Err(V1BondProverError::PositionBelowFloor)
        ));

        let other_sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([8; 32])).unwrap();
        let wrong_ask = SpendAuthorizingKey::from(&other_sk);
        let witness =
            fixture_witness(FIXTURE_VALUE, false, Some(wrong_ask), b"wrong-ask", 1).unwrap();
        let (tag, anchor) = v1_witness_facts(&witness);
        assert!(matches!(
            prove(witness, "bonded", address.as_bytes(), owner, tag, anchor, 1),
            Err(V1BondProverError::SpendAuthorityMismatch)
        ));

        let mut witness = fixture_witness(FIXTURE_VALUE, false, None, b"wrong-fvk", 1).unwrap();
        witness.full_viewing_key = FullViewingKey::from(&other_sk);
        let (tag, anchor) = v1_witness_facts(&witness);
        assert!(matches!(
            prove(witness, "bonded", address.as_bytes(), owner, tag, anchor, 1),
            Err(V1BondProverError::FullViewingKeyMismatch)
        ));

        for (name, candidate_address, candidate_owner, expected) in [
            (
                "Invalid",
                address.as_bytes(),
                owner,
                V1BondProverError::InvalidName,
            ),
            (
                "bonded",
                b"not-an-address".as_slice(),
                owner,
                V1BondProverError::InvalidAddress,
            ),
            (
                "bonded",
                address.as_bytes(),
                [0; 32],
                V1BondProverError::InvalidOwnerKey,
            ),
        ] {
            let witness = fixture_witness(FIXTURE_VALUE, false, None, name.as_bytes(), 1).unwrap();
            let (tag, anchor) = v1_witness_facts(&witness);
            assert_eq!(
                prove(
                    witness,
                    name,
                    candidate_address,
                    candidate_owner,
                    tag,
                    anchor,
                    1
                ),
                Err(expected)
            );
        }

        let mainnet_address = unified::Address::try_from_items(vec![unified::Receiver::Orchard(
            deployment.rendezvous.orchard_receiver,
        )])
        .unwrap()
        .encode(&zcash_protocol::consensus::NetworkType::Main);
        let witness = fixture_witness(FIXTURE_VALUE, false, None, b"network", 1).unwrap();
        let (tag, anchor) = v1_witness_facts(&witness);
        assert!(matches!(
            prove(
                witness,
                "bonded",
                mainnet_address.as_bytes(),
                owner,
                tag,
                anchor,
                1
            ),
            Err(V1BondProverError::InvalidAddress)
        ));

        let witness = fixture_witness(FIXTURE_VALUE, false, None, b"equal", 1).unwrap();
        let (tag, anchor) = v1_witness_facts(&witness);
        assert!(prove(witness, "bonded", address.as_bytes(), owner, tag, anchor, 1).is_ok());
    }

    #[test]
    #[ignore = "explicit one-time normative vector regeneration"]
    fn regenerate_dedicated_bond_vectors() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let tag_path = root.join("test-vectors/bond_tags.json");
        let tag: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&tag_path).unwrap()).unwrap();
        let canonical_nullifier = hex::decode(tag["canonical_nullifier"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let source = std::env::var("COPPICE_BOND_SOURCE_COMMIT")
            .expect("set COPPICE_BOND_SOURCE_COMMIT to the final generator source commit");
        let (bond, corrected_tag) =
            generate_coppice_bond_vectors(&source, canonical_nullifier).unwrap();
        assert_eq!(corrected_tag, std::fs::read_to_string(tag_path).unwrap());
        std::fs::write(root.join("test-vectors/coppice_bond_v1.json"), bond).unwrap();
    }

    #[test]
    #[ignore = "manual optimized benchmark"]
    fn minimal_bond_benchmark() {
        const RUNS: usize = 10;
        let (circuit, instance, _) =
            minimal_good(FIXTURE_VALUE, MINIMAL_TEST_POSITION, false, None).unwrap();
        for k in 9..=11 {
            let params = Params::<vesta::Affine>::new(k);
            let result = keygen_vk(&params, &circuit).and_then(|vk| {
                let pk = keygen_pk(&params, vk, &circuit)?;
                let proof = prove(&params, &pk, circuit.clone(), &instance)?;
                if verify(&params, pk.get_vk(), &proof, &instance) {
                    Ok(())
                } else {
                    Err(halo2_proofs::plonk::Error::ConstraintSystemFailure)
                }
            });
            println!("minimum-k-probe k={k} prove-verify={:?}", result.is_ok());
        }

        let k = 11;
        let params = Params::<vesta::Affine>::new(k);
        let vk = keygen_vk(&params, &circuit).unwrap();
        let pk = keygen_pk(&params, vk, &circuit).unwrap();
        let warmup = prove(&params, &pk, circuit.clone(), &instance).unwrap();
        assert!(verify(&params, pk.get_vk(), &warmup, &instance));

        let mut proof = Vec::new();
        let mut proving = Duration::ZERO;
        let mut verifying = Duration::ZERO;
        for _ in 0..RUNS {
            let start = Instant::now();
            proof = prove(&params, &pk, circuit.clone(), &instance).unwrap();
            proving += start.elapsed();
            let start = Instant::now();
            assert!(verify(&params, pk.get_vk(), &proof, &instance));
            verifying += start.elapsed();
        }
        let [
            advice,
            fixed,
            instance_columns,
            lookups,
            permutation_columns,
            permutation_sets,
            degree,
        ] = circuit_stats::<CoppiceBondCircuit>();
        println!(
            "columns advice={} fixed={} instance={} lookups={} permutation-columns={} permutation-product-sets={} degree={}",
            advice, fixed, instance_columns, lookups, permutation_columns, permutation_sets, degree,
        );
        println!("proof-bytes={}", proof.len());
        println!("prove-mean-us={}", proving.as_micros() / RUNS as u128);
        println!("verify-mean-us={}", verifying.as_micros() / RUNS as u128);
        println!("peak-rss-kib={:?}", peak_memory_kib());
    }
}
