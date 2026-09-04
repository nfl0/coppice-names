//! Canonical machine-readable identity for Names reducer semantics.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Stable domain for the machine-readable semantic manifest.
pub const RULESET_DOMAIN: &str = "coppice-names-semantics";
/// BLAKE2b personalization used only for semantic-ruleset identities.
pub const RULESET_PERSONALIZATION: &[u8] = b"CoppiceNmRule";

const EMBEDDED_MANIFEST: &[u8] = include_bytes!("../../../ruleset/names.json");

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    clauses: Vec<Clause>,
    domain: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Clause {
    effect: Vec<String>,
    id: String,
    inputs: Vec<String>,
    rule_type: String,
    when: Vec<String>,
}

fn validate_ascii(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

fn parsed_manifest() -> Manifest {
    let manifest: Manifest =
        serde_json::from_slice(EMBEDDED_MANIFEST).expect("embedded ruleset manifest is valid JSON");
    assert_eq!(manifest.domain, RULESET_DOMAIN, "ruleset domain mismatch");
    let mut identifiers = BTreeSet::new();
    for clause in &manifest.clauses {
        assert!(
            validate_ascii(&clause.id)
                && validate_ascii(&clause.rule_type)
                && clause.inputs.iter().all(|value| validate_ascii(value))
                && clause.when.iter().all(|value| validate_ascii(value))
                && clause.effect.iter().all(|value| validate_ascii(value)),
            "ruleset strings must be nonempty printable ASCII"
        );
        assert!(
            identifiers.insert(clause.id.as_str()),
            "ruleset clause identifiers must be unique"
        );
    }
    manifest
}

/// Returns the RFC 8785-compatible canonical bytes for the restricted schema.
///
/// The schema admits only objects, arrays, and printable-ASCII strings.
/// `serde_json::Value` stores object keys in lexical
/// order without the `preserve_order` feature, so its compact encoding is the
/// RFC 8785 representation for this deliberately restricted value domain.
pub fn canonical_manifest() -> Vec<u8> {
    let value: Value = serde_json::to_value(parsed_manifest()).expect("manifest is serializable");
    serde_json::to_vec(&value).expect("manifest is serializable")
}

/// Returns all stable semantic clause identifiers in lexical order.
pub fn clause_ids() -> BTreeSet<String> {
    parsed_manifest()
        .clauses
        .into_iter()
        .map(|clause| clause.id)
        .collect()
}

/// Returns the domain-separated 32-byte identity of the current ruleset.
pub fn ruleset_fingerprint() -> [u8; 32] {
    blake2b_simd::Params::new()
        .hash_length(32)
        .personal(RULESET_PERSONALIZATION)
        .hash(&canonical_manifest())
        .as_bytes()
        .try_into()
        .expect("BLAKE2b-256 output")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_manifest_is_already_canonical() {
        assert_eq!(
            EMBEDDED_MANIFEST
                .strip_suffix(b"\n")
                .unwrap_or(EMBEDDED_MANIFEST),
            canonical_manifest()
        );
    }

    #[test]
    fn fingerprint_is_stable_and_domain_separated() {
        let fingerprint = ruleset_fingerprint();
        assert_ne!(fingerprint, [0; 32]);
        assert_ne!(
            fingerprint,
            blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"CoppiceNmDep")
                .hash(&canonical_manifest())
                .as_bytes()
        );
    }
}
