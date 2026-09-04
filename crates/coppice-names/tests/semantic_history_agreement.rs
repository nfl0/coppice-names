use std::{path::PathBuf, process::Command};

use serde_json::Value;

fn case<'a>(trace: &'a Value, id: &str) -> &'a Value {
    trace["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == id)
        .unwrap()
}

fn step<'a>(case: &'a Value, label: &str) -> &'a Value {
    case["trace"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["label"] == label)
        .unwrap()
}

fn collect_clause_ids(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::Object(fields) => {
            if let Some(Value::String(identifier)) = fields.get("clause_id") {
                output.push(identifier.clone());
            }
            for child in fields.values() {
                collect_clause_ids(child, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_clause_ids(child, output);
            }
        }
        _ => {}
    }
}

#[test]
fn rust_and_independent_python_produce_exactly_the_same_trace() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let corpus = root.join("test-vectors/semantic_histories.json");
    let python = std::env::var_os("PYTHON").unwrap_or_else(|| "python3".into());

    let python_output = Command::new(python)
        .arg(root.join("scripts/verify-semantic-histories.py"))
        .arg(&corpus)
        .output()
        .expect("run independent Python semantic checker");
    assert!(
        python_output.status.success(),
        "Python checker failed:\n{}",
        String::from_utf8_lossy(&python_output.stderr)
    );

    let rust_output = Command::new(env!("CARGO_BIN_EXE_names-semantic-trace"))
        .arg(&corpus)
        .output()
        .expect("run Rust semantic trace consumer");
    assert!(
        rust_output.status.success(),
        "Rust consumer failed:\n{}",
        String::from_utf8_lossy(&rust_output.stderr)
    );

    let python_trace: Value = serde_json::from_slice(&python_output.stdout).unwrap();
    let rust_trace: Value = serde_json::from_slice(&rust_output.stdout).unwrap();
    assert_eq!(python_trace, rust_trace);
    assert_eq!(python_output.stdout, rust_output.stdout);
    let known_clauses = coppice_names::ruleset::clause_ids();
    let mut traced_clauses = Vec::new();
    collect_clause_ids(&rust_trace, &mut traced_clauses);
    assert!(!traced_clauses.is_empty());
    assert!(
        traced_clauses
            .iter()
            .all(|identifier| known_clauses.contains(identifier)),
        "trace emitted a clause ID absent from the normative manifest"
    );

    let cases = rust_trace["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    let lifecycle = case(&rust_trace, "lifecycle_competition_spend_refresh_and_fork");
    assert_eq!(
        step(lifecycle, "invalid-proof-first-valid-wins-competition")["full_result"]["operations"],
        serde_json::json!([
            {"tx_index": 0, "kind": "reveal", "accepted": false, "clause_id": "NAMES.REVEAL.PROOF"},
            {"tx_index": 1, "kind": "reveal", "accepted": true, "clause_id": "NAMES.REVEAL.ACCEPT"},
            {"tx_index": 2, "kind": "reveal", "accepted": false, "clause_id": "NAMES.REVEAL.MISSING"}
        ])
    );
    assert_eq!(
        step(lifecycle, "malformed-bulletin-ordinary-bond-spend")["full_state"]["resolutions"]["alice"]
            ["lifecycle"],
        "Cooldown"
    );
    assert_eq!(
        step(lifecycle, "malformed-bulletin-ordinary-bond-spend")["full_result"]["transitions"][0]
            ["clause_id"],
        "NAMES.SPEND.CURRENT"
    );
    assert_eq!(
        step(lifecycle, "last-cooldown-block")["full_state"]["resolutions"]["alice"]["lifecycle"],
        "Cooldown"
    );
    let replacement = step(lifecycle, "first-missing-replacement");
    assert_eq!(
        replacement["full_result"]["transitions"][0]["clause_id"],
        "NAMES.LIFECYCLE.COMPACT"
    );
    assert_eq!(
        replacement["full_result"]["ok"],
        serde_json::json!(["Reveal"])
    );
    assert_eq!(
        step(lifecycle, "rollback-replacement")["full_state"]["resolutions"]["alice"]["lifecycle"],
        "Cooldown"
    );
    assert_eq!(
        step(lifecycle, "fork-replacement")["full_result"]["transitions"][0]["transition"],
        "Compacted"
    );
    assert_eq!(
        step(lifecycle, "stale-refresh-then-valid-refresh")["full_result"]["operations"],
        serde_json::json!([
            {"tx_index": 0, "kind": "refresh", "accepted": false, "clause_id": "NAMES.REFRESH.CURRENT"},
            {"tx_index": 1, "kind": "refresh", "accepted": true, "clause_id": "NAMES.REFRESH.ACCEPT"}
        ])
    );
    let boundary = step(lifecycle, "expiry-missing-boundary");
    assert_eq!(
        boundary["full_state"]["resolutions"]["alice"]["lifecycle"],
        "Missing"
    );
    assert!(boundary["full_state"]["resolutions"]["alice"]["head"].is_null());
    assert_eq!(
        boundary["full_result"]["advance"][0]["transitions"][0]["clause_id"],
        "NAMES.LIFECYCLE.COMPACT"
    );

    let referenced = case(&rust_trace, "referenced_commit_atomicity_and_reapply");
    assert_eq!(
        step(referenced, "conflicting-evidence-rejected-atomically")["full_result"]["error"],
        "ConflictingReferencedCommit"
    );
    assert_eq!(
        step(referenced, "valid-evidence-reapply")["full_result"]["ok"],
        serde_json::json!(["Reveal"])
    );

    let structural = case(&rust_trace, "structural_rejection_and_rollback_errors");
    assert_eq!(
        step(structural, "wrong-parent")["full_result"]["error"],
        "WrongPreviousHash"
    );
    assert_eq!(
        step(structural, "noncanonical-action-position")["full_result"]["error"],
        "NonCanonicalActionIndex"
    );
    assert_eq!(
        step(structural, "rollback-empty-history")["full_result"]["error"],
        "NoAppliedBlock"
    );

    let timing = case(&rust_trace, "timing_endpoints_and_exact_filtering");
    assert_eq!(
        step(timing, "ttl-maturity-and-window-end-boundaries")["full_result"]["operations"],
        serde_json::json!([
            {"tx_index": 0, "kind": "reveal", "accepted": false, "clause_id": "NAMES.REVEAL.COMMIT"},
            {"tx_index": 1, "kind": "reveal", "accepted": true, "clause_id": "NAMES.REVEAL.ACCEPT"},
            {"tx_index": 2, "kind": "reveal", "accepted": false, "clause_id": "NAMES.REVEAL.SCHEDULE"}
        ])
    );
}
