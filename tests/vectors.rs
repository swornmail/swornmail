//! Cross-implementation freeze gate: this crate must agree with the shared
//! vectors published in the specification repository, case for case.
//!
//! Vector file resolution, in order: `$SWORN_VECTORS`, the sibling spec
//! checkout, then the vendored snapshot under `tests/testdata/`.

use std::env;
use std::path::PathBuf;

use base64::Engine as _;
use serde_json::Value as Json;
use swornmail::{
    reason_str, verify_signature_only, Ed25519PublicKey, KeyRecord, PolicyRecord, Reason,
};

const SPEC: &str = "draft-kafedzhy-swornmail-01";

fn vectors_path() -> PathBuf {
    if let Ok(path) = env::var("SWORN_VECTORS") {
        return PathBuf::from(path);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let shared = manifest.join("../swornmail-spec/test-vectors/v1.json");
    if shared.exists() {
        return shared;
    }
    manifest.join("tests/testdata/v1.json")
}

fn vectors() -> Json {
    let path = vectors_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading vectors at {}: {e}", path.display()));
    let json: Json = serde_json::from_str(&text).expect("vectors are valid JSON");
    assert_eq!(json["spec"].as_str(), Some(SPEC), "unexpected vector spec");
    json
}

fn operator_key(json: &Json) -> Ed25519PublicKey {
    let raw = hex::decode(json["ed25519_public_hex"].as_str().expect("public key hex"))
        .expect("public key is hex");
    Ed25519PublicKey::from_bytes(&raw).expect("public key is a valid Ed25519 point")
}

fn token_bytes(case: &Json, name: &str) -> Vec<u8> {
    let wire = case["token_b64url"].as_str().expect("token_b64url");
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(wire)
        .unwrap_or_else(|e| panic!("{name}: token_b64url does not decode: {e}"));
    // The three encodings in the file must describe the same octets.
    assert_eq!(
        hex::encode(&token),
        case["token_hex"].as_str().expect("token_hex"),
        "{name}: token_b64url and token_hex disagree"
    );
    assert_eq!(
        token,
        base64::engine::general_purpose::STANDARD
            .decode(case["token_b64std"].as_str().expect("token_b64std"))
            .expect("token_b64std decodes"),
        "{name}: token_b64url and token_b64std disagree"
    );
    token
}

#[test]
fn token_cases_match_vectors() {
    let json = vectors();
    let key = operator_key(&json);
    let cases = json["cases"].as_array().expect("cases array");
    // The v1 freeze set has 48 cases; a shorter file means a truncated or
    // filtered copy, which would pass vacuously.
    assert!(cases.len() >= 48, "only {} token cases found", cases.len());

    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let token = token_bytes(case, name);
        let source = case["source_ip"]
            .as_str()
            .expect("source_ip")
            .parse()
            .unwrap_or_else(|e| panic!("{name}: source_ip does not parse: {e}"));
        let now = case["now_unix"].as_i64().expect("now_unix");

        let outcome = verify_signature_only(&token, &key, source, now);
        let got = reason_str(&outcome);

        match (case.get("expect"), case.get("expect_any")) {
            (Some(expect), None) => {
                let want = expect.as_str().expect("expect is a string");
                assert_eq!(got, want, "{name}: reason mismatch");
            }
            (None, Some(any)) => {
                let want: Vec<&str> = any
                    .as_array()
                    .expect("expect_any is an array")
                    .iter()
                    .map(|v| v.as_str().expect("reason is a string"))
                    .collect();
                assert!(
                    want.contains(&got),
                    "{name}: reason {got} is not one of {want:?}"
                );
            }
            _ => panic!("{name}: case must carry exactly one of expect / expect_any"),
        }

        if let Ok(verified) = outcome {
            if let Some(operator) = case.get("operator") {
                assert_eq!(
                    verified.operator,
                    operator.as_str().expect("operator is a string"),
                    "{name}: operator mismatch"
                );
            }
            if let Some(unit) = case.get("unit") {
                assert_eq!(
                    verified.unit.to_string(),
                    unit.as_str().expect("unit is a string"),
                    "{name}: reputation unit mismatch"
                );
            }
        }
    }
}

#[test]
fn record_cases_match_vectors() {
    let json = vectors();
    let records = json["records"].as_array().expect("records array");
    assert!(
        records.len() >= 14,
        "only {} record cases found",
        records.len()
    );

    for record in records {
        let name = record["name"].as_str().expect("record name");
        let txt = record["txt"].as_str().expect("record txt");
        let outcome = match record["kind"].as_str().expect("record kind") {
            "key" => KeyRecord::parse(txt).map(|_| ()).map_err(|e| e.to_string()),
            "policy" => PolicyRecord::parse(txt)
                .map(|_| ())
                .map_err(|e| e.to_string()),
            other => panic!("{name}: unknown record kind {other}"),
        };
        match record["expect"].as_str().expect("record expect") {
            "ok" => assert!(outcome.is_ok(), "{name}: expected ok, got {outcome:?}"),
            "error" => assert!(outcome.is_err(), "{name}: expected error, got ok"),
            other => panic!("{name}: unknown expectation {other}"),
        }
    }
}

/// The two-phase flow a receiver actually uses must reach the same result, and
/// must name the key record to fetch before any signature check happens.
#[test]
fn two_phase_flow_names_the_key_record() {
    let json = vectors();
    let case = json["cases"]
        .as_array()
        .expect("cases array")
        .iter()
        .find(|c| c["name"] == "valid_in_prefix")
        .expect("valid_in_prefix case");
    let token = token_bytes(case, "valid_in_prefix");

    let pending = swornmail::parse(
        &token,
        case["source_ip"].as_str().unwrap().parse().unwrap(),
        case["now_unix"].as_i64().unwrap(),
    )
    .expect("local checks pass");
    let policy = PolicyRecord::parse(json["policy_record"].as_str().expect("policy record"))
        .expect("policy record parses");
    assert_eq!(
        format!("_prefixes._sworn.{}", pending.operator()),
        json["policy_record_qname"]
            .as_str()
            .expect("policy_record_qname")
    );
    let authorized = pending.authorize(&policy).expect("policy authorizes token");
    assert_eq!(
        format!("{}._sworn.{}", authorized.selector(), authorized.operator()),
        json["key_record_qname"].as_str().expect("key_record_qname")
    );

    let outcome = authorized
        .verify_signature(&operator_key(&json))
        .expect("signature verifies");
    let verified = match &outcome {
        swornmail::Outcome::Pass(v) => v,
        swornmail::Outcome::ObserveOnly(_) => panic!("committed policy reported as observe-only"),
    };
    assert_eq!(verified.unit.to_string(), case["unit"].as_str().unwrap());
    assert_eq!(outcome.auth_result(), "pass");
}

#[test]
fn policy_authorization_blocks_key_only_impersonation() {
    let json = vectors();
    let case = json["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "valid_in_prefix")
        .unwrap();
    let token = token_bytes(case, "valid_in_prefix");
    let source = case["source_ip"].as_str().unwrap().parse().unwrap();
    let now = case["now_unix"].as_i64().unwrap();

    let unrelated = PolicyRecord::parse("v=SWORN1; p=2001:db8:bad::/48; u=64").unwrap();
    assert_eq!(
        swornmail::parse(&token, source, now)
            .unwrap()
            .authorize(&unrelated)
            .unwrap_err(),
        swornmail::Reason::UnauthorizedPrefix
    );

    let wrong_unit = PolicyRecord::parse("v=SWORN1; p=2001:db8:f00::/48; u=56").unwrap();
    assert_eq!(
        swornmail::parse(&token, source, now)
            .unwrap()
            .authorize(&wrong_unit)
            .unwrap_err(),
        swornmail::Reason::PolicyUnitMismatch
    );
}

#[test]
fn testing_policy_can_never_be_reported_as_pass() {
    let json = vectors();
    let case = json["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "valid_in_prefix")
        .unwrap();
    let token = token_bytes(case, "valid_in_prefix");
    let policy =
        PolicyRecord::parse("v=SWORN1; p=2001:db8:f00::/48; u=64; t=y; rua=mailto:a@b.example")
            .unwrap();
    let outcome = swornmail::verify(
        &token,
        &operator_key(&json),
        &policy,
        case["source_ip"].as_str().unwrap().parse().unwrap(),
        case["now_unix"].as_i64().unwrap(),
    )
    .unwrap();
    // The type system, not the caller's diligence, is what keeps t=y out of
    // sworn=pass: there is no way to reach the Verified without matching.
    let verified = match &outcome {
        swornmail::Outcome::ObserveOnly(v) => v,
        swornmail::Outcome::Pass(_) => panic!("t=y policy reported as pass"),
    };
    assert_eq!(outcome.auth_result(), "none");
    assert!(verified.testing);
    assert_eq!(verified.rua.as_deref(), Some("mailto:a@b.example"));
}

/// A shared-hosting tenant enumerating its provider's aggregate gets the unit
/// it asked for as a *claim*, but reputation still keys on the single /64 the
/// connection actually corroborated.
#[test]
fn a_coarse_declared_unit_does_not_widen_the_observed_unit() {
    let json = vectors();
    let case = json["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "valid_in_prefix")
        .unwrap();
    let token = token_bytes(case, "valid_in_prefix");
    let source = case["source_ip"].as_str().unwrap().parse().unwrap();
    let now = case["now_unix"].as_i64().unwrap();
    let policy = PolicyRecord::parse("v=SWORN1; p=2001:db8:f00::/48; u=64").unwrap();

    let outcome = swornmail::verify(&token, &operator_key(&json), &policy, source, now).unwrap();
    let verified = outcome.verified();
    assert_eq!(
        verified.observed_unit.prefix_len(),
        swornmail::OBSERVED_UNIT_LEN,
        "observed unit must be the source /64 regardless of the declared unit"
    );
    assert_eq!(
        verified.observed_unit.to_string(),
        case["unit"].as_str().unwrap()
    );
}

/// The canonical vector file and the vendored snapshot must not drift apart.
#[test]
fn vendored_snapshot_matches_canonical_vectors() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let shared = manifest.join("../swornmail-spec/test-vectors/v1.json");
    if !shared.exists() {
        return;
    }
    let snapshot = manifest.join("tests/testdata/v1.json");
    assert_eq!(
        std::fs::read(&shared).expect("reading canonical vectors"),
        std::fs::read(&snapshot).expect("reading vendored vectors"),
        "tests/testdata/v1.json is stale; re-copy it from the spec repository"
    );
}

/// The key record published alongside the vectors must yield the same key as
/// the file's `ed25519_public_hex`.
#[test]
fn key_record_and_public_hex_agree() {
    let json = vectors();
    let record = KeyRecord::parse(json["key_record"].as_str().expect("key_record"))
        .expect("published key record parses");
    assert_eq!(
        record.public_key.to_bytes(),
        operator_key(&json).to_bytes(),
        "key record and ed25519_public_hex disagree"
    );
}

/// The authorization vectors: the Mode-2 contract the token vectors cannot
/// reach, because those verify a signature against a key with no policy in
/// sight. Expectations are authored from the draft, so this asserts conformance
/// rather than agreement with the Go reference's current behaviour.
#[test]
fn authorization_cases_match_vectors() {
    let json = vectors();
    let key = operator_key(&json);
    let cases = json["authorization"]
        .as_array()
        .expect("authorization section");
    assert!(!cases.is_empty(), "authorization vectors are missing");

    for case in cases {
        let name = case["name"].as_str().expect("name");
        let token = token_bytes(case, name);
        let source = case["source_ip"]
            .as_str()
            .expect("source_ip")
            .parse()
            .unwrap_or_else(|e| panic!("{name}: source_ip does not parse: {e}"));
        let now = case["now_unix"].as_i64().expect("now_unix");
        let policy = PolicyRecord::parse(case["policy_record"].as_str().expect("policy_record"))
            .unwrap_or_else(|e| panic!("{name}: policy record does not parse: {e:?}"));

        let outcome = swornmail::verify(&token, &key, &policy, source, now);
        let want_result = case["auth_result"].as_str().expect("auth_result");

        let verified = match &outcome {
            Ok(o) => {
                assert_eq!(o.auth_result(), want_result, "{name}: auth_result");
                // Pass vs ObserveOnly must follow the vector's testing flag,
                // never the caller's diligence.
                let testing = case["testing"].as_bool().unwrap_or(false);
                match o {
                    swornmail::Outcome::Pass(_) => {
                        assert!(!testing, "{name}: t=y reported as pass")
                    }
                    swornmail::Outcome::ObserveOnly(_) => {
                        assert!(testing, "{name}: committed policy reported as observe-only")
                    }
                }
                Some(o.verified())
            }
            Err(reason) => {
                let got = match reason {
                    Reason::BadSignature
                    | Reason::OffPrefix
                    | Reason::Expired
                    | Reason::NotYetValid => "fail",
                    _ => "permerror",
                };
                assert_eq!(got, want_result, "{name}: auth_result for {reason:?}");
                if let Some(expect) = case["expect"].as_str() {
                    assert_eq!(reason_str::<()>(&Err(*reason)), expect, "{name}: reason");
                }
                None
            }
        };

        if let Some(v) = verified {
            assert_eq!(
                v.operator,
                case["operator"].as_str().expect("operator"),
                "{name}: operator"
            );
            assert_eq!(
                v.unit.to_string(),
                case["unit"].as_str().expect("unit"),
                "{name}: unit"
            );
            assert_eq!(
                v.observed_unit.to_string(),
                case["observed_unit"].as_str().expect("observed_unit"),
                "{name}: observed unit"
            );
        }
    }
}
