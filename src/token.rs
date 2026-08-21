//! Mode-2 connection tokens: tagged `COSE_Sign1` over a CBOR payload.

use ciborium::value::Value;
use std::io::Cursor;
use std::net::Ipv6Addr;

use crate::address::{self, Ipv6Prefix};
use crate::key::Ed25519PublicKey;
use crate::payload::{Payload, Role};
use crate::reason::Reason;

/// CBOR tag for `COSE_Sign1_Tagged`. Untagged objects are rejected.
pub const COSE_SIGN1_TAG: u64 = 18;
/// COSE algorithm identifier for EdDSA.
pub const ALG_EDDSA: i128 = -8;
/// The content type that domain-separates SwornMail signatures.
pub const CONTENT_TYPE: &str = "application/sworn-token+cbor";
/// Fixed clock-skew tolerance, in seconds, applied at both window edges.
pub const SKEW_SECS: i128 = 300;

const LABEL_ALG: i128 = 1;
const LABEL_CRIT: i128 = 2;
const LABEL_CONTENT_TYPE: i128 = 3;
const LABEL_KID: i128 = 4;

/// A COSE header label: an integer, or a text string.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Label {
    Int(i128),
    Text(String),
}

/// One header bucket, keeping entries in wire order so duplicates are visible.
struct Headers(Vec<(Label, Value)>);

impl Headers {
    /// Reads a header map, rejecting a repeated label within the bucket.
    fn from_value(value: &Value) -> Result<Headers, Reason> {
        let entries = match value {
            Value::Map(entries) => entries,
            _ => return Err(Reason::Malformed),
        };
        let mut out: Vec<(Label, Value)> = Vec::with_capacity(entries.len());
        for (key, val) in entries {
            let label = match key {
                Value::Integer(i) => Label::Int(i128::from(*i)),
                Value::Text(s) => Label::Text(s.clone()),
                _ => return Err(Reason::Malformed),
            };
            if out.iter().any(|(seen, _)| seen == &label) {
                return Err(Reason::Malformed);
            }
            out.push((label, val.clone()));
        }
        Ok(Headers(out))
    }

    fn get(&self, label: i128) -> Option<&Value> {
        self.0
            .iter()
            .find(|(l, _)| l == &Label::Int(label))
            .map(|(_, v)| v)
    }

    fn has(&self, label: i128) -> bool {
        self.get(label).is_some()
    }

    fn labels(&self) -> impl Iterator<Item = &Label> {
        self.0.iter().map(|(l, _)| l)
    }
}

/// The outcome of a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The accountable operator domain.
    pub operator: String,
    /// The reputation key: the source address masked to the payload's unit
    /// length. Receivers key reputation on (operator, unit).
    pub unit: Ipv6Prefix,
    /// The attested prefix the source was found in.
    pub prefix: Ipv6Prefix,
    /// The `kid` header, i.e. the selector whose key record was used.
    pub selector: String,
    /// The operator's declared role.
    pub role: Role,
}

/// A token that has passed every check except the signature.
///
/// This is the state a receiver is in between reading the token and having the
/// operator key: the key record lives at `<kid>._sworn.<operator domain>`, both
/// of which are read from the token itself.
#[derive(Debug, Clone)]
pub struct Unverified {
    payload: Payload,
    selector: String,
    unit: Ipv6Prefix,
    to_be_signed: Vec<u8>,
    signature: Vec<u8>,
}

impl Unverified {
    /// The operator domain claimed by the token, already checked for
    /// conforming syntax.
    pub fn operator(&self) -> &str {
        &self.payload.operator
    }

    /// The selector claimed by the token, already checked for conforming
    /// syntax. Selector comparison is case-insensitive ASCII.
    pub fn selector(&self) -> &str {
        &self.selector
    }

    /// The claim as parsed. It means nothing until the signature verifies.
    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    /// Verifies the signature with the key fetched for
    /// [`selector`](Self::selector) and [`operator`](Self::operator).
    pub fn verify_signature(self, key: &Ed25519PublicKey) -> Result<Verified, Reason> {
        if !key.verify(&self.to_be_signed, &self.signature) {
            return Err(Reason::BadSignature);
        }
        Ok(Verified {
            operator: self.payload.operator,
            unit: self.unit,
            prefix: self.payload.prefix,
            selector: self.selector,
            role: self.payload.role,
        })
    }
}

/// Runs every check that does not need the operator key: token structure,
/// headers, payload, source eligibility, validity window, and membership.
///
/// Splitting the key fetch out is what lets a receiver honour the draft's rule
/// that a token failing a local check must be reported without any DNS query,
/// so garbage tokens cannot turn a verifier into an attacker-directed query
/// generator. `now` is Unix seconds.
pub fn parse(token: &[u8], source: Ipv6Addr, now: i64) -> Result<Unverified, Reason> {
    let cose = CoseSign1::parse(token)?;
    let selector = cose.check_headers()?;

    let payload_value: Value = decode_cbor(&cose.payload)?;
    let payload = Payload::from_value(&payload_value)?;

    if !address::is_eligible_source(source) {
        return Err(Reason::IneligibleSource);
    }

    let now = i128::from(now);
    if now < i128::from(payload.iat) - SKEW_SECS {
        return Err(Reason::NotYetValid);
    }
    if now > i128::from(payload.exp) + SKEW_SECS {
        return Err(Reason::Expired);
    }

    if !payload.prefix.contains(source) {
        return Err(Reason::OffPrefix);
    }

    let unit = Ipv6Prefix::new(address::mask(source, payload.unit), payload.unit)
        .expect("unit is at most 64");

    Ok(Unverified {
        payload,
        selector,
        unit,
        to_be_signed: cose.to_be_signed(),
        signature: cose.signature,
    })
}

/// Verifies a Mode-2 token against a source address and the current time.
///
/// `key` is the operator key already fetched from
/// `<kid>._sworn.<operator domain>`; this function performs no I/O. `now` is
/// Unix seconds. Receivers that fetch the key per connection should call
/// [`parse`] and [`Unverified::verify_signature`] instead, which is the same
/// sequence with the fetch in the middle.
pub fn verify(
    token: &[u8],
    key: &Ed25519PublicKey,
    source: Ipv6Addr,
    now: i64,
) -> Result<Verified, Reason> {
    parse(token, source, now)?.verify_signature(key)
}

/// Reason string for a verification outcome, using the draft's advisory
/// reason-code vocabulary.
pub fn reason_str<T>(outcome: &Result<T, Reason>) -> &'static str {
    match outcome {
        Ok(_) => crate::reason::PASS,
        Err(reason) => reason.as_str(),
    }
}

/// A parsed `COSE_Sign1`, keeping the protected bucket's original octets
/// because the signature is computed over them, not over a re-encoding.
struct CoseSign1 {
    protected_raw: Vec<u8>,
    protected: Headers,
    unprotected: Headers,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl CoseSign1 {
    fn parse(token: &[u8]) -> Result<CoseSign1, Reason> {
        let mut cursor = Cursor::new(token);
        let value: Value = ciborium::de::from_reader(&mut cursor).map_err(|_| Reason::Malformed)?;
        if cursor.position() != token.len() as u64 {
            return Err(Reason::Malformed);
        }

        let body = match value {
            Value::Tag(COSE_SIGN1_TAG, body) => *body,
            _ => return Err(Reason::Malformed),
        };
        let mut items = match body {
            Value::Array(items) if items.len() == 4 => items.into_iter(),
            _ => return Err(Reason::Malformed),
        };

        let protected_raw = take_bytes(items.next())?;
        let unprotected = Headers::from_value(&items.next().ok_or(Reason::Malformed)?)?;
        let payload = take_bytes(items.next())?;
        let signature = take_bytes(items.next())?;

        // A zero-length protected bucket encodes an empty map, per COSE.
        let protected = if protected_raw.is_empty() {
            Headers(Vec::new())
        } else {
            Headers::from_value(&decode_cbor(&protected_raw)?)?
        };

        Ok(CoseSign1 {
            protected_raw,
            protected,
            unprotected,
            payload,
            signature,
        })
    }

    /// Enforces the draft's header rules and returns the selector.
    ///
    /// Bucket confusion is checked first: when a label appears in the wrong
    /// place, the honest report is that the buckets conflict, not that the
    /// protected value it displaced is missing.
    fn check_headers(&self) -> Result<String, Reason> {
        if self.protected.has(LABEL_CRIT) || self.unprotected.has(LABEL_CRIT) {
            return Err(Reason::HeaderConfusion);
        }
        if [LABEL_ALG, LABEL_CONTENT_TYPE, LABEL_KID]
            .iter()
            .any(|&label| self.unprotected.has(label))
        {
            return Err(Reason::HeaderConfusion);
        }
        if self
            .unprotected
            .labels()
            .any(|label| self.protected.labels().any(|other| other == label))
        {
            return Err(Reason::HeaderConfusion);
        }

        // The algorithm comes from the key record, never from the token; the
        // header must merely agree with it. Only Ed25519 is implemented.
        match self.protected.get(LABEL_ALG) {
            Some(Value::Integer(alg)) if i128::from(*alg) == ALG_EDDSA => {}
            _ => return Err(Reason::HeaderConfusion),
        }

        match self.protected.get(LABEL_CONTENT_TYPE) {
            Some(Value::Text(cty)) if cty == CONTENT_TYPE => {}
            _ => return Err(Reason::BadContentType),
        }

        match self.protected.get(LABEL_KID) {
            Some(Value::Bytes(kid)) => selector_from_kid(kid).ok_or(Reason::BadKid),
            _ => Err(Reason::BadKid),
        }
    }

    /// The `Sig_structure` octets: `["Signature1", protected, external_aad,
    /// payload]` with a zero-length `external_aad`.
    fn to_be_signed(&self) -> Vec<u8> {
        let sig_structure = Value::Array(vec![
            Value::Text("Signature1".to_owned()),
            Value::Bytes(self.protected_raw.clone()),
            Value::Bytes(Vec::new()),
            Value::Bytes(self.payload.clone()),
        ]);
        let mut out = Vec::with_capacity(self.protected_raw.len() + self.payload.len() + 16);
        ciborium::ser::into_writer(&sig_structure, &mut out).expect("writing to a Vec");
        out
    }
}

fn decode_cbor(bytes: &[u8]) -> Result<Value, Reason> {
    let mut cursor = Cursor::new(bytes);
    let value: Value = ciborium::de::from_reader(&mut cursor).map_err(|_| Reason::Malformed)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(Reason::Malformed);
    }
    Ok(value)
}

fn take_bytes(value: Option<Value>) -> Result<Vec<u8>, Reason> {
    match value {
        Some(Value::Bytes(b)) => Ok(b),
        _ => Err(Reason::Malformed),
    }
}

/// Reads a `kid` as a selector: a single DNS label of 1–63 LDH octets that
/// neither begins nor ends with a hyphen.
fn selector_from_kid(kid: &[u8]) -> Option<String> {
    if kid.is_empty() || kid.len() > 63 {
        return None;
    }
    if kid[0] == b'-' || kid[kid.len() - 1] == b'-' {
        return None;
    }
    if !kid.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-') {
        return None;
    }
    String::from_utf8(kid.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_conforming_selectors() {
        assert_eq!(selector_from_kid(b"2026a").as_deref(), Some("2026a"));
        assert_eq!(selector_from_kid(b"a-b").as_deref(), Some("a-b"));
        assert_eq!(selector_from_kid(&[b'a'; 63]).map(|s| s.len()), Some(63));
    }

    #[test]
    fn rejects_non_label_selectors() {
        assert!(selector_from_kid(b"").is_none());
        assert!(selector_from_kid(&[b'a'; 64]).is_none());
        assert!(selector_from_kid(b"-lead").is_none());
        assert!(selector_from_kid(b"trail-").is_none());
        assert!(selector_from_kid(b"two.labels").is_none());
        assert!(selector_from_kid(b"under_score").is_none());
        assert!(selector_from_kid("sel\u{e9}".as_bytes()).is_none());
    }
}
