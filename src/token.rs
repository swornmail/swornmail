//! Mode-2 connection tokens: tagged `COSE_Sign1` over a CBOR payload.

use ciborium::value::Value;
use std::io::Cursor;
use std::net::Ipv6Addr;

use crate::address::{self, Ipv6Prefix};
use crate::key::Ed25519PublicKey;
use crate::payload::{Payload, Role};
use crate::reason::Reason;
use crate::record::PolicyRecord;

/// CBOR tag for `COSE_Sign1_Tagged`. Untagged objects are rejected.
pub const COSE_SIGN1_TAG: u64 = 18;

/// The fallback reputation boundary: the connecting source's `/64`.
///
/// Written as its own constant rather than derived from the declared unit on
/// purpose — a claimant-declared unit MUST NOT be able to widen it, so a
/// future change to the unit range cannot silently move this boundary.
pub const OBSERVED_UNIT_LEN: u8 = 64;
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
// Non-exhaustive: only this crate constructs a Verified, and policy metadata
// has grown once already. Downstream must not break when it grows again.
#[non_exhaustive]
pub struct Verified {
    /// The accountable operator domain.
    pub operator: String,
    /// The aggregation the operator ASKED for: the source address masked to
    /// the payload's unit length. It is a claim, not evidence — see
    /// [`Verified::observed_unit`].
    pub unit: Ipv6Prefix,
    /// The reputation key: the source address masked to
    /// [`OBSERVED_UNIT_LEN`]. Source membership proves that this connection
    /// came from inside `prefix`; it never proves exclusive control of it, so
    /// a claimant declaring a broad unit over shared space cannot widen where
    /// reputation attaches. Receivers key on (operator, observed_unit) unless
    /// they hold independent evidence of control over the whole prefix.
    pub observed_unit: Ipv6Prefix,
    /// The attested prefix the source was found in — the space the operator
    /// claims. Rolling abuse up to it needs independent control evidence.
    pub prefix: Ipv6Prefix,
    /// The `kid` header, i.e. the selector whose key record was used.
    pub selector: String,
    /// The operator's declared role.
    pub role: Role,
    /// Whether the authorizing policy is observe-only (`t=y`). A successful
    /// cryptographic result with this flag must be reported as `sworn=none`.
    pub testing: bool,
    /// Aggregate report destination from the authorizing policy.
    pub rua: Option<String>,
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
    observed_unit: Ipv6Prefix,
    to_be_signed: Vec<u8>,
    signature: Vec<u8>,
}

/// A locally valid token whose prefix and unit are authorized by the
/// separately published operator policy. Receivers reach this state before
/// fetching the key.
#[derive(Debug, Clone)]
pub struct Authorized {
    token: Unverified,
    testing: bool,
    rua: Option<String>,
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

    /// Applies the operator policy before any key lookup. The policy must
    /// cover the signed prefix and its `u=` value must equal the signed unit.
    pub fn authorize(self, policy: &PolicyRecord) -> Result<Authorized, Reason> {
        if !policy.authorizes(self.payload.prefix) {
            return Err(Reason::UnauthorizedPrefix);
        }
        if policy.unit != self.payload.unit {
            return Err(Reason::PolicyUnitMismatch);
        }
        Ok(Authorized {
            token: self,
            testing: policy.testing,
            rua: policy.rua.clone(),
        })
    }

    /// Low-level signature verification without policy authorization.
    ///
    /// This exists for frozen token-vector conformance. It is not a complete
    /// SwornMail verdict; production receivers must call [`Self::authorize`]
    /// first and then [`Authorized::verify_signature`].
    pub fn verify_signature_only(self, key: &Ed25519PublicKey) -> Result<Verified, Reason> {
        self.finish_signature(key, false, None)
    }

    fn finish_signature(
        self,
        key: &Ed25519PublicKey,
        testing: bool,
        rua: Option<String>,
    ) -> Result<Verified, Reason> {
        if !key.verify(&self.to_be_signed, &self.signature) {
            return Err(Reason::BadSignature);
        }
        Ok(Verified {
            operator: self.payload.operator,
            unit: self.unit,
            observed_unit: self.observed_unit,
            prefix: self.payload.prefix,
            selector: self.selector,
            role: self.payload.role,
            testing,
            rua,
        })
    }
}

/// The verdict of a complete, policy-aware verification.
///
/// A testing operator is a distinct variant rather than a flag on `Verified`
/// so that the unsafe reading is unrepresentable: a caller cannot obtain the
/// `Verified` without deciding which arm it is in, and `Pass` is only ever
/// produced by a policy that has accepted accountability. Reporting an
/// observe-only deployment as `sworn=pass` is exactly what `t=y` exists to
/// prevent, for credit and for blame alike.
// Deliberately NOT non_exhaustive: the two verdicts are total for a complete
// verification, and forcing a wildcard arm would let a future variant be
// silently swept into whichever branch a consumer wrote for `_` — the exact
// mistake exhaustive matching is here to prevent.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// Every check passed and the operator stakes reputation: `sworn=pass`.
    Pass(Verified),
    /// Every check passed but the policy carries `t=y`: report
    /// `sworn=none policy.testing=y policy.wouldbe=pass`, and stake nothing.
    ObserveOnly(Verified),
}

impl Outcome {
    /// The Authentication-Results result value for this verdict.
    pub fn auth_result(&self) -> &'static str {
        match self {
            Outcome::Pass(_) => "pass",
            Outcome::ObserveOnly(_) => "none",
        }
    }

    /// The verified token, whichever verdict was reached. Callers that reach
    /// for this on an `ObserveOnly` outcome are responsible for not staking
    /// reputation on it; use it for reporting only.
    pub fn verified(&self) -> &Verified {
        match self {
            Outcome::Pass(v) | Outcome::ObserveOnly(v) => v,
        }
    }
}

impl Authorized {
    /// Canonical lowercase operator domain whose key record is needed.
    pub fn operator(&self) -> &str {
        self.token.operator()
    }

    /// Canonical lowercase selector whose key record is needed.
    pub fn selector(&self) -> &str {
        self.token.selector()
    }

    /// Completes verification with the key fetched from
    /// `<selector>._sworn.<operator>`. Policy metadata is exposed only after
    /// the signature succeeds, so a failed token attributes nothing to the
    /// operator it names.
    pub fn verify_signature(self, key: &Ed25519PublicKey) -> Result<Outcome, Reason> {
        let testing = self.testing;
        let verified = self.token.finish_signature(key, testing, self.rua)?;
        Ok(if testing {
            Outcome::ObserveOnly(verified)
        } else {
            Outcome::Pass(verified)
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
    // From the source, never from the token: a claimant-declared unit MUST
    // NOT be able to widen the boundary reputation attaches to.
    let observed_unit =
        Ipv6Prefix::new(address::mask(source, OBSERVED_UNIT_LEN), OBSERVED_UNIT_LEN)
            .expect("64 is a valid prefix length");

    Ok(Unverified {
        payload,
        selector,
        unit,
        observed_unit,
        to_be_signed: cose.to_be_signed(),
        signature: cose.signature,
    })
}

/// Low-level token/signature verification without operator policy.
///
/// `key` is the operator key already fetched from
/// `<kid>._sworn.<operator domain>`; this function performs no I/O. `now` is
/// Unix seconds. This function exists for frozen token-vector conformance and
/// must not be reported as a complete SwornMail pass. Production receivers
/// use [`parse`], [`Unverified::authorize`], and
/// [`Authorized::verify_signature`] instead.
pub fn verify_signature_only(
    token: &[u8],
    key: &Ed25519PublicKey,
    source: Ipv6Addr,
    now: i64,
) -> Result<Verified, Reason> {
    parse(token, source, now)?.verify_signature_only(key)
}

/// Complete no-I/O verification when both parsed DNS records are already
/// available. Live-DNS receivers should use [`parse`],
/// [`Unverified::authorize`], then [`Authorized::verify_signature`] to ensure
/// the policy is checked before the key lookup.
pub fn verify(
    token: &[u8],
    key: &Ed25519PublicKey,
    policy: &PolicyRecord,
    source: Ipv6Addr,
    now: i64,
) -> Result<Outcome, Reason> {
    parse(token, source, now)?
        .authorize(policy)?
        .verify_signature(key)
}

/// Explicit alias for [`verify`].
pub fn verify_authorized(
    token: &[u8],
    key: &Ed25519PublicKey,
    policy: &PolicyRecord,
    source: Ipv6Addr,
    now: i64,
) -> Result<Outcome, Reason> {
    verify(token, key, policy, source, now)
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
    String::from_utf8(kid.to_vec())
        .ok()
        .map(|selector| selector.to_ascii_lowercase())
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
