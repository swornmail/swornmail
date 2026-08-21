//! The signed claim carried inside a Mode-2 token.
//!
//! Parsing is deliberately strict: the payload is a CBOR map with integer keys
//! only, no duplicates, and every REQUIRED key present. A lenient parser that
//! took the last of two duplicate keys would let a signer smuggle a second
//! attested prefix past a verifier that read the first.

use ciborium::value::Value;
use std::net::Ipv6Addr;

use crate::address::Ipv6Prefix;
use crate::reason::Reason;

/// Maximum token lifetime, `exp - iat`, in seconds.
pub const MAX_LIFETIME_SECS: u64 = 86_400;
/// Reputation unit assumed when the payload omits key 3.
pub const DEFAULT_UNIT: u8 = 64;

const KEY_OPERATOR: i128 = 1;
const KEY_PREFIX: i128 = 2;
const KEY_UNIT: i128 = 3;
const KEY_IAT: i128 = 4;
const KEY_EXP: i128 = 5;
const KEY_ROLE: i128 = 6;

/// The operator's self-asserted relationship to the attested prefix.
///
/// `role` carries no cryptographic weight; it exists so that receivers can see
/// what kind of sender claims the prefix, and so that `esp-tenant` can be held
/// to the stricter unit rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// An MTA speaking for its own prefix.
    Mta,
    /// A tenant of a shared ESP prefix; `unit` must equal the prefix length.
    EspTenant,
    /// A forwarder attesting its own prefix for this hop only.
    Forwarder,
}

impl Role {
    /// The wire value of this role.
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Mta => "mta",
            Role::EspTenant => "esp-tenant",
            Role::Forwarder => "forwarder",
        }
    }

    fn parse(s: &str) -> Option<Role> {
        match s {
            "mta" => Some(Role::Mta),
            "esp-tenant" => Some(Role::EspTenant),
            "forwarder" => Some(Role::Forwarder),
            _ => None,
        }
    }
}

/// A validated token payload.
///
/// Every field has already passed the checks the draft calls payload-intrinsic:
/// prefix canonicality and range, validity bounds, unit bounds, and role. The
/// checks that depend on the connection — source eligibility, the validity
/// window, membership, and the signature — belong to
/// [`verify`](crate::verify).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    /// Operator domain, in A-label form.
    pub operator: String,
    /// The attested prefix, canonical and within the permitted range.
    pub prefix: Ipv6Prefix,
    /// Reputation unit length, with the default already applied.
    pub unit: u8,
    /// Issuance time, Unix seconds.
    pub iat: u64,
    /// Expiry, Unix seconds.
    pub exp: u64,
    /// The operator's declared role.
    pub role: Role,
}

impl Payload {
    /// Parses and validates a payload from its decoded CBOR value.
    ///
    /// The draft requires signers to use deterministic encoding but states no
    /// verifier duty to reject a payload that is not, unlike prefix
    /// canonicality where it says so outright. Nothing here therefore rejects
    /// unsorted map keys, indefinite-length maps, or non-minimal integer
    /// encodings; the signature still binds the exact octets. A verifier that
    /// enforced determinism would refuse tokens this one accepts.
    pub fn from_value(value: &Value) -> Result<Payload, Reason> {
        let entries = match value {
            Value::Map(entries) => entries,
            _ => return Err(Reason::Malformed),
        };

        let mut operator = None;
        let mut prefix_bytes = None;
        let mut unit = None;
        let mut iat = None;
        let mut exp = None;
        let mut role_text = None;
        let mut seen: Vec<i128> = Vec::with_capacity(entries.len());

        for (key, val) in entries {
            // Non-integer keys are fatal even though unknown integer keys are
            // ignored: the CDDL admits `* int => any` and nothing else.
            let key = match key {
                Value::Integer(i) => i128::from(*i),
                _ => return Err(Reason::Malformed),
            };
            if seen.contains(&key) {
                return Err(Reason::Malformed);
            }
            seen.push(key);

            match key {
                KEY_OPERATOR => operator = Some(text(val)?),
                KEY_PREFIX => prefix_bytes = Some(bytes(val)?),
                KEY_UNIT => unit = Some(uint(val)?),
                KEY_IAT => iat = Some(uint(val)?),
                KEY_EXP => exp = Some(uint(val)?),
                KEY_ROLE => role_text = Some(text(val)?),
                _ => {}
            }
        }

        let (operator, prefix_bytes, iat, exp, role_text) =
            match (operator, prefix_bytes, iat, exp, role_text) {
                (Some(o), Some(p), Some(i), Some(e), Some(r)) => (o, p, i, e, r),
                _ => return Err(Reason::Malformed),
            };

        if !is_operator_domain(operator) {
            return Err(Reason::Malformed);
        }
        let role = Role::parse(role_text).ok_or(Reason::BadRole)?;
        let prefix = decode_prefix(prefix_bytes)?;
        if !prefix.is_attestable() {
            return Err(Reason::BadPrefix);
        }

        // Validity bounds are evaluated on the raw values, before any skew.
        if exp <= iat {
            return Err(Reason::BadValidity);
        }
        if exp - iat > MAX_LIFETIME_SECS {
            return Err(Reason::LifetimeTooLong);
        }

        let unit = unit.unwrap_or(u64::from(DEFAULT_UNIT));
        if unit > u64::from(crate::address::MAX_PREFIX_LEN) || unit < u64::from(prefix.prefix_len())
        {
            return Err(Reason::BadUnit);
        }
        let unit = unit as u8;
        // A shared ESP prefix cannot be split into finer reputation units, or
        // one tenant's abuse would land on a unit no one is accountable for.
        if role == Role::EspTenant && unit != prefix.prefix_len() {
            return Err(Reason::BadUnit);
        }

        Ok(Payload {
            operator: operator.to_owned(),
            prefix,
            unit,
            iat,
            exp,
            role,
        })
    }
}

fn text(value: &Value) -> Result<&str, Reason> {
    match value {
        Value::Text(s) => Ok(s),
        _ => Err(Reason::Malformed),
    }
}

fn bytes(value: &Value) -> Result<&[u8], Reason> {
    match value {
        Value::Bytes(b) => Ok(b),
        _ => Err(Reason::Malformed),
    }
}

/// Reads a CBOR unsigned integer. Negative values are malformed rather than
/// out-of-range: the CDDL types these fields `uint`.
fn uint(value: &Value) -> Result<u64, Reason> {
    match value {
        Value::Integer(i) => u64::try_from(i128::from(*i)).map_err(|_| Reason::Malformed),
        _ => Err(Reason::Malformed),
    }
}

/// Decodes the 17-octet prefix wire form: 16 address octets, then the length.
fn decode_prefix(b: &[u8]) -> Result<Ipv6Prefix, Reason> {
    let raw: [u8; 17] = b.try_into().map_err(|_| Reason::Malformed)?;
    let addr: [u8; 16] = raw[..16].try_into().expect("16 of 17 octets");
    Ipv6Prefix::new(Ipv6Addr::from(addr), raw[16]).ok_or(Reason::BadPrefix)
}

/// Whether `s` is a usable operator domain: ASCII A-label form, at most 253
/// octets, each label 1–63 LDH octets not starting or ending with a hyphen.
///
/// This runs before any DNS query is built from the value, which is what keeps
/// a token from steering a verifier at an attacker-chosen name — or, with the
/// CRLF that the vectors exercise, at an injected SMTP command.
fn is_operator_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 || !s.is_ascii() {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_operator_domains() {
        assert!(is_operator_domain("mailer.example.com"));
        assert!(is_operator_domain("xn--80ak6aa92e.example"));
        assert!(is_operator_domain("a"));
    }

    #[test]
    fn rejects_injection_and_malformed_domains() {
        for s in [
            "",
            "x.example.com\r\nQUIT",
            "evil.example.com..",
            ".example.com",
            // A trailing root dot is rejected: the draft asks for A-label form,
            // and the verifier appends its own labels to build the QNAME.
            "example.com.",
            "*.example.com",
            "-bad.example.com",
            "bad-.example.com",
            "exa mple.com",
            "exämple.com",
            "under_score.example.com",
            "x.example.com\0",
        ] {
            assert!(!is_operator_domain(s), "{s:?} must be rejected");
        }
    }

    #[test]
    fn rejects_oversized_domain() {
        let long_label = "a".repeat(64);
        assert!(!is_operator_domain(&format!("{long_label}.example.com")));
        let long_domain = vec!["a".repeat(60); 5].join(".");
        assert!(long_domain.len() > 253);
        assert!(!is_operator_domain(&long_domain));
    }
}
