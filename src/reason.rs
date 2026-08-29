//! Verification reason codes.
//!
//! The draft calls reason codes "advisory diagnostics": the order in which a
//! verifier discovers a fault is not normative, only the fault it lands on.

use core::fmt;

/// Reason string reported for a successful verification.
pub const PASS: &str = "pass";

/// Why a token failed verification.
///
/// Every variant maps to one of the reason tokens used in the shared test
/// vectors and in `Authentication-Results` diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
// Non-exhaustive: reason codes are an advisory diagnostic vocabulary that
// grows with the draft, so adding one must not break a downstream `match`.
#[non_exhaustive]
pub enum Reason {
    /// Source address is not inside the attested prefix.
    OffPrefix,
    /// Source address is not an ordinary global-unicast IPv6 address.
    IneligibleSource,
    /// Now is later than `exp` plus the skew tolerance.
    Expired,
    /// Now is earlier than `iat` minus the skew tolerance.
    NotYetValid,
    /// Signature does not verify under the operator key.
    BadSignature,
    /// `exp - iat` exceeds the 86400-second cap.
    LifetimeTooLong,
    /// `unit` is shorter than the prefix, longer than 64, or (for
    /// `esp-tenant`) not equal to the prefix length.
    BadUnit,
    /// Attested prefix is non-canonical or outside the permitted range.
    BadPrefix,
    /// `exp` is not greater than `iat`.
    BadValidity,
    /// The signed prefix is not covered by the operator policy enumeration.
    UnauthorizedPrefix,
    /// The token unit does not equal the separately published policy unit.
    PolicyUnitMismatch,
    /// Protected content type is absent or not `application/sworn-token+cbor`.
    BadContentType,
    /// Protected `kid` is absent or is not a conforming single DNS label.
    BadKid,
    /// Header buckets conflict: `crit` present, a protected label repeated in
    /// the unprotected bucket, an unprotected `alg`/`cty`/`kid`, or an `alg`
    /// that does not match the key.
    HeaderConfusion,
    /// `role` is absent from the registered set.
    BadRole,
    /// Structurally invalid: untagged COSE, bad CBOR, non-integer or duplicate
    /// payload key, missing REQUIRED key, or a non-conforming operator domain.
    Malformed,
}

impl Reason {
    /// The reason token used in test vectors and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Reason::OffPrefix => "off_prefix",
            Reason::IneligibleSource => "ineligible_source",
            Reason::Expired => "expired",
            Reason::NotYetValid => "not_yet_valid",
            Reason::BadSignature => "bad_signature",
            Reason::LifetimeTooLong => "lifetime_too_long",
            Reason::BadUnit => "bad_unit",
            Reason::BadPrefix => "bad_prefix",
            Reason::BadValidity => "bad_validity",
            Reason::UnauthorizedPrefix => "unauthorized_prefix",
            Reason::PolicyUnitMismatch => "policy_unit_mismatch",
            Reason::BadContentType => "bad_content_type",
            Reason::BadKid => "bad_kid",
            Reason::HeaderConfusion => "header_confusion",
            Reason::BadRole => "bad_role",
            Reason::Malformed => "malformed",
        }
    }

    /// The `Authentication-Results` result value this reason reports as.
    ///
    /// `fail` covers the four causes the draft lists as authentication
    /// failures; every other reason is a permanent error. Neither value may be
    /// treated as worse than `none` for reputation purposes.
    pub const fn auth_result(self) -> &'static str {
        match self {
            Reason::BadSignature | Reason::OffPrefix | Reason::Expired | Reason::NotYetValid => {
                "fail"
            }
            _ => "permerror",
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for Reason {}
