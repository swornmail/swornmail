//! # SwornMail
//!
//! Reference constants and (eventually) verification primitives for the
//! **SwornMail protocol**: cryptographic IPv6 prefix attestation for email.
//!
//! SwornMail lets a sending operator attest, at SMTP time, that the
//! connecting IPv6 address belongs to a declared prefix under a single
//! accountable identity (a domain) — giving receivers a stable reputation
//! unit instead of an unusable 2^64 address space.
//!
//! ## Status
//!
//! Early development. The protocol draft is being prepared for IETF
//! submission. This crate currently pins the crate name and publishes the
//! protocol's wire-level constants; the verification API will follow the
//! draft. Watch <https://swornmail.dev> and
//! <https://github.com/swornmail/swornmail>.

/// Protocol version tag used in DNS records and tokens.
pub const SWORN_VERSION: &str = "SWORN1";

/// DNS label under which an operator publishes its SwornMail key/policy
/// record, e.g. `_sworn.mailer.example.com`.
pub const DNS_LABEL: &str = "_sworn";

/// Default reputation-unit prefix length receivers aggregate on within an
/// attested prefix (the IPv6 SLAAC boundary).
pub const DEFAULT_UNIT_PREFIX_LEN: u8 = 64;

/// Recommended (SHOULD, not MUST) upper bound in bytes for a Mode-2
/// connection token with classical (Ed25519) signatures. Post-quantum
/// algorithms will exceed this; the bound is advisory to keep tokens in a
/// single TCP segment where possible.
pub const RECOMMENDED_TOKEN_BYTES_CLASSICAL: usize = 512;

/// Maximum token lifetime in seconds (24 hours).
pub const MAX_TOKEN_LIFETIME_SECS: u64 = 86_400;
