//! # SwornMail
//!
//! An independent implementation of **SwornMail**: cryptographic IPv6 prefix
//! attestation for email, per `draft-kafedzhy-swornmail-01`.
//!
//! SwornMail lets a sending operator attest, at SMTP time, that the connecting
//! IPv6 address belongs to a declared prefix under a single accountable
//! identity (a domain) — giving receivers a stable reputation unit instead of
//! an unusable 2^64 address space.
//!
//! ## Status
//!
//! `0.1` verifies Mode-2 connection tokens and parses operator records,
//! against the shared cross-implementation vectors in the specification
//! repository (`test-vectors/v1.json`). Signing is not implemented.
//!
//! **The protocol wire format is not yet frozen** — expect breaking changes
//! before v1.
//!
//! ## Verifying a token
//!
//! ```no_run
//! use swornmail::{parse, reason_str, KeyRecord};
//!
//! # fn lookup_txt(_qname: &str) -> String { String::new() }
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let token: Vec<u8> = Vec::new();
//! // Local checks first: a token that fails here costs no DNS query.
//! let pending = parse(&token, "2001:db8:f00::1".parse()?, 1786293000)?;
//! let qname = format!("{}._sworn.{}", pending.selector(), pending.operator());
//! let record = KeyRecord::parse(&lookup_txt(&qname))?;
//! let outcome = pending.verify_signature(&record.public_key);
//! println!("sworn={}", reason_str(&outcome));
//! # Ok(())
//! # }
//! ```
//!
//! A failed verification identifies no accountable party. Receivers must not
//! treat any failure as worse than no attestation at all, and must not charge
//! it against the operator domain named in the token.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod address;
pub mod key;
pub mod payload;
pub mod reason;
pub mod record;
pub mod token;

pub use address::Ipv6Prefix;
pub use key::Ed25519PublicKey;
pub use payload::{Payload, Role};
pub use reason::Reason;
pub use record::{KeyRecord, PolicyRecord, RecordError};
pub use token::{parse, reason_str, verify, Unverified, Verified};

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
