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
//! This crate verifies Mode-2 connection tokens and parses operator records,
//! against the shared cross-implementation vectors in the specification
//! repository (`test-vectors/v1.json`). Signing is not implemented.
//!
//! **The `-01` wire format is frozen**: token octets, which records are
//! accepted, and the conformance vectors. This crate's own API is not, and
//! may still change between minor versions before `1.0`.
//!
//! ## Verifying a token
//!
//! The crate performs no I/O. The caller does the two TXT lookups and has a
//! DNS contract to honour, which the example spells out. The first rule
//! guards the resolver; the rest are the draft's record-selection rules.
//!
//! - Query absolute names, with the trailing dot. The names are built from
//!   the token, and a resolver search list must not get to rewrite them.
//! - Concatenate the character-strings of one TXT RR in order, with no
//!   separator, before parsing.
//! - Ignore TXT RRs that do not begin with `v=SWORN1`.
//! - If more than one TXT RR begins with `v=SWORN1`, the record set is in
//!   error: report `permerror` and pick none of them.
//! - A lookup that fails temporarily is `temperror`. It is never "no
//!   record", or anyone able to disrupt DNS could erase an attestation.
//!
//! ```no_run
//! use swornmail::{parse, reason_str, KeyRecord, Outcome, PolicyRecord, RecordError};
//!
//! /// One TXT RRset: an entry per RR, holding that RR's character-strings.
//! type TxtRrset = Vec<Vec<String>>;
//!
//! # fn lookup_txt(_absolute_qname: &str) -> Result<TxtRrset, Box<dyn std::error::Error>> {
//! #     Ok(Vec::new())
//! # }
//! /// Picks the SwornMail record out of an RRset. `Ok(None)` is "no record"
//! /// (`sworn=none`); `Err` is a record set in error (`sworn=permerror`).
//! fn sworn_record(rrset: &TxtRrset) -> Result<Option<String>, &'static str> {
//!     let mut found = None;
//!     for rr in rrset {
//!         let txt = rr.concat();
//!         if !txt.starts_with("v=SWORN1") {
//!             continue;
//!         }
//!         if found.is_some() {
//!             return Err("more than one v=SWORN1 record");
//!         }
//!         found = Some(txt);
//!     }
//!     Ok(found)
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let token: Vec<u8> = Vec::new();
//! // Local checks first: a token that fails here costs no DNS query.
//! let pending = parse(&token, "2001:db8:f00::1".parse()?, 1786293000)?;
//!
//! // `lookup_txt` is the caller's resolver. An error from it is a temporary
//! // failure (`sworn=temperror`), kept apart from an empty answer.
//! let policy_qname = format!("_prefixes._sworn.{}.", pending.operator());
//! let Some(txt) = sworn_record(&lookup_txt(&policy_qname)?)? else {
//!     println!("sworn=none");
//!     return Ok(());
//! };
//! let policy = PolicyRecord::parse(&txt)?; // an Err here is permerror
//! let authorized = pending.authorize(&policy)?; // before the key query
//!
//! let key_qname = format!("{}._sworn.{}.", authorized.selector(), authorized.operator());
//! let Some(txt) = sworn_record(&lookup_txt(&key_qname)?)? else {
//!     println!("sworn=none");
//!     return Ok(());
//! };
//! let record = match KeyRecord::parse(&txt) {
//!     Ok(record) => record,
//!     // An algorithm this verifier predates is no attestation, not an error.
//!     Err(RecordError::UnknownAlgorithm) => {
//!         println!("sworn=none");
//!         return Ok(());
//!     }
//!     Err(error) => return Err(error.into()), // permerror
//! };
//! match authorized.verify_signature(&record.public_key) {
//!     // Key reputation on `observed_unit`, not `unit`: `unit` is what the
//!     // operator asked for, `observed_unit` is what this connection proved.
//!     Ok(Outcome::Pass(v)) => println!("sworn=pass unit={}", v.observed_unit),
//!     // t=y: report the would-be result and stake nothing.
//!     Ok(Outcome::ObserveOnly(_)) => println!("sworn=none policy.testing=y policy.wouldbe=pass"),
//!     Err(reason) => println!("sworn-reason={}", reason_str::<()>(&Err(reason))),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! A failed verification identifies no accountable party. Receivers must not
//! treat any failure as worse than no attestation at all, and must not charge
//! it against the operator domain named in the token.
//!
//! A verified token also carries the policy's `rua`, where the operator asks
//! for aggregate reports to be sent. That is a request, not permission to
//! send: see [`PolicyRecord::rua`] for the consent check the draft requires
//! when the mailbox lies outside the operator domain.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod address;
mod encoded;
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
pub use token::{
    parse, parse_excluding, reason_str, verify, verify_authorized, verify_signature_only,
    Authorized, Outcome, Unverified, Verified, MAX_TOKEN_LEN, OBSERVED_UNIT_LEN,
};

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
