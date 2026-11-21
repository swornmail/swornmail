//! Operator DNS records: one key record per selector, one policy record per
//! operator.

use base64::Engine as _;
use core::fmt;
use std::collections::HashSet;

use crate::address::Ipv6Prefix;
use crate::key::Ed25519PublicKey;

/// Version tag value every SwornMail record must carry first.
pub const VERSION: &str = "SWORN1";
/// Length of a `pk=` value for `k=ed25519`: 32 octets in padded base64.
const ED25519_PK_ENCODED_LEN: usize = 44;
/// Largest number of prefixes a policy record may enumerate; the rest are
/// ignored rather than treated as an error.
pub const MAX_POLICY_PREFIXES: usize = 64;

/// Why a record could not be used.
///
/// Callers report an unusable record as `permerror`, with one exception:
/// [`RecordError::UnknownAlgorithm`] must be reported as `sworn=none`, so that
/// publishing a future-algorithm selector alongside a current one never
/// penalizes an operator running against older verifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// The record does not begin with `v=SWORN1`.
    NotSworn,
    /// A tag is not in `name=value` form, or its value contains whitespace.
    MalformedTag,
    /// The same tag name appears more than once.
    DuplicateTag,
    /// A REQUIRED tag is absent.
    MissingTag(&'static str),
    /// A tag's value is outside its defined syntax or range.
    BadValue(&'static str),
    /// The `k=` algorithm is not implemented here.
    UnknownAlgorithm,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordError::NotSworn => f.write_str("record does not begin with v=SWORN1"),
            RecordError::MalformedTag => f.write_str("malformed tag"),
            RecordError::DuplicateTag => f.write_str("duplicate tag"),
            RecordError::MissingTag(tag) => write!(f, "missing required tag {tag}="),
            RecordError::BadValue(tag) => write!(f, "invalid value for tag {tag}="),
            RecordError::UnknownAlgorithm => f.write_str("unimplemented k= algorithm"),
        }
    }
}

impl std::error::Error for RecordError {}

/// A `<selector>._sworn.<domain>` key record.
#[derive(Debug, Clone)]
pub struct KeyRecord {
    /// The operator's signing key. Only `k=ed25519` is implemented.
    pub public_key: Ed25519PublicKey,
}

impl KeyRecord {
    /// Parses one key record's TXT content.
    ///
    /// The selector lives in the QNAME, so there is no `s=` tag; a legacy `s=`
    /// is ignored like any other unknown tag.
    pub fn parse(txt: &str) -> Result<KeyRecord, RecordError> {
        let tags = parse_tags(txt)?;
        let algorithm = get(&tags, "k").ok_or(RecordError::MissingTag("k"))?;
        if algorithm != "ed25519" {
            return Err(RecordError::UnknownAlgorithm);
        }
        let encoded = get(&tags, "pk").ok_or(RecordError::MissingTag("pk"))?;
        // The record is untrusted DNS text, so the length is checked before
        // any decoding work is spent on it. This refuses nothing the decoder
        // and the key-length check below would not: the decoder requires
        // canonical padding and admits no whitespace, so 32 octets have
        // exactly one accepted spelling and it is 44 characters long.
        if encoded.len() != ED25519_PK_ENCODED_LEN {
            return Err(RecordError::BadValue("pk"));
        }
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| RecordError::BadValue("pk"))?;
        let public_key = Ed25519PublicKey::from_bytes(&raw).ok_or(RecordError::BadValue("pk"))?;
        Ok(KeyRecord { public_key })
    }
}

/// A `_prefixes._sworn.<domain>` policy record.
#[derive(Debug, Clone)]
pub struct PolicyRecord {
    /// Enumerated attested prefixes, at most [`MAX_POLICY_PREFIXES`].
    pub prefixes: Vec<Ipv6Prefix>,
    /// Requested reputation unit; 64 when `u=` is absent.
    pub unit: u8,
    /// Whether `t=` carries the `y` (testing) flag.
    pub testing: bool,
    /// Aggregate report destination, `mailto:` only.
    ///
    /// This is where the operator asks for reports to go; it is the
    /// operator's request and nothing more. The value is syntax-checked
    /// here, never checked for consent. When the mailbox domain is neither
    /// the operator domain nor a subdomain of it, the draft requires the
    /// receiver to confirm consent before sending anything: query
    /// `<operator-domain>._report._sworn.<rua-domain>` for a TXT record
    /// beginning with `v=SWORN1`, and send nothing if it is absent or if
    /// that name is longer than DNS allows (253 octets). Without that
    /// check a policy record can aim a receiver's reports at a mailbox of
    /// the publisher's choosing.
    pub rua: Option<String>,
}

impl PolicyRecord {
    /// Parses one policy record's TXT content.
    pub fn parse(txt: &str) -> Result<PolicyRecord, RecordError> {
        let tags = parse_tags(txt)?;

        let mut prefixes = Vec::new();
        if let Some(list) = get(&tags, "p") {
            // Prefixes past the 64th are ignored, not validated: the draft
            // caps the work a verifier does on an oversized record.
            // Empty elements are skipped, not rejected, and do not count
            // against the cap — matching the Go reference and the Lua module.
            // A trailing comma is sloppy, not hostile, and three parsers
            // disagreeing about it is now an authorization difference rather
            // than a lint difference.
            for entry in list
                .split(',')
                .filter(|entry| !entry.is_empty())
                .take(MAX_POLICY_PREFIXES)
            {
                let prefix: Ipv6Prefix = entry.parse().map_err(|_| RecordError::BadValue("p"))?;
                if !prefix.is_attestable() {
                    return Err(RecordError::BadValue("p"));
                }
                prefixes.push(prefix);
            }
        }

        let unit = match get(&tags, "u") {
            Some(value) => {
                let unit =
                    crate::address::parse_decimal(value).ok_or(RecordError::BadValue("u"))?;
                if !(1..=crate::address::MAX_PREFIX_LEN).contains(&unit) {
                    return Err(RecordError::BadValue("u"));
                }
                unit
            }
            None => crate::payload::DEFAULT_UNIT,
        };

        // Unknown t= flags are ignored by design, so a future flag never
        // invalidates a record for a verifier that predates it.
        let testing = get(&tags, "t").is_some_and(|flags| flags.split(':').any(|flag| flag == "y"));

        let rua = match get(&tags, "rua") {
            Some(value) => {
                if !valid_rua(value) {
                    return Err(RecordError::BadValue("rua"));
                }
                Some(value.to_owned())
            }
            None => None,
        };

        if prefixes.iter().any(|prefix| unit < prefix.prefix_len()) {
            return Err(RecordError::BadValue("u"));
        }

        Ok(PolicyRecord {
            prefixes,
            unit,
            testing,
            rua,
        })
    }

    /// Whether this policy explicitly authorizes a signed token prefix.
    /// A broader policy prefix may authorize a more specific token prefix,
    /// but a narrow enumeration never authorizes its parent.
    pub fn authorizes(&self, token_prefix: Ipv6Prefix) -> bool {
        token_prefix.is_attestable()
            && self.prefixes.iter().any(|allowed| {
                allowed.is_attestable()
                    && token_prefix.prefix_len() >= allowed.prefix_len()
                    && allowed.contains(token_prefix.addr())
            })
    }
}

/// Splits a record into `(name, value)` tags, enforcing the shared rules:
/// `v=SWORN1` first, no repeated tag name, no whitespace inside a value.
fn parse_tags(txt: &str) -> Result<Vec<(&str, &str)>, RecordError> {
    // A SwornMail record is printable ASCII by construction: domains are LDH,
    // prefixes and units are digits and punctuation, rua is a dot-atom. So the
    // rule is the simplest one three implementations can agree on exactly —
    // reject every byte outside 0x20..=0x7E, plus HTAB.
    //
    // "Whitespace" is where parsers silently disagree: Go's unicode.IsSpace
    // covers U+00A0 and U+3000, Lua's %s is byte-wise, and this crate's
    // is_ascii_whitespace excludes VT. The same record then parses differently
    // in three places. Restricting the record to an explicit octet set removes
    // the disagreement at its source, and takes CR, LF, NUL, DEL and every
    // other C0 control with it.
    //
    // HTAB is admitted because a hand-edited zone file legitimately contains
    // one between tags, and all three implementations already strip it there
    // and reject it inside a value.
    if txt
        .bytes()
        .any(|byte| byte != b'\t' && !(0x20..=0x7e).contains(&byte))
    {
        return Err(RecordError::MalformedTag);
    }
    let mut tags: Vec<(&str, &str)> = Vec::new();
    // Names seen so far, in a set rather than found by rescanning `tags`: the
    // record is untrusted, and comparing every tag with every earlier one is
    // quadratic work in the number of tags a publisher chooses to send.
    let mut seen: HashSet<&str> = HashSet::new();
    for segment in txt.split(';') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let (name, value) = segment.split_once('=').ok_or(RecordError::MalformedTag)?;
        let (name, value) = (name.trim(), value.trim());
        // The segment is already trimmed, so any whitespace left is internal.
        // Only SP and HTAB survive the octet gate above, and those are
        // exactly what "whitespace" means here — is_ascii_whitespace
        // would be wrong twice over, admitting FF and excluding VT.
        if name.is_empty() || value.bytes().any(|c| c == b' ' || c == b'\t') {
            return Err(RecordError::MalformedTag);
        }
        if !seen.insert(name) {
            return Err(RecordError::DuplicateTag);
        }
        tags.push((name, value));
    }

    match tags.first() {
        Some(("v", VERSION)) => Ok(tags),
        _ => Err(RecordError::NotSworn),
    }
}

fn valid_rua(value: &str) -> bool {
    let Some(address) = value.strip_prefix("mailto:") else {
        return false;
    };
    if address.matches('@').count() != 1 {
        return false;
    }
    let Some((local, domain)) = address.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.split('.').all(|atom| {
            !atom.is_empty()
                && atom.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&byte)
                })
        })
        && crate::payload::is_operator_domain(domain)
}

fn get<'a>(tags: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|(tag, _)| *tag == name)
        .map(|(_, value)| *value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &str = "pk=ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=";

    #[test]
    fn parses_key_record() {
        let record = KeyRecord::parse(&format!("v=SWORN1; k=ed25519; {PK}")).unwrap();
        assert_eq!(
            record.public_key.to_string(),
            "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
        );
    }

    #[test]
    fn rejects_whitespace_inside_a_value() {
        assert_eq!(
            KeyRecord::parse("v=SWORN1; k=ed 25519; pk=AA==").unwrap_err(),
            RecordError::MalformedTag
        );
    }

    #[test]
    fn reports_unknown_algorithm_distinctly() {
        // The caller must map this to sworn=none, never sworn=fail.
        assert_eq!(
            KeyRecord::parse(&format!("v=SWORN1; k=fn-dsa-512; {PK}")).unwrap_err(),
            RecordError::UnknownAlgorithm
        );
    }

    #[test]
    fn rejects_wrong_length_key() {
        assert_eq!(
            KeyRecord::parse("v=SWORN1; k=ed25519; pk=AAAA").unwrap_err(),
            RecordError::BadValue("pk")
        );
    }

    // The length gate ahead of the decoder must refuse nothing the decoder
    // accepted: each of these was already an invalid pk, and stays one.
    #[test]
    fn rejects_pk_values_that_cannot_be_a_padded_key() {
        let key = &PK["pk=".len()..];
        let engine = base64::engine::general_purpose::STANDARD;
        let long = "A".repeat(4096);
        for value in [
            "",
            "=",
            "AAAA",
            // The same key without its padding: 43 characters.
            key.trim_end_matches('='),
            // 30 and 34 octets, correctly padded: 40 and 48 characters.
            &engine.encode([0u8; 30]),
            &engine.encode([0u8; 34]),
            // The key with a further padded group appended.
            &format!("{key}AA=="),
            &long,
        ] {
            assert_ne!(value.len(), ED25519_PK_ENCODED_LEN, "{value:?}");
            // What the decoder alone made of it before the gate existed.
            assert!(
                engine.decode(value).map_or(true, |raw| raw.len() != 32),
                "decoder alone accepts {value:?} as a key"
            );
            assert_eq!(
                KeyRecord::parse(&format!("v=SWORN1; k=ed25519; pk={value}")).unwrap_err(),
                RecordError::BadValue("pk"),
                "{value:?}"
            );
        }
        // 31 and 33 octets are also 44 characters, so they pass the gate and
        // are still refused by the key-length check behind it.
        for raw in [&[0u8; 31][..], &[0u8; 33]] {
            let value = engine.encode(raw);
            assert_eq!(value.len(), ED25519_PK_ENCODED_LEN);
            assert_eq!(
                KeyRecord::parse(&format!("v=SWORN1; k=ed25519; pk={value}")).unwrap_err(),
                RecordError::BadValue("pk")
            );
        }
    }

    // The other direction: every spelling the decoder reads as 32 octets is
    // 44 characters, so the gate cannot have turned an accepted key away.
    #[test]
    fn every_decodable_key_is_44_characters() {
        let engine = base64::engine::general_purpose::STANDARD;
        assert_eq!(engine.encode([0xffu8; 32]).len(), ED25519_PK_ENCODED_LEN);
        let mut decoded = 0;
        for len in 0..=96 {
            for padding in 0..=3 {
                let value = format!("{}{}", "A".repeat(len), "=".repeat(padding));
                if engine.decode(&value).is_ok_and(|raw| raw.len() == 32) {
                    assert_eq!(value.len(), ED25519_PK_ENCODED_LEN, "{value:?}");
                    decoded += 1;
                }
            }
        }
        // Without this the loop could pass by decoding nothing at all.
        assert_eq!(decoded, 1, "exactly one sampled spelling is a 32-octet key");
    }

    #[test]
    fn detects_a_duplicate_tag_among_many() {
        let many: String = (0..2000).map(|i| format!("; x{i}=1")).collect();
        assert!(PolicyRecord::parse(&format!("v=SWORN1{many}")).is_ok());
        // First and last tag of a long record, and a repeated version tag.
        assert_eq!(
            PolicyRecord::parse(&format!("v=SWORN1; u=64{many}; u=64")).unwrap_err(),
            RecordError::DuplicateTag
        );
        assert_eq!(
            PolicyRecord::parse(&format!("v=SWORN1{many}; v=SWORN1")).unwrap_err(),
            RecordError::DuplicateTag
        );
        // Names differing only in case are distinct, as before.
        assert!(PolicyRecord::parse("v=SWORN1; x=1; X=1").is_ok());
    }

    #[test]
    fn parses_policy_defaults() {
        let record = PolicyRecord::parse("v=SWORN1; p=2001:db8:f00::/48").unwrap();
        assert_eq!(record.unit, 64);
        assert!(!record.testing);
        assert!(record.rua.is_none());
        assert_eq!(record.prefixes.len(), 1);
    }

    #[test]
    fn ignores_prefixes_past_the_cap() {
        let mut prefixes: Vec<String> = (0..MAX_POLICY_PREFIXES)
            .map(|i| format!("2001:db8:{i:x}00::/48"))
            .collect();
        prefixes.push("not-a-prefix".to_owned());
        let record = PolicyRecord::parse(&format!("v=SWORN1; p={}", prefixes.join(","))).unwrap();
        assert_eq!(record.prefixes.len(), MAX_POLICY_PREFIXES);
    }

    #[test]
    fn reads_testing_flag_among_unknown_flags() {
        let record = PolicyRecord::parse("v=SWORN1; t=z:y:future").unwrap();
        assert!(record.testing);
        assert!(!PolicyRecord::parse("v=SWORN1; t=z").unwrap().testing);
    }

    #[test]
    fn rejects_policy_units_broader_than_a_prefix() {
        assert_eq!(
            PolicyRecord::parse("v=SWORN1; p=2001:db8:f00:1200::/56; u=48").unwrap_err(),
            RecordError::BadValue("u")
        );
    }

    #[test]
    fn rejects_unsafe_report_destinations() {
        for value in [
            "mailto:a@b.example\r\nBcc:victim@example.net",
            "mailto:a@b.example,c@d.example",
            "mailto:.a@b.example",
            "mailto:a@bad domain.example",
        ] {
            assert!(
                PolicyRecord::parse(&format!("v=SWORN1; rua={value}")).is_err(),
                "accepted {value:?}"
            );
        }
        assert!(PolicyRecord::parse("v=SWORN1; rua=mailto:a.b+tag@b.example").is_ok());
    }
}
