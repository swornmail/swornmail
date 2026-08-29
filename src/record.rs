//! Operator DNS records: one key record per selector, one policy record per
//! operator.

use base64::Engine as _;
use core::fmt;

use crate::address::Ipv6Prefix;
use crate::key::Ed25519PublicKey;

/// Version tag value every SwornMail record must carry first.
pub const VERSION: &str = "SWORN1";
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
                let unit: u8 = value.parse().map_err(|_| RecordError::BadValue("u"))?;
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
        if tags.iter().any(|(seen, _)| *seen == name) {
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
