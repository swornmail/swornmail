//! IPv6 prefix arithmetic and the draft's address constraints.
//!
//! Two distinct rule sets live here, and the draft keeps them separate:
//! constraints on an *attested prefix* (canonical, 32–64, inside `2000::/3`,
//! clear of Teredo and 6to4) and eligibility of a *connecting source address*
//! (no embedded-IPv4 or transition ranges, nothing outside `2000::/3`).

use core::fmt;
use core::str::FromStr;
use std::net::Ipv6Addr;

/// Shortest attested prefix the draft permits.
pub const MIN_PREFIX_LEN: u8 = 32;
/// Longest attested prefix the draft permits.
pub const MAX_PREFIX_LEN: u8 = 64;

const GLOBAL_UNICAST: Ipv6Prefix =
    Ipv6Prefix::new_unchecked(Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3);
const TEREDO: Ipv6Prefix =
    Ipv6Prefix::new_unchecked(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 32);
const SIX_TO_FOUR: Ipv6Prefix =
    Ipv6Prefix::new_unchecked(Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16);

/// Ranges a connecting source address must not fall in. The first four sit
/// outside `2000::/3` and are therefore redundant with the global-unicast
/// bound; they are listed because the draft names them, and because the
/// cross-family confusion they enable is the reason the rule exists.
const INELIGIBLE_SOURCE_RANGES: [Ipv6Prefix; 6] = [
    // IPv4-mapped ::ffff:0:0/96
    Ipv6Prefix::new_unchecked(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0), 96),
    // IPv4-compatible ::/96
    Ipv6Prefix::new_unchecked(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 96),
    // NAT64 well-known 64:ff9b::/96
    Ipv6Prefix::new_unchecked(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96),
    // NAT64 local-use 64:ff9b:1::/48
    Ipv6Prefix::new_unchecked(Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0), 48),
    TEREDO,
    SIX_TO_FOUR,
];

/// An IPv6 prefix: an address and a prefix length in bits.
///
/// The address is stored as given; use [`Ipv6Prefix::is_canonical`] to test
/// whether the bits beyond the length are zero, as the draft requires of
/// anything carried on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Prefix {
    addr: Ipv6Addr,
    len: u8,
}

impl Ipv6Prefix {
    /// Builds a prefix, returning `None` when `len` exceeds 128.
    pub const fn new(addr: Ipv6Addr, len: u8) -> Option<Self> {
        if len > 128 {
            return None;
        }
        Some(Ipv6Prefix { addr, len })
    }

    const fn new_unchecked(addr: Ipv6Addr, len: u8) -> Self {
        Ipv6Prefix { addr, len }
    }

    /// The prefix address, exactly as supplied.
    pub const fn addr(&self) -> Ipv6Addr {
        self.addr
    }

    /// The prefix length in bits.
    pub const fn prefix_len(&self) -> u8 {
        self.len
    }

    /// The same prefix with every bit beyond the length cleared.
    pub fn masked(&self) -> Ipv6Prefix {
        Ipv6Prefix {
            addr: mask(self.addr, self.len),
            len: self.len,
        }
    }

    /// Whether every bit beyond the prefix length is already zero.
    pub fn is_canonical(&self) -> bool {
        mask(self.addr, self.len) == self.addr
    }

    /// Whether `addr` falls within this prefix.
    pub fn contains(&self, addr: Ipv6Addr) -> bool {
        mask(addr, self.len) == mask(self.addr, self.len)
    }

    /// Whether this prefix overlaps `other` in either direction.
    fn overlaps(&self, other: &Ipv6Prefix) -> bool {
        let shorter = self.len.min(other.len);
        mask(self.addr, shorter) == mask(other.addr, shorter)
    }

    /// Whether this prefix may be attested: masked-canonical, 32–64 bits long,
    /// inside `2000::/3`, and clear of the Teredo and 6to4 ranges.
    pub fn is_attestable(&self) -> bool {
        self.is_canonical()
            && (MIN_PREFIX_LEN..=MAX_PREFIX_LEN).contains(&self.len)
            && GLOBAL_UNICAST.contains(self.addr)
            && !self.overlaps(&TEREDO)
            && !self.overlaps(&SIX_TO_FOUR)
    }
}

impl fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// Failure to parse an `address/length` prefix in presentation form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsePrefixError;

impl fmt::Display for ParsePrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid IPv6 prefix")
    }
}

impl std::error::Error for ParsePrefixError {}

impl FromStr for Ipv6Prefix {
    type Err = ParsePrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, len) = s.split_once('/').ok_or(ParsePrefixError)?;
        let addr: Ipv6Addr = addr.parse().map_err(|_| ParsePrefixError)?;
        let len: u8 = len.parse().map_err(|_| ParsePrefixError)?;
        Ipv6Prefix::new(addr, len).ok_or(ParsePrefixError)
    }
}

/// Clears every bit of `addr` beyond `len`.
pub fn mask(addr: Ipv6Addr, len: u8) -> Ipv6Addr {
    let bits = u128::from(addr);
    let keep = if len >= 128 {
        u128::MAX
    } else {
        !(u128::MAX >> len)
    };
    Ipv6Addr::from(bits & keep)
}

/// Whether a connecting source address may be considered part of any attested
/// prefix: ordinary global unicast, with no embedded-IPv4 or transition range.
pub fn is_eligible_source(addr: Ipv6Addr) -> bool {
    if !GLOBAL_UNICAST.contains(addr) {
        return false;
    }
    !INELIGIBLE_SOURCE_RANGES
        .iter()
        .any(|range| range.contains(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn prefix(s: &str) -> Ipv6Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn masks_to_unit_boundary() {
        let unit = Ipv6Prefix::new(mask(addr("2001:db8:f00:1234::a:1"), 64), 64).unwrap();
        assert_eq!(unit.to_string(), "2001:db8:f00:1234::/64");
    }

    #[test]
    fn rejects_non_canonical_prefix() {
        assert!(!prefix("2001:db8:f00:dead::/48").is_attestable());
        assert!(prefix("2001:db8:f00::/48").is_attestable());
    }

    #[test]
    fn enforces_attested_prefix_bounds() {
        assert!(!prefix("2001:db8::/16").is_attestable(), "too short");
        assert!(
            !prefix("2001:db8:f00:1234:5::/80").is_attestable(),
            "too long"
        );
        assert!(!prefix("fc00::/48").is_attestable(), "not global unicast");
        assert!(!prefix("2001::/48").is_attestable(), "teredo");
        assert!(!prefix("2002::/48").is_attestable(), "6to4");
        // A /16 enclosing 2002::/16 overlaps it even though it is not inside.
        assert!(!prefix("2000::/16").overlaps(&SIX_TO_FOUR));
        assert!(prefix("2002::/16").overlaps(&SIX_TO_FOUR));
    }

    #[test]
    fn rejects_ineligible_sources() {
        for s in [
            "::ffff:203.0.113.5",
            "::203.0.113.5",
            "64:ff9b::203.0.113.5",
            "64:ff9b:1::1",
            "2001::1",
            "2002:c000:204::1",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "::1",
        ] {
            assert!(!is_eligible_source(addr(s)), "{s} must be ineligible");
        }
        assert!(is_eligible_source(addr("2001:db8:f00:1234::a:1")));
    }
}
