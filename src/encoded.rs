//! CBOR major types, read off the encoding.
//!
//! ciborium's `Value` folds a bignum (tag 2 or 3 around a byte string) into a
//! plain `Value::Integer`, so anything decided on a `Value` cannot tell a
//! bignum from an integer. The token CDDL can: a payload key is `int`, a COSE
//! header label is `int / tstr`, and a bignum is neither. A token carrying its
//! operator under the key `2(h'01')` therefore decoded cleanly here, while a
//! verifier that keeps the tag calls it malformed: one signed token, two
//! verdicts. The checks that must hold a key or a value to its type read the
//! first octet of the item instead, where there is nothing to fold.
//!
//! Everything here takes untrusted input and fails closed: octets that are
//! not exactly the expected well-formed item are malformed.

use ciborium::value::Value;
use std::io::Cursor;

use crate::reason::Reason;

pub(crate) const MAJOR_UINT: u8 = 0;
pub(crate) const MAJOR_NINT: u8 = 1;
pub(crate) const MAJOR_BYTES: u8 = 2;
pub(crate) const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;

/// The major type of the item that starts `item`.
pub(crate) fn major(item: &[u8]) -> Result<u8, Reason> {
    item.first().map(|b| b >> 5).ok_or(Reason::Malformed)
}

/// Reads an item's major type, its argument (`None` for an indefinite
/// length), and how many octets the two occupy.
fn head(item: &[u8]) -> Result<(u8, Option<u64>, usize), Reason> {
    let first = *item.first().ok_or(Reason::Malformed)?;
    let (major, info) = (first >> 5, first & 0x1f);
    let size = match info {
        0..=23 => return Ok((major, Some(u64::from(info)), 1)),
        24 => 2,
        25 => 3,
        26 => 5,
        27 => 9,
        31 => return Ok((major, None, 1)),
        _ => return Err(Reason::Malformed),
    };
    let arg = item
        .get(1..size)
        .ok_or(Reason::Malformed)?
        .iter()
        .fold(0u64, |arg, &b| (arg << 8) | u64::from(b));
    Ok((major, Some(arg), size))
}

/// Splits the first well-formed item off `bytes`.
fn next_item(bytes: &[u8]) -> Result<(&[u8], &[u8]), Reason> {
    let mut cursor = Cursor::new(bytes);
    let _: Value = ciborium::de::from_reader(&mut cursor).map_err(|_| Reason::Malformed)?;
    Ok(bytes.split_at(cursor.position() as usize))
}

/// One key and value of a map, each still encoded.
pub(crate) type Entry<'a> = (&'a [u8], &'a [u8]);

/// Splits an encoded map into its entries, in wire order. A tagged map is
/// not a map.
pub(crate) fn map_entries(bytes: &[u8]) -> Result<Vec<Entry<'_>>, Reason> {
    let (major, count, size) = head(bytes)?;
    if major != MAJOR_MAP {
        return Err(Reason::Malformed);
    }
    let mut rest = &bytes[size..];
    let mut entries = Vec::new();
    loop {
        match count {
            Some(n) if entries.len() as u64 == n => break,
            None if rest.first() == Some(&0xff) => {
                rest = &rest[1..];
                break;
            }
            _ => {}
        }
        let (key, after) = next_item(rest)?;
        let (value, after) = next_item(after)?;
        entries.push((key, value));
        rest = after;
    }
    if !rest.is_empty() {
        return Err(Reason::Malformed);
    }
    Ok(entries)
}

/// Reads an integer item: `None` for anything that is not major type 0 or 1,
/// which includes a bignum.
pub(crate) fn integer(item: &[u8]) -> Option<i128> {
    match head(item) {
        Ok((MAJOR_UINT, Some(n), _)) => Some(i128::from(n)),
        Ok((MAJOR_NINT, Some(n), _)) => Some(-1 - i128::from(n)),
        _ => None,
    }
}

/// Returns the encoded unprotected header bucket of a tagged `COSE_Sign1`:
/// the second element of the array under the tag.
pub(crate) fn unprotected_bucket(token: &[u8]) -> Result<&[u8], Reason> {
    let (major, _, size) = head(token)?;
    if major != MAJOR_TAG {
        return Err(Reason::Malformed);
    }
    let body = &token[size..];
    let (major, _, size) = head(body)?;
    if major != MAJOR_ARRAY {
        return Err(Reason::Malformed);
    }
    let (_, rest) = next_item(&body[size..])?;
    let (unprotected, _) = next_item(rest)?;
    Ok(unprotected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_definite_and_indefinite_maps() {
        // {1: "a", 2: h'00'}
        let definite = [0xa2, 0x01, 0x61, b'a', 0x02, 0x41, 0x00];
        let indefinite = [0xbf, 0x01, 0x61, b'a', 0x02, 0x41, 0x00, 0xff];
        for map in [&definite[..], &indefinite[..]] {
            let entries = map_entries(map).unwrap();
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0], (&[0x01][..], &[0x61, b'a'][..]));
            assert_eq!(entries[1], (&[0x02][..], &[0x41, 0x00][..]));
        }
    }

    #[test]
    fn rejects_what_is_not_exactly_one_map() {
        for bytes in [
            &[][..],
            &[0x80],                         // an array
            &[0xd9, 0xd9, 0xf7, 0xa0],       // a self-described map is a tag
            &[0xa1, 0x01],                   // a key with no value
            &[0xa0, 0x00],                   // a trailing octet
            &[0xbf, 0x01, 0x61, b'a'],       // no break
            &[0xbb, 0xff, 0xff, 0xff, 0xff], // a truncated count
        ] {
            assert_eq!(map_entries(bytes), Err(Reason::Malformed), "{bytes:02x?}");
        }
    }

    #[test]
    fn finds_the_unprotected_bucket() {
        // 18([h'', {99: 1}, h'', h''])
        let token = [0xd2, 0x84, 0x40, 0xa1, 0x18, 0x63, 0x01, 0x40, 0x40];
        assert_eq!(
            unprotected_bucket(&token),
            Ok(&[0xa1, 0x18, 0x63, 0x01][..])
        );
        // The same under a two-octet tag head and an indefinite-length array.
        let loose = [0xd8, 0x12, 0x9f, 0x40, 0xa0, 0x40, 0x40, 0xff];
        assert_eq!(unprotected_bucket(&loose), Ok(&[0xa0][..]));
        for bytes in [
            &[][..],
            &[0x84, 0x40, 0xa0, 0x40, 0x40], // untagged
            &[0xd2, 0xa0],                   // a tagged map
            &[0xd2, 0x84, 0x40],             // nothing after the protected bucket
        ] {
            assert_eq!(
                unprotected_bucket(bytes),
                Err(Reason::Malformed),
                "{bytes:02x?}"
            );
        }
    }

    #[test]
    fn a_bignum_is_not_an_integer() {
        assert_eq!(integer(&[0x01]), Some(1));
        assert_eq!(integer(&[0x18, 0x63]), Some(99));
        assert_eq!(integer(&[0x20]), Some(-1));
        assert_eq!(
            integer(&[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Some(i128::from(u64::MAX))
        );
        assert_eq!(
            integer(&[0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Some(-1 - i128::from(u64::MAX))
        );
        assert_eq!(integer(&[0xc2, 0x41, 0x01]), None); // 2(h'01')
        assert_eq!(integer(&[0xc3, 0x41, 0x00]), None); // 3(h'00')
        assert_eq!(integer(&[0xd9, 0xd9, 0xf7, 0x01]), None); // 55799(1)
        assert_eq!(integer(&[0x61, b'1']), None);
        assert_eq!(integer(&[0xf9, 0x3c, 0x00]), None); // 1.0
    }
}
