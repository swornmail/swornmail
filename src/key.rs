//! Operator signing keys.

use core::fmt;

/// An Ed25519 public key, as published in a `<selector>._sworn` key record.
///
/// Wrapping the underlying key type keeps the signature backend out of this
/// crate's public API, so it can be replaced when the algorithm registry grows
/// a post-quantum entry.
#[derive(Debug, Clone)]
pub struct Ed25519PublicKey(ed25519_dalek::VerifyingKey);

impl Ed25519PublicKey {
    /// Length of an Ed25519 public key in octets.
    pub const LEN: usize = 32;

    /// Parses a key from its 32-octet encoding, returning `None` if the length
    /// is wrong or the encoding is not a valid curve point.
    pub fn from_bytes(bytes: &[u8]) -> Option<Ed25519PublicKey> {
        let bytes: [u8; Self::LEN] = bytes.try_into().ok()?;
        ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .ok()
            .map(Ed25519PublicKey)
    }

    /// The key's 32-octet encoding.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        self.0.to_bytes()
    }

    /// Verifies a detached signature over `message`.
    ///
    /// Uses strict verification, which rejects small-order and non-canonically
    /// encoded keys and signatures. The draft does not specify a verification
    /// equation; strict is the safer reading, and the difference is only
    /// reachable with a deliberately malformed key.
    pub(crate) fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(signature) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        let signature = ed25519_dalek::Signature::from_bytes(&signature);
        self.0.verify_strict(message, &signature).is_ok()
    }
}

impl fmt::Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.to_bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
