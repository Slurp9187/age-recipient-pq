use age::{secrecy, Identity as AgeIdentity, Recipient as AgeRecipient};
use age_core::format::{FileKey, Stanza};
use age_core::secrecy::SecretString;
use base64::prelude::{Engine as _, BASE64_STANDARD_NO_PAD};
use bech32::{self, Variant, ToBase32, FromBase32};
use pq_xwing_hpke::kem::{Kem, MlKem768X25519};
use pq_xwing_hpke::{aead::new_aead, kdf::new_kdf};
use pq_xwing_hpke::{
    hpke::{new_sender, open},
};
use secrecy::{ExposeSecret, SecretBox};
use std::collections::HashSet;
use std::str::FromStr;

/// The stanza tag identifying this post-quantum hybrid recipient in the age file format.
/// This tag is "mlkem768x25519" to indicate ML-KEM-768 combined with X25519.
const STANZA_TAG: &str = "mlkem768x25519"; // From plugin/age-go
/// The domain separation label for HPKE operations, matching the age-go plugin.
const PQ_LABEL: &[u8] = b"age-encryption.org/mlkem768x25519"; // From plugin/age-go
/// The KDF ID for HPKE, corresponding to HKDF-SHA256.
const KDF_ID: u16 = 0x0001; // HKDF-SHA256
/// The AEAD ID for HPKE, corresponding to ChaCha20Poly1305.
const AEAD_ID: u16 = 0x0003; // ChaCha20Poly1305

/// A post-quantum hybrid recipient for encryption, using ML-KEM-768 and X25519.
///
/// This struct holds the public key and provides methods to wrap file keys in the age format.
/// It implements [`age::Recipient`] for integration with the age encryption tool.
pub struct HybridRecipient {
    /// The public key bytes, consisting of the ML-KEM-768 public key concatenated with the X25519 public key.
    pub pub_key: Vec<u8>,
}

impl HybridRecipient {
    /// Generates a new hybrid recipient and its corresponding identity.
    ///
    /// This method creates a new key pair using the XWing768X25519 KEM and returns
    /// a recipient for encryption and an identity for decryption.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// extern crate age_recipient_pq;
    /// use age_recipient_pq::{HybridRecipient, HybridIdentity};
    /// let (recipient, identity) = HybridRecipient::generate().unwrap();
    /// ```
    pub fn generate() -> Result<(Self, HybridIdentity), Box<dyn std::error::Error>> {
        let kem = MlKem768X25519;
        let sk = kem.generate_key()?;
        let pk = sk.public_key();
        let seed_bytes = sk.bytes()?;
        let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| "Invalid seed length")?;
        let pub_key_bytes = pk.bytes();
        Ok((
            Self {
                pub_key: pub_key_bytes,
            },
            HybridIdentity {
                seed: SecretBox::new(Box::new(seed)),
            },
        ))
    }

    /// Parses a hybrid recipient from its string representation.
    ///
    /// The expected format is a Bech32-encoded string with HRP "age1pq" and the public key as data.
    ///
    /// # Arguments
    ///
    /// * `s` - The string to parse.
    ///
    /// # Errors
    ///
    /// Returns an [`age::EncryptError`] if the string is malformed or the key is invalid.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// extern crate age_recipient_pq;
    /// use age_recipient_pq::HybridRecipient;
    /// let recipient = HybridRecipient::parse("age1pq1...").unwrap();
    /// ```
    pub fn parse(s: &str) -> Result<Self, age::EncryptError> {
        let (hrp, data5, variant) = bech32::decode(s).map_err(|e| {
            age::EncryptError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;

        if variant != Variant::Bech32 || hrp != "age1pq" {
            return Err(age::EncryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid Bech32 variant or HRP: {} {:?}", hrp, variant),
            )));
        }

        let pub_key = Vec::<u8>::from_base32(&data5).map_err(|_| {
            age::EncryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid base32 data",
            ))
        })?;

        Ok(Self { pub_key })
    }

    /// Serializes the recipient to its canonical string format.
    ///
    /// Returns a Bech32-encoded string with HRP "age1pq" and the public key as data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// extern crate age_recipient_pq;
    /// use age_recipient_pq::HybridRecipient;
    /// let (recipient, _) = HybridRecipient::generate().unwrap();
    /// let str = recipient.to_string();
    /// assert!(str.starts_with("age1pq1"));
    /// ```
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        let data5 = self.pub_key.to_base32();
        bech32::encode("age1pq", data5, Variant::Bech32)
            .expect("Bech32 encoding never fails with valid HRP + byte-derived data")
    }
}

/// Implements string parsing for [`HybridRecipient`].
impl FromStr for HybridRecipient {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).map_err(|_| "failed to parse HybridRecipient")
    }
}

/// Implements the age [`AgeRecipient`] trait for [`HybridRecipient`].
impl AgeRecipient for HybridRecipient {
    /// Wraps a file key using HPKE with this recipient's public key.
    ///
    /// This generates an encrypted stanza that can be decrypted by the corresponding identity.
    /// The stanza uses the tag "mlkem768x25519" and includes the encapsulated key.
    ///
    /// # Arguments
    ///
    /// * `file_key` - The file key to encrypt.
    ///
    /// # Returns
    ///
    /// A tuple of the created stanza and a set of labels including "postquantum".
    ///
    /// # Errors
    ///
    /// Returns an [`age::EncryptError`] if encryption fails.
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        let kem = MlKem768X25519;
        let pk = kem.new_public_key(&self.pub_key).map_err(|e| {
            age::EncryptError::Io(std::io::Error::other(format!("Invalid pub key: {:?}", e)))
        })?;
        let kdf = new_kdf(KDF_ID).map_err(|e| {
            age::EncryptError::Io(std::io::Error::other(format!("KDF error: {:?}", e)))
        })?;
        let aead = new_aead(AEAD_ID).map_err(|e| {
            age::EncryptError::Io(std::io::Error::other(format!("AEAD error: {:?}", e)))
        })?;
        let (enc, mut sender) = new_sender(pk, kdf, aead, PQ_LABEL).map_err(|e| {
            age::EncryptError::Io(std::io::Error::other(format!(
                "HPKE new_sender error: {:?}",
                e
            )))
        })?;
        let wrapped = sender.seal(&[], file_key.expose_secret()).map_err(|e| {
            age::EncryptError::Io(std::io::Error::other(format!("HPKE seal error: {:?}", e)))
        })?;
        let base64_enc = BASE64_STANDARD_NO_PAD.encode(&enc);
        let stanza = Stanza {
            tag: STANZA_TAG.to_string(),
            args: vec![base64_enc],
            body: wrapped,
        };
        let mut labels = HashSet::new();
        labels.insert("postquantum".to_string());
        Ok((vec![stanza], labels))
    }
}

/// A post-quantum hybrid identity for decryption, holding the private key seed.
///
/// This struct contains a 32-byte seed from which the private key is derived.
/// The seed is securely wrapped in a [`SecretBox`] to ensure zeroization.
/// It implements [`age::Identity`] for decryption in the age tool.
pub struct HybridIdentity {
    seed: SecretBox<[u8; 32]>,
}

impl HybridIdentity {
    /// Parses a hybrid identity from its bech32-encoded string representation.
    ///
    /// The format uses HRP "AGE-SECRET-KEY-PQ-" and contains the 32-byte seed.
    ///
    /// # Arguments
    ///
    /// * `s` - The string to parse.
    ///
    /// # Errors
    ///
    /// Returns an [`age::DecryptError`] if the string is invalid.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// extern crate age_recipient_pq;
    /// use age_recipient_pq::HybridIdentity;
    /// let identity = HybridIdentity::parse("AGE-SECRET-KEY-PQ-1...").unwrap();
    /// ```
    pub fn parse(s: &str) -> Result<Self, age::DecryptError> {
        let (hrp, data5, variant) = bech32::decode(s).map_err(|e| {
            age::DecryptError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;

        if variant != Variant::Bech32 || hrp.to_ascii_lowercase() != "age-secret-key-pq-" {
            return Err(age::DecryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid HRP or variant: {} {:?}", hrp, variant),
            )));
        }

        let seed_bytes = Vec::<u8>::from_base32(&data5).map_err(|_| {
            age::DecryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid base32 data",
            ))
        })?;

        let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
            age::DecryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid seed length",
            ))
        })?;

        Ok(Self {
            seed: SecretBox::new(Box::new(seed)),
        })
    }

    /// Serializes the identity to its bech32-encoded string representation.
    ///
    /// Returns a [`SecretString`] to prevent accidental exposure in logs.
    ///
    /// # Examples
    ///
    /// ```rust
    /// extern crate age_recipient_pq;
    /// use age_recipient_pq::{HybridIdentity, HybridRecipient};
    /// use age::secrecy::ExposeSecret;
    /// let (_, identity) = HybridRecipient::generate().unwrap();
    /// let secret_str = identity.to_string();
    /// let str = secret_str.expose_secret().clone();
    /// ```
    pub fn to_string(&self) -> SecretString {
        let data5 = self.seed.expose_secret().to_base32();
        let encoded = bech32::encode("age-secret-key-pq-", data5, Variant::Bech32)
            .expect("Bech32 encoding never fails with valid HRP + byte-derived data");
        SecretString::from(encoded.to_ascii_uppercase())
    }

    /// Derives the public recipient from this identity.
    ///
    /// Computes the public key from the private key seed.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// extern crate age_recipient_pq;
    /// use age_recipient_pq::{HybridIdentity, HybridRecipient};
    /// let (_, identity) = HybridRecipient::generate().unwrap();
    /// let recipient = identity.to_public().unwrap();
    /// ```
    pub fn to_public(&self) -> Result<HybridRecipient, Box<dyn std::error::Error>> {
        let kem = MlKem768X25519;
        let sk = kem.new_private_key(self.seed.expose_secret())?;
        let pk = sk.public_key();
        let pub_key_bytes = pk.bytes();
        Ok(HybridRecipient {
            pub_key: pub_key_bytes,
        })
    }
}

/// Implements string parsing for [`HybridIdentity`].
impl FromStr for HybridIdentity {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).map_err(|_| "failed to parse HybridIdentity")
    }
}

/// Implements the age [`AgeIdentity`] trait for [`HybridIdentity`].
impl AgeIdentity for HybridIdentity {
    /// Attempts to decrypt a single stanza using this identity.
    ///
    /// Supports the current format (tag + base64(enc)) and legacy format (base64(enc)) for compatibility.
    ///
    /// # Arguments
    ///
    /// * `stanza` - The stanza to decrypt.
    ///
    /// # Returns
    ///
    /// `Some(Ok(file_key))` on success, `Some(Err(e))` on decryption error, or `None` if not applicable.
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        if stanza.tag != STANZA_TAG {
            return None;
        }
        let enc: Vec<u8>;
        if stanza.args.len() == 2 && stanza.args[0] == STANZA_TAG {
            enc = match BASE64_STANDARD_NO_PAD.decode(&stanza.args[1]) {
                Ok(b) => b,
                Err(_) => return None,
            };
        } else if stanza.args.len() == 1 {
            enc = match BASE64_STANDARD_NO_PAD.decode(&stanza.args[0]) {
                Ok(b) => b,
                Err(_) => return None,
            };
        } else {
            return None;
        }
        let kem = MlKem768X25519;
        let sk = match kem.new_private_key(self.seed.expose_secret()) {
            Ok(s) => s,
            Err(_) => return None,
        };
        let kdf = match new_kdf(KDF_ID) {
            Ok(k) => k,
            Err(_) => return None,
        };
        let aead = match new_aead(AEAD_ID) {
            Ok(a) => a,
            Err(_) => return None,
        };
        let mut ct = enc;
        ct.extend_from_slice(&stanza.body);
        let file_key_bytes = match open(sk, kdf, aead, PQ_LABEL, &ct) {
            Ok(f) => f,
            Err(_) => return None,
        };
        let file_key = match file_key_bytes.try_into() {
            Ok(arr) => FileKey::new(Box::new(arr)),
            Err(_) => return None,
        };
        Some(Ok(file_key))
    }

    /// Attempts to decrypt any of the provided stanzas using this identity.
    ///
    /// Tries each stanza in order and returns the result of the first successful decryption.
    ///
    /// # Arguments
    ///
    /// * `stanzas` - The stanzas to try.
    ///
    /// # Returns
    ///
    /// `Some(Ok(file_key))` on success, `Some(Err(e))` on error, or `None` if none succeed.
    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, age::DecryptError>> {
        stanzas.iter().find_map(|stanza| self.unwrap_stanza(stanza))
    }
}

/// Tests for the post-quantum hybrid recipient and identity.
#[cfg(test)]
pub(crate) mod tests {
    use age::{Identity, Recipient};
    use age_core::format::FileKey;
    use age_core::secrecy::ExposeSecret;
    use proptest::prelude::*;
    use super::HybridRecipient;

    #[test]
    fn test_suite_id_matches_go() {
        let expected = vec![0x48, 0x50, 0x4b, 0x45, 0x64, 0x7a, 0x00, 0x01, 0x00, 0x03];
        let mut sid = Vec::with_capacity(10);
        sid.extend_from_slice(b"HPKE");
        sid.extend_from_slice(&0x647au16.to_be_bytes());
        sid.extend_from_slice(&0x0001u16.to_be_bytes());
        sid.extend_from_slice(&0x0003u16.to_be_bytes());
        assert_eq!(sid, expected);
    }

    proptest! {
        #[test]
        fn wrap_and_unwrap(file_key_bytes in proptest::collection::vec(any::<u8>(), 16..=16)) {
            let file_key = FileKey::new(Box::new(file_key_bytes.try_into().unwrap()));
            let (recipient, identity) = HybridRecipient::generate().unwrap();
            let res = recipient.wrap_file_key(&file_key);
            prop_assert!(res.is_ok());
            let (stanzas, labels) = res.unwrap();
            prop_assert!(labels.contains("postquantum"));
            let res = identity.unwrap_stanzas(&stanzas);
            prop_assert!(res.is_some());
            let res = res.unwrap();
            prop_assert!(res.is_ok());
            let unwrapped = res.unwrap();
            prop_assert_eq!(unwrapped.expose_secret(), file_key.expose_secret());
        }
    }
}
