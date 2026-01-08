// src/pq.rs

use age::{secrecy, Identity as AgeIdentity, Recipient as AgeRecipient};
use age_core::format::{FileKey, Stanza};
use age_core::secrecy::SecretString;
use base64::prelude::{Engine as _, BASE64_STANDARD_NO_PAD};
use bech32::Hrp;
use pq_xwing_hpke::{aead::new_aead, kdf::new_kdf};
use pq_xwing_hpke::{
    hpke::{new_sender, open},
    kem::{Kem, XWing768X25519},
};

use secrecy::{ExposeSecret, SecretBox};
use std::collections::HashSet;
use std::str::FromStr;

const STANZA_TAG: &str = "mlkem768x25519"; // From plugin/age-go
const PQ_LABEL: &[u8] = b"age-encryption.org/mlkem768x25519"; // From plugin/age-go

const KDF_ID: u16 = 0x0001; // HKDF-SHA256
const AEAD_ID: u16 = 0x0003; // ChaCha20Poly1305

pub struct HybridRecipient {
    pub_key: Vec<u8>,
}

impl HybridRecipient {
    pub fn generate() -> Result<(Self, HybridIdentity), Box<dyn std::error::Error>> {
        let kem = XWing768X25519;
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

    pub fn parse(s: &str) -> Result<Self, age::EncryptError> {
        if !s.starts_with("age1pq1") {
            return Err(age::EncryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid recipient format",
            )));
        }
        let base64_part = &s[7..];
        let pub_key = BASE64_STANDARD_NO_PAD.decode(base64_part).map_err(|e| {
            age::EncryptError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
        Ok(Self { pub_key })
    }

    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        format!("age1pq1{}", BASE64_STANDARD_NO_PAD.encode(&self.pub_key))
    }
}

impl FromStr for HybridRecipient {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).map_err(|_| "failed to parse HybridRecipient")
    }
}

impl AgeRecipient for HybridRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        let kem = XWing768X25519;
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
            args: vec![STANZA_TAG.to_string(), base64_enc],
            body: wrapped,
        };
        let mut labels = HashSet::new();
        labels.insert("postquantum".to_string());
        Ok((vec![stanza], labels))
    }
}

pub struct HybridIdentity {
    seed: SecretBox<[u8; 32]>,
}

impl HybridIdentity {
    pub fn parse(s: &str) -> Result<Self, age::DecryptError> {
        let (hrp, data) = bech32::decode(s).map_err(|e| {
            age::DecryptError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
        if hrp.as_str() != "AGE-SECRET-KEY-PQ-1" {
            return Err(age::DecryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid HRP",
            )));
        }
        let seed: [u8; 32] = data.try_into().map_err(|_| {
            age::DecryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid seed length",
            ))
        })?;
        Ok(Self {
            seed: SecretBox::new(Box::new(seed)),
        })
    }

    pub fn to_string(&self) -> SecretString {
        let hrp = Hrp::parse("AGE-SECRET-KEY-PQ-1").unwrap();
        let encoded = bech32::encode::<bech32::Bech32>(hrp, self.seed.expose_secret())
            .expect("Encoding failed");
        SecretString::from(encoded.to_uppercase())
    }

    pub fn to_public(&self) -> Result<HybridRecipient, Box<dyn std::error::Error>> {
        let kem = XWing768X25519;
        let sk = kem.new_private_key(self.seed.expose_secret())?;
        let pk = sk.public_key();
        let pub_key_bytes = pk.bytes();
        Ok(HybridRecipient {
            pub_key: pub_key_bytes,
        })
    }
}

impl FromStr for HybridIdentity {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).map_err(|_| "failed to parse HybridIdentity")
    }
}

impl AgeIdentity for HybridIdentity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        if stanza.tag != STANZA_TAG {
            return None;
        }
        if stanza.args.len() != 2 || stanza.args[0] != STANZA_TAG {
            return None;
        }
        let enc: Vec<u8> = match BASE64_STANDARD_NO_PAD.decode(&stanza.args[1]) {
            Ok(b) => b,
            Err(_) => return None,
        };
        let kem = XWing768X25519;
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

    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, age::DecryptError>> {
        stanzas.iter().find_map(|stanza| self.unwrap_stanza(stanza))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use age::{Identity, Recipient};
    use age_core::format::FileKey;
    use age_core::secrecy::ExposeSecret;
    use pq_xwing_hpke::kem::Kem;
    use proptest::prelude::*;
    use secrecy::SecretBox;

    use super::{HybridIdentity, HybridRecipient};

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
