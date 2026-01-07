// src/pq.rs

use age::{secrecy, Identity as AgeIdentity, Recipient as AgeRecipient};
use age_core::format::{FileKey, Stanza};
use age_core::secrecy::SecretString;
use base64::prelude::{Engine as _, BASE64_STANDARD_NO_PAD};
use bech32::{self, FromBase32, ToBase32, Variant};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use pq_xwing_hpke::xwing768x25519::{Ciphertext, DecapsulationKey, EncapsulationKey};
use rand::{rngs::OsRng, TryRngCore};
use secrecy::{ExposeSecret, SecretBox};
use std::collections::HashSet;
use std::str::FromStr;
use zeroize::Zeroize;

use crate::hpke_pq::{
    compute_nonce, derive_key_and_nonce, map_hpke_decrypt_error, map_hpke_error,
};

const STANZA_TAG: &str = "mlkem768x25519"; // From plugin/age-go
const PQ_LABEL: &[u8] = b"age-encryption.org/mlkem768x25519"; // From plugin/age-go

pub struct HybridRecipient {
    pub_key: EncapsulationKey,
}

impl HybridRecipient {
    pub fn generate() -> (Self, HybridIdentity) {
        let mut seed = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut seed)
            .expect("Failed to generate random seed");
        let sk = DecapsulationKey::from_seed(&seed);
        let pk = sk.encapsulation_key().expect("Key generation failed");
        (
            Self { pub_key: pk },
            HybridIdentity {
                seed: SecretBox::new(Box::new(seed)),
            },
        )
    }

    pub fn parse(s: &str) -> Result<Self, age::EncryptError> {
        let (hrp, data, _) = bech32::decode(s).map_err(|e| {
            age::EncryptError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
        if hrp != "age1pq" {
            return Err(age::EncryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid HRF",
            )));
        }
        let bytes = Vec::<u8>::from_base32(&data).map_err(|_| {
            age::EncryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid base32",
            ))
        })?;
        let pub_key = EncapsulationKey::try_from(&bytes[..]).map_err(|_| {
            age::EncryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid key",
            ))
        })?;
        Ok(Self { pub_key })
    }

    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        bech32::encode(
            "age1pq",
            self.pub_key.to_bytes().to_base32(),
            Variant::Bech32,
        )
        .expect("Encoding failed")
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
        let mut rng = OsRng;
        let (ct, mut ss) = self
            .pub_key
            .encapsulate(&mut rng)
            .map_err(|_| age::EncryptError::Io(std::io::Error::other("Encapsulation failed")))?;

        let (mut aead_key_bytes, base_nonce) =
            derive_key_and_nonce(&ss, PQ_LABEL).map_err(map_hpke_error)?;
        let nonce_bytes = compute_nonce(&base_nonce, 0u64);
        let nonce = Nonce::from(nonce_bytes);
        let aead_key = Key::from(aead_key_bytes);
        aead_key_bytes.zeroize();

        let aead = ChaCha20Poly1305::new(&aead_key);
        let wrapped = aead
            .encrypt(&nonce, file_key.expose_secret().as_slice())
            .map_err(|_| age::EncryptError::Io(std::io::Error::other("Encryption failed")))?;

        let ct_base64 = BASE64_STANDARD_NO_PAD.encode(ct.to_bytes());
        let stanza = Stanza {
            tag: STANZA_TAG.to_string(),
            args: vec![ct_base64],
            body: wrapped,
        };
        ss.zeroize();
        let mut labels = HashSet::new();
        labels.insert("postquantum".to_string());
        Ok((vec![stanza], labels))
    }
}

pub struct HybridIdentity {
    seed: secrecy::SecretBox<[u8; 32]>,
}

impl HybridIdentity {
    pub fn parse(s: &str) -> Result<Self, age::DecryptError> {
        let (hrp, data, _) = bech32::decode(s).map_err(|e| {
            age::DecryptError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
        if hrp != "age-secret-key-pq-" {
            return Err(age::DecryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid HRF",
            )));
        }
        let bytes = Vec::<u8>::from_base32(&data).map_err(|_| {
            age::DecryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid base32",
            ))
        })?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| {
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
        let sk_base32 = self.seed.expose_secret().to_base32();
        let mut encoded = bech32::encode("age-secret-key-pq-", sk_base32, Variant::Bech32)
            .expect("Encoding failed");
        let ret = SecretString::from(encoded.to_uppercase());

        // Clear intermediates
        encoded.zeroize();

        ret
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
        println!("Starting unwrap_stanza for tag: {}", stanza.tag);
        if stanza.tag != STANZA_TAG {
            println!("Tag mismatch: expected {}, got {}", STANZA_TAG, stanza.tag);
            return None;
        }
        println!("Tag ok");
        if stanza.args.len() != 1 {
            println!("Args len mismatch: expected 1, got {}", stanza.args.len());
            return None;
        }
        println!("Args ok");
        // Decode base64 ct
        let ct_bytes = match BASE64_STANDARD_NO_PAD.decode(&stanza.args[0]) {
            Ok(b) => b,
            Err(e) => {
                println!("Base64 decode failed: {:?}", e);
                return None;
            }
        };
        println!("Base64 decode ok, ct_bytes len: {}", ct_bytes.len());
        let ct = match Ciphertext::try_from(&ct_bytes[..]) {
            Ok(c) => c,
            Err(e) => {
                println!("Ciphertext try_from failed: {:?}", e);
                return None;
            }
        };
        println!("Ciphertext ok");
        // Decapsulate
        let sk = DecapsulationKey::from_seed(self.seed.expose_secret());
        let mut ss = match sk.decapsulate(&ct) {
            Ok(s) => s,
            Err(e) => {
                println!("Decapsulate failed: {:?}", e);
                return None;
            }
        };
        println!(
            "Decapsulate ok, ss len: {}, ss starts with: {:?}",
            ss.len(),
            &ss[0..std::cmp::min(16, ss.len())]
        );
        println!("SS hash: {:?}", ss);
        // Derive AEAD key
        let (mut aead_key_bytes, base_nonce) = match derive_key_and_nonce(&ss, PQ_LABEL) {
            Ok(result) => result,
            Err(e) => return Some(Err(map_hpke_decrypt_error(e))),
        };
        let nonce_bytes = compute_nonce(&base_nonce, 0u64);
        let nonce = Nonce::from(nonce_bytes);
        let aead_key = Key::from(aead_key_bytes);
        println!(
            "Key derivation ok, aead_key starts with: {:?}",
            &aead_key_bytes[0..4]
        );
        aead_key_bytes.zeroize();
        // Decrypt
        let aead = ChaCha20Poly1305::new(&aead_key);
        let decrypted = match aead.decrypt(&nonce, &*stanza.body) {
            Ok(d) => d,
            Err(e) => {
                println!("AEAD decrypt failed: {:?}", e);
                println!(
                    "stanza.body len: {}, nonce: {:?}",
                    stanza.body.len(),
                    &nonce_bytes[0..12]
                );
                println!("Expected decrypted len 16, but AEAD failed");
                return None;
            }
        };
        println!("Decrypt ok, decrypted len: {}", decrypted.len());
        if decrypted.len() != 16 {
            println!(
                "Decrypted len mismatch: got {}, expected 16",
                decrypted.len()
            );
            return None;
        }
        println!("Len check ok");
        let decrypted_array: [u8; 16] = decrypted.try_into().unwrap_or_else(|_| {
            println!("try_into failed for decrypted_array");
            [0u8; 16]
        });
        let file_key = FileKey::new(Box::new(decrypted_array));
        ss.zeroize();
        println!("File key created ok");
        Some(Ok(file_key))
    }

    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, age::DecryptError>> {
        stanzas.iter().find_map(|stanza| self.unwrap_stanza(stanza))
    }
}
