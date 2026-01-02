use age::{secrecy, Identity as AgeIdentity, Recipient as AgeRecipient};
use age_core::format::{FileKey, Stanza};
use base64::prelude::{Engine as _, BASE64_STANDARD_NO_PAD};
use bech32::{self, FromBase32, ToBase32, Variant};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use libcrux_hkdf::{expand, extract, Algorithm};
use pq_xwing_kem::xwing768x25519::{Ciphertext, DecapsulationKey, EncapsulationKey};
use rand::{rngs::OsRng, TryRngCore};
use secrecy::{ExposeSecret, SecretBox};
use std::collections::HashSet;
use zeroize::Zeroize;

// use crate::InfallibleOsRng;

const STANZA_TAG: &str = "mlkem768x25519"; // From plugin/age-go
const PQ_LABEL: &[u8] = b"age-encryption.org/mlkem768x25519"; // From plugin/age-go
const SUITE_ID: &[u8] = b"HPKE\x00\x64\x7a\x00\x01\x00\x01"; // From plugin (HPKE for MLKEM768-X25519)

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

    pub fn to_string(&self) -> String {
        bech32::encode(
            "age1pq",
            self.pub_key.to_bytes().to_base32(),
            Variant::Bech32,
        )
        .expect("Encoding failed")
    }
}

impl AgeRecipient for HybridRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        let mut rng = OsRng;
        let (ct, mut ss) = self.pub_key.encapsulate(&mut rng).map_err(|_| {
            age::EncryptError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Encapsulation failed",
            ))
        })?;

        let mut prk = [0u8; 32];
        extract(Algorithm::Sha256, &mut prk, &ss, SUITE_ID).map_err(|_| {
            age::EncryptError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "HKDF extract failed",
            ))
        })?;
        let mut aead_key_bytes = [0u8; 32];
        expand(Algorithm::Sha256, &mut aead_key_bytes, &prk, PQ_LABEL).map_err(|_| {
            age::EncryptError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "HKDF expand failed",
            ))
        })?;
        let aead_key = Key::from(aead_key_bytes);
        aead_key_bytes.zeroize();

        let mut nonce_bytes = [0u8; 12];
        OsRng
            .try_fill_bytes(&mut nonce_bytes)
            .expect("Failed to generate nonce");
        let nonce = Nonce::from(nonce_bytes);

        let aead = ChaCha20Poly1305::new(&aead_key);
        let wrapped = aead
            .encrypt(&nonce, file_key.expose_secret().as_slice())
            .map_err(|_| {
                age::EncryptError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Encryption failed",
                ))
            })?;

        let ct_base64 = BASE64_STANDARD_NO_PAD.encode(&ct.to_bytes());
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
        if hrp != "AGE-SECRET-KEY-PQ-" {
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

    pub fn to_string(&self) -> String {
        bech32::encode(
            "AGE-SECRET-KEY-PQ-",
            self.seed.expose_secret().to_base32(),
            Variant::Bech32,
        )
        .expect("Encoding failed")
        .to_uppercase()
    }
}

impl AgeIdentity for HybridIdentity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        if stanza.tag != STANZA_TAG {
            return None;
        }
        if stanza.args.len() != 1 {
            return None;
        }
        // Decode base64 ct
        let ct_bytes = BASE64_STANDARD_NO_PAD.decode(&stanza.args[0]).ok()?;
        let ct = Ciphertext::try_from(&ct_bytes[..]).ok()?;
        // Decapsulate
        let sk = DecapsulationKey::from_seed(self.seed.expose_secret());
        let mut ss = sk.decapsulate(&ct).ok()?;
        // Derive AEAD key
        let mut prk = [0u8; 32];
        extract(Algorithm::Sha256, &mut prk, &ss, SUITE_ID).ok()?;
        let mut aead_key_bytes = [0u8; 32];
        expand(Algorithm::Sha256, &mut aead_key_bytes, &prk, PQ_LABEL).ok()?;
        let aead_key = Key::from(aead_key_bytes);
        aead_key_bytes.zeroize();
        // Zero nonce
        let nonce = Nonce::from([0u8; 12]);
        // Decrypt
        let aead = ChaCha20Poly1305::new(&aead_key);
        let decrypted = aead.decrypt(&nonce, &*stanza.body).ok()?;
        if decrypted.len() != 16 {
            return None;
        }
        let decrypted_array: [u8; 16] = decrypted.try_into().ok()?;
        let file_key = FileKey::new(Box::new(decrypted_array));
        ss.zeroize();
        Some(Ok(file_key))
    }

    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, age::DecryptError>> {
        stanzas.iter().find_map(|stanza| self.unwrap_stanza(stanza))
    }
}
