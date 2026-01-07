// src/hpke_pq.rs

//! Age-specific HPKE utilities using pq_xwing_hpke primitives.
//! Hardcoded for the post-quantum suite: XWing768x25519 (KEM ID 0x647a),
//! HKDF-SHA256 (KDF ID 0x0001), ChaCha20Poly1305 (AEAD ID 0x0003, base mode 0).

use pq_xwing_hpke::{kdf::new_kdf, Error};
use std::io::Error as IoError;

pub const KEM_ID: u16 = 0x647a; // XWing768X25519 from pq_xwing_hpke::kem
pub const KDF_ID: u16 = 0x0001; // HKDF-SHA256
pub const AEAD_ID: u16 = 0x0003; // ChaCha20Poly1305 (determines key=32, nonce=12 sizes)
const MODE: u8 = 0; // Base mode (no PSK)

/// Derives the AEAD key and base_nonce from a KEM shared secret for Age's PQ suite.
/// Implements RFC 9180 two-stage KDF (HKDF-SHA256, mode 0).
/// Errors map to age::EncryptError/DecryptError in callers.
/// Generates the HPKE suite ID from KEM, KDF, and AEAD IDs.
pub fn suite_id(kem_id: u16, kdf_id: u16, aead_id: u16) -> Vec<u8> {
    let mut sid = Vec::with_capacity(10);
    sid.extend_from_slice(b"HPKE");
    sid.extend_from_slice(&kem_id.to_be_bytes());
    sid.extend_from_slice(&kdf_id.to_be_bytes());
    sid.extend_from_slice(&aead_id.to_be_bytes());
    sid
}

pub fn derive_key_and_nonce(
    shared_secret: &[u8],
    info: &[u8], // Age label, e.g., b"age-encryption.org/mlkem768x25519"
) -> Result<([u8; 32], [u8; 12]), Error> {
    let sid = suite_id(KEM_ID, KDF_ID, AEAD_ID);
    let kdf = new_kdf(KDF_ID)?; // HKDF-SHA256 as Box<dyn Kdf>

    // Stage 1: Hashes (empty salt)
    let psk_id_hash = kdf.labeled_extract(&sid, None, "psk_id_hash", &[])?;
    let info_hash = kdf.labeled_extract(&sid, None, "info_hash", info)?;

    // ks_context = mode || psk_id_hash || info_hash
    let mut ks_context = Vec::new();
    ks_context.push(MODE);
    ks_context.extend_from_slice(&psk_id_hash);
    ks_context.extend_from_slice(&info_hash);

    // Stage 2: Extract PRK from shared_secret
    let secret = kdf.labeled_extract(&sid, Some(shared_secret), "secret", &[])?;

    // Expand to key (32 bytes for ChaCha20)
    let key_vec = kdf.labeled_expand(&sid, &secret, "key", &ks_context, 32u16)?;
    if key_vec.len() != 32 {
        return Err(Error::InvalidLength);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_vec);

    // Expand to base_nonce (12 bytes for ChaCha20)
    let nonce_vec = kdf.labeled_expand(&sid, &secret, "base_nonce", &ks_context, 12u16)?;
    if nonce_vec.len() != 12 {
        return Err(Error::InvalidLength);
    }
    let mut base_nonce = [0u8; 12];
    base_nonce.copy_from_slice(&nonce_vec);

    Ok((key, base_nonce))
}

/// Age-specific nonce computation (seq=0, so nonce == base_nonce).
/// Reuses pq_xwing_hpke::compute_nonce if available; otherwise, inline here.
pub fn compute_nonce(base_nonce: &[u8; 12], seq: u64) -> [u8; 12] {
    // If pq_xwing_hpke::compute_nonce exists, call it:
    // pq_xwing_hpke::compute_nonce(base_nonce, seq)
    // Otherwise, inline (identical to HPKE spec):
    let mut nonce = *base_nonce;
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    nonce
}

// Helper to map HPKE errors to Age's (call in pq.rs)
pub fn map_hpke_error(e: Error) -> age::EncryptError {
    age::EncryptError::Io(IoError::other(format!("HPKE error: {:?}", e)))
}

pub fn map_hpke_decrypt_error(e: Error) -> age::DecryptError {
    age::DecryptError::Io(IoError::other(format!("HPKE error: {:?}", e)))
}
