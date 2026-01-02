use libcrux_hkdf::{expand, extract, Algorithm};

// HPKE Suite IDs for MLKEM768-X25519 + HKDF-SHA256 + ChaCha20-Poly1305
const SUITE_ID: [u8; 10] = [b'H', b'P', b'K', b'E', 0x64, 0x7a, 0x00, 0x01, 0x00, 0x03];

// HPKE-v1 prefix
const HPKE_V1: &[u8] = b"HPKE-v1";

/// Labeled Extract for HKDF-SHA256 (two-stage KDF)
fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &str, ikm: &[u8]) -> [u8; 32] {
    let mut labeled_ikm = Vec::new();
    labeled_ikm.extend_from_slice(HPKE_V1);
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label.as_bytes());
    labeled_ikm.extend_from_slice(ikm);

    let mut prk = [0u8; 32];
    extract(Algorithm::Sha256, &mut prk, &labeled_ikm, salt).unwrap();
    prk
}

/// Labeled Expand for HKDF-SHA256
fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8; 32],
    label: &str,
    info: &[u8],
    length: u16,
) -> Vec<u8> {
    let mut labeled_info = Vec::new();
    labeled_info.extend_from_slice(&(length as u16).to_be_bytes());
    labeled_info.extend_from_slice(HPKE_V1);
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label.as_bytes());
    labeled_info.extend_from_slice(info);

    let mut out = vec![0u8; length as usize];
    expand(Algorithm::Sha256, &mut out, prk, &labeled_info).unwrap();
    out
}

/// Compute HPKE key and base_nonce for base mode (mode 0, no PSK)
pub fn derive_key_and_nonce(shared_secret: &[u8], info: &[u8]) -> ([u8; 32], [u8; 12]) {
    // pskIDHash = labeledExtract(suiteID, salt=null, label="psk_id_hash", ikm=null)
    let psk_id_hash = labeled_extract(&SUITE_ID, b"", "psk_id_hash", b"");

    // infoHash = labeledExtract(suiteID, salt=null, label="info_hash", ikm=info)
    let info_hash = labeled_extract(&SUITE_ID, b"", "info_hash", info);

    // ksContext = mode(0) + pskIDHash + infoHash
    let mut ks_context = Vec::new();
    ks_context.push(0u8); // mode 0
    ks_context.extend_from_slice(&psk_id_hash);
    ks_context.extend_from_slice(&info_hash);

    // secret = labeledExtract(suiteID, salt=shared_secret, label="secret", ikm=null)
    let secret = labeled_extract(&SUITE_ID, shared_secret, "secret", b"");

    // key = labeledExpand(suiteID, secret, "key", ksContext, 32)
    let key_bytes = labeled_expand(&SUITE_ID, &secret, "key", &ks_context, 32);
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    // baseNonce = labeledExpand(suiteID, secret, "base_nonce", ksContext, 12)
    let nonce_bytes = labeled_expand(&SUITE_ID, &secret, "base_nonce", &ks_context, 12);
    let mut base_nonce = [0u8; 12];
    base_nonce.copy_from_slice(&nonce_bytes);

    (key, base_nonce)
}

/// Compute nonce for sequence number (seq=0 for age)
pub fn compute_nonce(base_nonce: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = base_nonce.clone();
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i]; // last 8 bytes
    }
    nonce
}
