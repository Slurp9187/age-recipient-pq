use age::{Decryptor, Identity};
use age_pq_native_rs::pq::HybridIdentity;
use std::fs;
use std::io::Read;

#[test]
fn test_decrypt_lorem_encrypted_with_age_cli() {
    // Read the encrypted file (lorem.txt.age from age-cli)
    let encrypted_data =
        fs::read("tests/data/lorem.txt.age").expect("Failed to read tests/data/lorem.txt.age");

    // Read the original plaintext for comparison
    let original_plaintext =
        fs::read("tests/data/lorem.txt").expect("Failed to read tests/data/lorem.txt");

    // Read the secret key from age-cli (corresponds to age_go_recipient.key public key)
    let mut identity_str = fs::read_to_string("tests/data/age_go_identity.key")
        .expect("Failed to read tests/data/age_go_identity.key");
    identity_str = identity_str.trim().to_string();

    // Parse the identity
    let identity = HybridIdentity::parse(&identity_str).expect("Failed to parse identity");

    // Decrypt using age-xwing
    let decryptor = Decryptor::new(&encrypted_data[..]).expect("Failed to create decryptor");
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn Identity))
        .expect("Failed to start decryption");

    let mut decrypted = Vec::new();
    reader
        .read_to_end(&mut decrypted)
        .expect("Failed to read decrypted data");

    // Assert it matches the original
    assert_eq!(decrypted, original_plaintext);
}
