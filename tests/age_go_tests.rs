use age::{Encryptor, Recipient};
use age_xwing::pq::HybridRecipient;
use std::fs;
use std::io::{Read, Write};

#[test]
fn generate_keys_and_encrypt() {
    let (recipient, identity) = HybridRecipient::generate();

    // Save recipient to recipient.key
    fs::write("recipient.key", recipient.to_string()).expect("Failed to write recipient");

    // Save identity to identity.key
    fs::write("identity.key", identity.to_string()).expect("Failed to write identity");

    // Encrypt some plaintext to age_xwing.age
    let plaintext = b"This is a test message for age-xwing encryption.";
    let encryptor =
        Encryptor::with_recipients(std::iter::once(&recipient as &dyn Recipient)).unwrap();
    let mut file = fs::File::create("age_xwing.age").unwrap();
    let mut writer = encryptor.wrap_output(&mut file).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
}

#[test]
fn encrypt_and_decrypt_roundtrip() {
    let (recipient, identity) = HybridRecipient::generate();

    let plaintext = b"This is a test message for age-xwing encryption.";

    // Encrypt
    let encryptor =
        Encryptor::with_recipients(std::iter::once(&recipient as &dyn Recipient)).unwrap();
    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();

    // Decrypt
    let decryptor = age::Decryptor::new(&encrypted[..]).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .unwrap();
    let mut decrypted = Vec::new();
    reader.read_to_end(&mut decrypted).unwrap();

    assert_eq!(decrypted, plaintext);
}
