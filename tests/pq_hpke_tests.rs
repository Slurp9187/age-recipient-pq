#[cfg(test)]
mod tests {
    use age_xwing::hpke_pq::*;

    #[test]
    fn test_suite_id_matches_go() {
        // From known HPKE suite or age-go test
        let expected = vec![0x48, 0x50, 0x4b, 0x45, 0x64, 0x7a, 0x00, 0x01, 0x00, 0x03]; // "HPKE" + 0x647a_BE + 0x0001_BE + 0x0003_BE
        let result = suite_id(KEM_ID, KDF_ID, AEAD_ID);
        assert_eq!(result, expected);
    }
}
