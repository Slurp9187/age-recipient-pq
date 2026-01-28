# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.1] - 2026-01-09

### Added
- Initial release of `age-recipient-pq`, a Rust library providing post-quantum hybrid recipients and identities compatible with the age encryption format.
- Implementation of ML-KEM-768 combined with X25519 for quantum-resistant encryption.
- Key generation, serialization, and parsing APIs for `HybridRecipient` and `HybridIdentity`.
- Full compatibility with age file format and Rage conventions (using `secrecy` crate for secret handling).
- Comprehensive test suite:
  - Unit tests for key operations, encryption/decryption roundtrips, and serialization.
  - Low-level PQ stanza wrapping/unwrapping and error handling tests.
  - CLI interoperability tests requiring age CLI >= v1.3.0 (skips gracefully if unavailable).
- Test data files in `tests/data/` for interop verification (lorem.txt, encrypted, and PQ keys).
- Shared test utilities in `tests/common.rs` for version checks and skips.
- README.md with installation, usage, security notes, and testing instructions.
- CHANGELOG.md for tracking changes.
- Custom Bech32 checksum implementation with extended code length (4096) to support encoding of PQ public keys longer than standard limits.

### Security
- Post-quantum security via NIST-standardized ML-KEM-768.
- Hybrid design with X25519 for efficiency and backward compatibility.
- Warning: Not independently audited; use at own risk.

### Compatibility
- Requires Rust and age library dependencies.
- CLI interop tests need age CLI >= v1.3.0 installed.
- Bech32 handling uses `rust-bitcoin/rust-bech32` for keys exceeding standard length limits.
