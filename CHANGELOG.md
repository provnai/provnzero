# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-beta] - 2026-03-20

### Added
- **RFC 9180 HPKE Integration**: Migrated from custom KDF/encryption to standard HPKE (X25519-HKDF-SHA256-AES256GCM).
- **Rate Limiting**: Added `tower-governor` based rate limiting to prevent API abuse.
- **Graceful Shutdown**: Implemented `SIGINT`/`SIGTERM` handlers for safe cleanup and memory zeroization.
- **Test Suite**: 12-point automated Python integration test suite.
- **Documentation**: New root README and updated SDK documentation.

### Changed
- Refactored `provnzero-proxy` to use standard `hpke` crate.
- Rewrote `provnzero-sdk` to use `@noble` primitives for HPKE Base mode.
- Optimized `SecureBuffer` for zero-allocation reuse where possible.

### Removed
- Legacy custom ECDH key derivation logic.
- Defunct `Crypto` struct in `crypto.rs`.

## [0.1.0] - 2026-03-15

### Added
- Initial prototype of the ZDR Proxy.
- Support for OpenAI and Anthropic providers.
- Basic X25519 + AES-GCM implementation.
- Ed25519 VEX receipt signing.
