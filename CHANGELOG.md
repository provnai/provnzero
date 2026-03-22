# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0-beta.1] - 2026-03-22

### Added
- **Modern Chat API Support**: Migrated OpenAI, Anthropic, and DeepSeek to modern Chat Completion endpoints.
- **Enhanced Rate Limiting**: Added strict per-endpoint rate limiting for encryption key initialization.
- **Monorepo Hygiene**: Optimized `.gitignore` and build scripts for root-level Cargo workspaces.

### Fixed
- **OpenAI 404 Errors**: Resolved compatibility issues with modern LLM models by switching from `/completions` to `/chat/completions`.
- **Nixpacks Deployment**: Fixed static linking issues for `musl` environments by migrating to `rustls-tls`.
- **Memory Safety**: Reinforcements to `Zeroize` logic for intermediate prompt buffers.

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
