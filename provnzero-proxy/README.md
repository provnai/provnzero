# ProvnZero Proxy

[![Crates.io](https://img.shields.io/badge/crates.io-v1.0.0--beta-orange.svg)]()
[![Rust](https://img.shields.io/badge/rust-v1.75+-brown.svg)]()

The Rust-based ZDR proxy for the ProvnZero project. Built with Axum, it routes encrypted LLM prompts without storing or logging the plaintext.

## Features

- **RFC 9180 HPKE**: Standard-compliant Hybrid Public Key Encryption (`X25519-HKDF-SHA256-AES256GCM`).
- **Axum**: Async HTTP routing.
- **Rate Limiting**: Request throttling via `tower-governor`.
- **Graceful Shutdown**: Parity and memory zeroization on SIGINT/SIGTERM.
- **VEX Proofs**: Ed25519-signed receipts.

## Security Architecture

ProvnZero enforces **Zero Data Retention (ZDR)** using Rust's memory safety guarantees.

- **Ephemeral Context**: Every request uses a single-use HPKE session.
- **Self-Pruning Memory**: Expired ephemeral keys are automatically pruned.
- **No Persistence**: Zero database or disk dependencies.

## Getting Started

### Prerequisites
- Rust 1.75+
- (Optional) WSL for Linux-parity testing

### Run Locally
```bash
# Clone the repository
cd provnzero-proxy

# Build for release
cargo build --release

# Run with environment variables
OPENAI_API_KEY=sk-xxxx cargo run
```

### Deployment (Railway)
ProvnZero is pre-configured for Railway deployment:
```bash
railway up
```

## API Specification

### 1. Initialize Session
`POST /v1/init`

Begins an HPKE session.
**Response**:
```json
{
  "pubkey": "base64-X25519-server-public-key",
  "key_id": "unique-session-id"
}
```

### 2. Submit Encrypted Completion
`POST /v1/completions`

Submits an HPKE-sealed prompt for processing.
**Request**:
```json
{
  "key_id": "unique-session-id",
  "encapsulated_key": "base64-hpke-encap-key",
  "ciphertext": "base64-hpke-ciphertext",
  "provider": "openai"
}
```

## Configuration

| Variable | Default | Description |
| :--- | :--- | :--- |
| `OPENAI_API_KEY` | - | Required for OpenAI support |
| `OPENAI_BASE_URL`| `https://api.openai.com/v1` | Override to support Groq, Ollama, OpenRouter, etc. |
| `ANTHROPIC_API_KEY` | - | Required for Anthropic support |
| `DEEPSEEK_API_KEY` | - | Required for DeepSeek support |
| `PORT` | 3001 | Listen port |

## License
Apache 2.0
