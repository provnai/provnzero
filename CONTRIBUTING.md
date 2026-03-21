# Contributing to ProvnZero

First off, thank you for considering contributing to ProvnZero! It's people like you that make ProvnZero a robust, secure, and performant Zero Data Retention proxy.

## Setting up your Local Environment

ProvnZero is a monorepo consisting of two main pieces:
1. `provnzero-proxy`: The core server written in Rust.
2. `provnzero-sdk`: The client SDK written in TypeScript.

### Building the Proxy (Rust)
Ensure you have [Rust](https://rustup.rs/) installed (1.70+ recommended).
```bash
cd provnzero-proxy
cargo build
```

To run the proxy locally for testing:
```bash
cargo run
```
*Note: Set `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `DEEPSEEK_API_KEY` environment variables to enable actual remote LLM inference, otherwise it runs in echo mode.*

### Building the SDK (Node/TypeScript)
Ensure you have Node.js (v18+) installed.
```bash
cd provnzero-sdk
npm install
npm run build
```

## Running Tests

Before submitting a Pull Request, verify that all tests pass.

**Run SDK Tests:**
Ensure the Rust Proxy is running locally on port `3001` before running the SDK test suite.
```bash
cd provnzero-sdk
npm test
```

**Run End-to-End Integration Tests:**
From the root of the repository:
```bash
python test_suite.py
python benchmark.py
```

## Pull Request Process

1. Fork the repo and create your branch from `main`.
2. Ensure any new Rust code is cleanly formatted with `cargo fmt`.
3. Check for obvious lints with `cargo clippy`. We strive for 0 warnings!
4. If you've modified the SDK, ensure no new TypeScript warnings were introduced via `npm run build`.
5. Issue a Pull Request with a clear description of your changes.

## Code of Conduct
Please be respectful and patient with other contributors. We prioritize a welcoming environment for developers focusing on high-assurance security engineering.
