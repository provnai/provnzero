# ProvnZero SDK (TypeScript)

[![npm version](https://img.shields.io/npm/v/provnzero-sdk.svg)](https://www.npmjs.com/package/provnzero-sdk)
[![TypeScript](https://img.shields.io/badge/typescript-v5.0+-blue.svg)]()

The TypeScript/Node.js SDK for the ProvnZero proxy. It handles HPKE sealing, key exchange, and VEX receipt parsing.

## Features

- **Standard HPKE**: Implements HPKE Base mode via `@noble`.
- **Async API**: Clean Promise-based interface.
- **Zero-Dependency Core**: Lightweight footprint.
- **Client-Side Sealing**: Manages ephemeral keypairs and session isolation automatically.

## Installation

```bash
npm install provnzero-sdk
```

## Basic Usage

```typescript
import { ProvnZeroClient } from 'provnzero-sdk';

const client = new ProvnZeroClient('http://localhost:3001');

async function askSecurely() {
  try {
    const response = await client.send({
      prompt: "What is the capital of France?",
      provider: "openai"
    });

    console.log("AI Response:", response.text);
    console.log("VEX Receipt:", response.receipt);
  } catch (err) {
    console.error("Secure call failed:", err);
  }
}

askSecurely();
```

## Security

The SDK performs **client-side sealing** before the prompt ever leaves your memory.
1. It requests the server's public key.
2. It generates a fresh ephemeral keypair.
3. It performs HPKE `setup_sender` to derive a secret key.
4. It seals the prompt using AES-256-GCM.
5. Only the **ciphertext** and **encapsulated key** are sent to the proxy.

## Development

```bash
# Install dependencies
npm install

# Build the SDK
npm run build

# Run tests
npm test
```

## License
Apache 2.0
