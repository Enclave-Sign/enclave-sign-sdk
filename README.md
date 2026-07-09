# @enclave/sign-sdk

Post-quantum document signing SDK for **Enclave Sign**. Open-source (AGPL-3.0-or-later) cryptography built on [`@enclave/pqc-primitives`](https://github.com/Enclave-Inc/enclave-pqc-primitives).

## Layout

```text
src/
  envelope/         Encrypt envelope packages
  decrypt/          Decrypt recipient documents
  keys/             Sender ML-DSA key persistence
  tokens/           Signing-link tokens
  signature/        Recipient signatures + verification
  manifest/         Canonical manifest builder
tests/              Round-trip tests
```

## Enclave Sign repos

| Repo | Org | Role |
|------|-----|------|
| **enclave-sign** | Enclave-Sign | Web app (Next.js) |
| **enclave-sign-sdk** | Enclave-Sign | This package — AGPL crypto |
| **enclave-sign-api** | Enclave-Encrypt | Supabase edge functions + Sign migrations |
| **enclave-pqc-primitives** | Enclave-Inc | Shared NIST PQ primitives |

## Install

```bash
npm install @enclave/sign-sdk @enclave/pqc-primitives
```

Monorepo sibling (local dev):

```json
"@enclave/pqc-primitives": "file:../../Enclave-Inc/enclave-pqc-primitives"
```

## Usage

```ts
import {
  encryptEnvelopePackage,
  decryptEnvelopeDocument,
  getOrCreateSenderSigningKeys,
} from "@enclave/sign-sdk";
```

## Development

```bash
cd ../../Enclave-Inc/enclave-pqc-primitives && npm run build
npm install
npm run typecheck
npm test
npm run build
```

## License

AGPL-3.0-or-later — see [LICENSE](./LICENSE). Contact Enclave for commercial licensing.
