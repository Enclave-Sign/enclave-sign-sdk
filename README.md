# @enclave/sign-sdk

Post-quantum document signing SDK for **Enclave Sign**. Open-source (AGPL-3.0-or-later) cryptography built on [`@enclave/pqc-core`](https://github.com/Enclave-Encrypt/enclave-pqc-core).

## Enclave Sign repos

| Repo | Org | Role |
|------|-----|------|
| **enclave-sign** | Enclave-Sign | Web app (Next.js) |
| **enclave-sign-sdk** | Enclave-Sign | This package — AGPL crypto |
| **enclave-sign-api** | Enclave-Encrypt | Supabase edge functions + Sign migrations |
| **enclave-pqc-core** | Enclave-Encrypt | Shared NIST PQ primitives |

App and API both depend on this SDK so crypto can be audited in one place.

## Install

```bash
npm install @enclave/sign-sdk @enclave/pqc-core
```

Monorepo sibling (local dev):

```json
"@enclave/pqc-core": "file:../../Enclave-Encrypt/enclave-pqc-core"
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
npm install
npm run build
```

## License

AGPL-3.0-or-later — contact Enclave for commercial licensing.
