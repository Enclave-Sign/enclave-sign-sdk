# AGENTS.md — enclave-sign-sdk

Post-quantum document signing cryptography for **Enclave Sign**.

## Layout

```text
src/
  envelope/         Encrypt envelope packages (ML-KEM + AES-GCM + ML-DSA manifest)
  decrypt/          Decrypt recipient documents
  keys/             Sender ML-DSA key persistence (browser localStorage)
  tokens/           Opaque signing-link tokens
  signature/        Recipient signatures + manifest verification
  manifest/         Canonical manifest builder (shared by encrypt/verify)
  *.ts              Deno vendor compatibility shims (re-export modules)
tests/              Round-trip and verification tests
```

## Commands

```bash
npm run typecheck
npm test
npm run build
```

Build `@enclave/pqc-primitives` first:

```bash
cd ../../Enclave-Inc/enclave-pqc-primitives && npm run build
```

## Rules

1. All crypto via `@enclave/pqc-primitives` — no direct `@noble/*` imports.
2. Algorithm IDs from primitives registry constants, not hardcoded strings.
3. `hashSigningToken` uses SHAKE256 via primitives (`hashUtf8`), not SHA-256.
4. Run `npm test` and `npm run build` before finishing changes.

## Dependencies

| Package | Role |
|---------|------|
| `@enclave/pqc-primitives` | ML-KEM, ML-DSA, AES-GCM, SHAKE256, encoding |

Local dev path: `file:../../Enclave-Inc/enclave-pqc-primitives`
