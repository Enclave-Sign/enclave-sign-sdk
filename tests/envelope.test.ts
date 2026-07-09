import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { decryptEnvelopeDocument } from "../src/decrypt/index.js";
import { encryptEnvelopePackage } from "../src/envelope/index.js";
import { buildCanonicalManifest } from "../src/manifest/index.js";
import {
  buildRecipientSignature,
  verifyEnvelopeManifest,
  verifyRecipientSignature,
} from "../src/signature/index.js";
import { generateMlDsaKeypair } from "@enclave/pqc-primitives";
import { hashSigningToken } from "../src/tokens/index.js";

describe("buildCanonicalManifest", () => {
  it("normalizes subject and recipient email", () => {
    const manifest = buildCanonicalManifest({
      subject: "  Test Subject  ",
      documents: [
        { fileName: "a.pdf", contentHash: "hash", byteSize: 10 },
      ],
      recipients: [{ email: "User@Example.com", kemPublicKey: "pk" }],
    });

    assert.equal(manifest.subject, "Test Subject");
    assert.deepEqual(manifest.recipients, [
      { email: "user@example.com", kemPublicKey: "pk" },
    ]);
  });
});

describe("encryptEnvelopePackage", () => {
  it("round-trips a document for one recipient", async () => {
    const sender = generateMlDsaKeypair();
    const plaintext = new TextEncoder().encode("signed document");

    const encrypted = await encryptEnvelopePackage({
      subject: "Contract",
      documents: [
        {
          fileName: "contract.pdf",
          contentType: "application/pdf",
          plaintext,
        },
      ],
      recipients: [
        {
          clientId: "client-1",
          name: "Recipient",
          email: "recipient@example.com",
        },
      ],
      senderSecretKey: sender.secretKey,
      senderPublicKey: sender.publicKey,
    });

    const recipient = encrypted.recipients[0];
    assert.ok(recipient);
    const documentKey = recipient.documentKeys[0];
    assert.ok(documentKey);
    const document = encrypted.documents[0];
    assert.ok(document);

    const decrypted = await decryptEnvelopeDocument({
      ciphertext: document.ciphertext,
      ivBase64: document.ivBase64,
      kemCiphertextB64: documentKey.kemCiphertext,
      kemSecretKeyB64: recipient.kemSecretKey,
      wrappedDekB64: documentKey.wrappedDekB64,
      wrappedDekIvB64: documentKey.wrappedDekIvB64,
      subject: encrypted.subject,
      fileName: document.fileName,
      recipientEmail: recipient.email,
    });

    assert.deepEqual(decrypted, plaintext);

    assert.equal(
      verifyEnvelopeManifest({
        subject: encrypted.subject,
        manifestSignature: encrypted.manifestSignature,
        senderPublicKey: encrypted.senderPublicKey,
        documents: encrypted.documents.map((doc) => ({
          fileName: doc.fileName,
          contentHash: doc.contentHash,
          byteSize: doc.byteSize,
        })),
        recipients: encrypted.recipients.map((r) => ({
          email: r.email,
          kemPublicKey: r.kemPublicKey,
        })),
      }),
      true,
    );
  });
});

describe("recipient signature", () => {
  it("signs and verifies", () => {
    const signed = buildRecipientSignature({
      envelopeId: "env-1",
      recipientId: "rec-1",
      recipientEmail: "signer@example.com",
    });

    assert.equal(
      verifyRecipientSignature({
        envelopeId: "env-1",
        recipientId: "rec-1",
        recipientEmail: "signer@example.com",
        signedAt: signed.signedAt,
        signature: signed.signature,
        signerPublicKey: signed.signerPublicKey,
      }),
      true,
    );
  });
});

describe("hashSigningToken", () => {
  it("returns deterministic SHAKE256 hex", () => {
    const first = hashSigningToken("token-value");
    const second = hashSigningToken("token-value");
    assert.equal(first, second);
    assert.match(first, /^[0-9a-f]{64}$/);
  });
});
