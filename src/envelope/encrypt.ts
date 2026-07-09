import {
  bytesToBase64,
  bytesToBase64Url,
  DOCUMENT_ENCRYPTION_ALGORITHM,
  encryptAesGcmBytes,
  encryptBytesWithKey,
  encapsulateMlKem,
  encodeMlDsaPublicKey,
  encodeMlDsaSignature,
  encodeMlKemPublicKey,
  encodeMlKemSecretKey,
  generateMlKemKeypair,
  ML_DSA_ALGORITHM,
  ML_KEM_ALGORITHM,
  shake256Bytes,
  signMlDsa,
} from "@enclave/pqc-primitives";

import { buildCanonicalManifest } from "../manifest/canonical.js";
import type {
  EncryptedDocumentInput,
  EncryptedDocumentPackage,
  EncryptedEnvelopePackage,
  EncryptedRecipientPackage,
  RecipientInput,
} from "./types.js";

export { DOCUMENT_ENCRYPTION_ALGORITHM, ML_DSA_ALGORITHM, ML_KEM_ALGORITHM };
export type {
  EncryptedDocumentInput,
  EncryptedDocumentPackage,
  EncryptedEnvelopePackage,
  EncryptedRecipientPackage,
  RecipientInput,
} from "./types.js";

function assertNonEmpty(value: string, label: string): void {
  if (!value.trim()) {
    throw new Error(`${label} must not be empty`);
  }
}

function hashDocumentContent(plaintext: Uint8Array): string {
  return bytesToBase64Url(shake256Bytes(plaintext));
}

export async function encryptEnvelopePackage(input: {
  subject: string;
  documents: EncryptedDocumentInput[];
  recipients: RecipientInput[];
  senderSecretKey: Uint8Array;
  senderPublicKey: Uint8Array;
}): Promise<EncryptedEnvelopePackage> {
  assertNonEmpty(input.subject, "Envelope subject");

  if (input.documents.length === 0) {
    throw new Error("At least one document is required");
  }
  if (input.recipients.length === 0) {
    throw new Error("At least one recipient is required");
  }
  if (input.senderSecretKey.length === 0 || input.senderPublicKey.length === 0) {
    throw new Error("Sender signing keys must not be empty");
  }

  const encryptedDocuments: EncryptedDocumentPackage[] = [];
  const documentDeks = new Map<string, { dekBase64: string; ivBase64: string }>();

  for (const document of input.documents) {
    assertNonEmpty(document.fileName, "Document file name");
    if (document.plaintext.length === 0) {
      throw new Error(`Document ${document.fileName} must not be empty`);
    }

    const encrypted = await encryptAesGcmBytes({ plaintext: document.plaintext });
    documentDeks.set(document.fileName, {
      dekBase64: encrypted.keyBase64,
      ivBase64: encrypted.ivBase64,
    });

    encryptedDocuments.push({
      fileName: document.fileName,
      contentType: document.contentType,
      ciphertext: encrypted.ciphertext,
      contentHash: hashDocumentContent(document.plaintext),
      ivBase64: encrypted.ivBase64,
      byteSize: document.plaintext.byteLength,
    });
  }

  const encryptedRecipients: EncryptedRecipientPackage[] = [];

  for (const recipient of input.recipients) {
    assertNonEmpty(recipient.email, "Recipient email");

    const kemKeypair = generateMlKemKeypair();
    const documentKeys: EncryptedRecipientPackage["documentKeys"] = [];
    const normalizedEmail = recipient.email.trim().toLowerCase();

    for (const document of input.documents) {
      const dek = documentDeks.get(document.fileName);
      if (!dek) {
        throw new Error(`Missing DEK for document ${document.fileName}`);
      }

      const { cipherText, sharedSecret } = encapsulateMlKem(kemKeypair.publicKey);
      const wrapped = await encryptBytesWithKey({
        plaintext: new TextEncoder().encode(dek.dekBase64),
        key: sharedSecret,
        additionalData: new TextEncoder().encode(
          `${input.subject.trim()}:${document.fileName}:${normalizedEmail}`,
        ),
      });

      documentKeys.push({
        fileName: document.fileName,
        kemCiphertext: bytesToBase64(cipherText),
        wrappedDekB64: bytesToBase64(wrapped.ciphertext),
        wrappedDekIvB64: wrapped.ivBase64,
      });
    }

    encryptedRecipients.push({
      clientId: recipient.clientId,
      email: recipient.email.trim(),
      name: recipient.name.trim(),
      kemPublicKey: encodeMlKemPublicKey(kemKeypair.publicKey),
      kemSecretKey: encodeMlKemSecretKey(kemKeypair.secretKey),
      documentKeys,
    });
  }

  const manifest = buildCanonicalManifest({
    subject: input.subject.trim(),
    documents: encryptedDocuments,
    recipients: encryptedRecipients,
  });
  const manifestBytes = new TextEncoder().encode(JSON.stringify(manifest));
  const manifestSignature = signMlDsa(input.senderSecretKey, manifestBytes);

  return {
    subject: input.subject.trim(),
    manifestAlgorithm: ML_DSA_ALGORITHM,
    manifestSignature: encodeMlDsaSignature(manifestSignature),
    senderPublicKey: encodeMlDsaPublicKey(input.senderPublicKey),
    encryptionMetadata: {
      version: 1,
      kem: ML_KEM_ALGORITHM,
      documentAlgorithm: DOCUMENT_ENCRYPTION_ALGORITHM,
      manifest,
    },
    documents: encryptedDocuments,
    recipients: encryptedRecipients,
  };
}
