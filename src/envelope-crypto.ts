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
} from "@enclave/pqc-core";

export { DOCUMENT_ENCRYPTION_ALGORITHM, ML_DSA_ALGORITHM, ML_KEM_ALGORITHM };

export type RecipientInput = {
  clientId: string;
  name: string;
  email: string;
};

export type EncryptedDocumentInput = {
  fileName: string;
  contentType: string;
  plaintext: Uint8Array;
};

export type EncryptedRecipientPackage = {
  clientId: string;
  email: string;
  name: string;
  kemPublicKey: string;
  kemSecretKey: string;
  documentKeys: Array<{
    fileName: string;
    kemCiphertext: string;
    wrappedDekB64: string;
    wrappedDekIvB64: string;
  }>;
};

export type EncryptedDocumentPackage = {
  fileName: string;
  contentType: string;
  ciphertext: Uint8Array;
  contentHash: string;
  ivBase64: string;
  byteSize: number;
};

export type EncryptedEnvelopePackage = {
  subject: string;
  manifestAlgorithm: typeof ML_DSA_ALGORITHM;
  manifestSignature: string;
  senderPublicKey: string;
  encryptionMetadata: {
    version: 1;
    kem: typeof ML_KEM_ALGORITHM;
    documentAlgorithm: typeof DOCUMENT_ENCRYPTION_ALGORITHM;
    manifest: Record<string, unknown>;
  };
  documents: EncryptedDocumentPackage[];
  recipients: EncryptedRecipientPackage[];
};

function hashDocumentContent(plaintext: Uint8Array): string {
  return bytesToBase64Url(shake256Bytes(plaintext));
}

function buildManifest(input: {
  subject: string;
  documents: EncryptedDocumentPackage[];
  recipients: EncryptedRecipientPackage[];
}): Record<string, unknown> {
  return {
    version: 1,
    subject: input.subject,
    documents: input.documents.map((document) => ({
      fileName: document.fileName,
      contentHash: document.contentHash,
      byteSize: document.byteSize,
    })),
    recipients: input.recipients.map((recipient) => ({
      email: recipient.email.toLowerCase(),
      kemPublicKey: recipient.kemPublicKey,
    })),
  };
}

export async function encryptEnvelopePackage(input: {
  subject: string;
  documents: EncryptedDocumentInput[];
  recipients: RecipientInput[];
  senderSecretKey: Uint8Array;
  senderPublicKey: Uint8Array;
}): Promise<EncryptedEnvelopePackage> {
  const encryptedDocuments: EncryptedDocumentPackage[] = [];
  const documentDeks = new Map<string, { dekBase64: string; ivBase64: string }>();

  for (const document of input.documents) {
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
    const kemKeypair = generateMlKemKeypair();
    const documentKeys: EncryptedRecipientPackage["documentKeys"] = [];

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
          `${input.subject}:${document.fileName}:${recipient.email.toLowerCase()}`,
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

  const manifest = buildManifest({
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
