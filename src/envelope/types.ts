import {
  DOCUMENT_ENCRYPTION_ALGORITHM,
  ML_DSA_ALGORITHM,
  ML_KEM_ALGORITHM,
} from "@enclave/pqc-primitives";

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
