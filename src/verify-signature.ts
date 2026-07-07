import {
  base64UrlToBytes,
  verifyMlDsa,
} from "@enclave/pqc-core";

import type { RecipientSignaturePayload } from "./recipient-signature.js";

export type ManifestDocumentInput = {
  fileName: string;
  contentHash: string;
  byteSize: number;
};

export type ManifestRecipientInput = {
  email: string;
  kemPublicKey: string;
};

export function buildCanonicalManifest(input: {
  subject: string;
  documents: ManifestDocumentInput[];
  recipients: ManifestRecipientInput[];
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

export function verifyEnvelopeManifest(input: {
  subject: string;
  manifestSignature: string;
  senderPublicKey: string;
  documents: ManifestDocumentInput[];
  recipients: ManifestRecipientInput[];
}): boolean {
  if (!input.manifestSignature?.trim() || !input.senderPublicKey?.trim()) {
    return false;
  }

  try {
    const manifest = buildCanonicalManifest({
      subject: input.subject.trim(),
      documents: input.documents,
      recipients: input.recipients,
    });
    const manifestBytes = new TextEncoder().encode(JSON.stringify(manifest));
    return verifyMlDsa(
      base64UrlToBytes(input.senderPublicKey),
      manifestBytes,
      base64UrlToBytes(input.manifestSignature),
    );
  } catch {
    return false;
  }
}

export function verifyRecipientSignature(input: {
  envelopeId: string;
  recipientId: string;
  recipientEmail: string;
  signedAt: string;
  signature: string;
  signerPublicKey: string;
}): boolean {
  if (
    !input.signature?.trim() ||
    !input.signerPublicKey?.trim() ||
    !input.signedAt?.trim()
  ) {
    return false;
  }

  try {
    const payload: RecipientSignaturePayload = {
      version: 1,
      envelopeId: input.envelopeId,
      recipientId: input.recipientId,
      recipientEmail: input.recipientEmail.toLowerCase(),
      action: "sign",
      signedAt: input.signedAt,
    };
    const message = new TextEncoder().encode(JSON.stringify(payload));
    return verifyMlDsa(
      base64UrlToBytes(input.signerPublicKey),
      message,
      base64UrlToBytes(input.signature),
    );
  } catch {
    return false;
  }
}
