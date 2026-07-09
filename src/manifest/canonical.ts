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
    subject: input.subject.trim(),
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
