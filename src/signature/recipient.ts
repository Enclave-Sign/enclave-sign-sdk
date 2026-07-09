import {
  encodeMlDsaPublicKey,
  encodeMlDsaSignature,
  generateMlDsaKeypair,
  signMlDsa,
} from "@enclave/pqc-primitives";

export type RecipientSignaturePayload = {
  version: 1;
  envelopeId: string;
  recipientId: string;
  recipientEmail: string;
  action: "sign";
  signedAt: string;
};

function assertNonEmpty(value: string, label: string): void {
  if (!value.trim()) {
    throw new Error(`${label} must not be empty`);
  }
}

export function buildRecipientSignature(input: {
  envelopeId: string;
  recipientId: string;
  recipientEmail: string;
}): {
  signature: string;
  signerPublicKey: string;
  signedAt: string;
} {
  assertNonEmpty(input.envelopeId, "Envelope ID");
  assertNonEmpty(input.recipientId, "Recipient ID");
  assertNonEmpty(input.recipientEmail, "Recipient email");

  const keys = generateMlDsaKeypair();
  const signedAt = new Date().toISOString();
  const payload: RecipientSignaturePayload = {
    version: 1,
    envelopeId: input.envelopeId,
    recipientId: input.recipientId,
    recipientEmail: input.recipientEmail.toLowerCase(),
    action: "sign",
    signedAt,
  };

  const message = new TextEncoder().encode(JSON.stringify(payload));
  const signature = signMlDsa(keys.secretKey, message);

  return {
    signature: encodeMlDsaSignature(signature),
    signerPublicKey: encodeMlDsaPublicKey(keys.publicKey),
    signedAt,
  };
}
