import {
  encodeMlDsaPublicKey,
  encodeMlDsaSignature,
  generateMlDsaKeypair,
  signMlDsa,
} from "@enclave/pqc-core";

export type RecipientSignaturePayload = {
  version: 1;
  envelopeId: string;
  recipientId: string;
  recipientEmail: string;
  action: "sign";
  signedAt: string;
};

export function buildRecipientSignature(input: {
  envelopeId: string;
  recipientId: string;
  recipientEmail: string;
}): {
  signature: string;
  signerPublicKey: string;
  signedAt: string;
} {
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
