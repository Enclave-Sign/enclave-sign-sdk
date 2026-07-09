import {
  base64ToBytes,
  base64UrlToBytes,
  decapsulateMlKem,
  decryptAesGcmBytes,
  decryptBytesWithKey,
} from "@enclave/pqc-primitives";

function assertNonEmpty(value: string, label: string): void {
  if (!value.trim()) {
    throw new Error(`${label} must not be empty`);
  }
}

export async function decryptEnvelopeDocument(input: {
  ciphertext: Uint8Array;
  ivBase64: string;
  kemCiphertextB64: string;
  kemSecretKeyB64: string;
  wrappedDekB64: string;
  wrappedDekIvB64: string;
  subject: string;
  fileName: string;
  recipientEmail: string;
}): Promise<Uint8Array> {
  assertNonEmpty(input.ivBase64, "Document IV");
  assertNonEmpty(input.kemCiphertextB64, "KEM ciphertext");
  assertNonEmpty(input.kemSecretKeyB64, "KEM secret key");
  assertNonEmpty(input.wrappedDekB64, "Wrapped DEK");
  assertNonEmpty(input.wrappedDekIvB64, "Wrapped DEK IV");
  assertNonEmpty(input.subject, "Envelope subject");
  assertNonEmpty(input.fileName, "Document file name");
  assertNonEmpty(input.recipientEmail, "Recipient email");

  if (input.ciphertext.length === 0) {
    throw new Error("Ciphertext must not be empty");
  }

  const sharedSecret = decapsulateMlKem(
    base64ToBytes(input.kemCiphertextB64),
    base64UrlToBytes(input.kemSecretKeyB64),
  );

  const dekBytes = await decryptBytesWithKey({
    ciphertext: base64ToBytes(input.wrappedDekB64),
    key: sharedSecret,
    ivBase64: input.wrappedDekIvB64,
    additionalData: new TextEncoder().encode(
      `${input.subject.trim()}:${input.fileName}:${input.recipientEmail.toLowerCase()}`,
    ),
  });

  const dekBase64 = new TextDecoder().decode(dekBytes);

  return decryptAesGcmBytes({
    ciphertext: input.ciphertext,
    keyBase64: dekBase64,
    ivBase64: input.ivBase64,
  });
}
