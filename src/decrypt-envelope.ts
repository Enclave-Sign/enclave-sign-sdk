import {
  base64ToBytes,
  base64UrlToBytes,
  decapsulateMlKem,
  decryptAesGcmBytes,
  decryptBytesWithKey,
} from "@enclave/pqc-core";

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
  const sharedSecret = decapsulateMlKem(
    base64ToBytes(input.kemCiphertextB64),
    base64UrlToBytes(input.kemSecretKeyB64),
  );

  const dekBytes = await decryptBytesWithKey({
    ciphertext: base64ToBytes(input.wrappedDekB64),
    key: sharedSecret,
    ivBase64: input.wrappedDekIvB64,
    additionalData: new TextEncoder().encode(
      `${input.subject}:${input.fileName}:${input.recipientEmail.toLowerCase()}`,
    ),
  });

  const dekBase64 = new TextDecoder().decode(dekBytes);

  return decryptAesGcmBytes({
    ciphertext: input.ciphertext,
    keyBase64: dekBase64,
    ivBase64: input.ivBase64,
  });
}

export {
  decryptAesGcmBytes,
  decryptBytesWithKey,
} from "@enclave/pqc-core";
