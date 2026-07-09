import {
  base64UrlToBytes,
  bytesToBase64Url,
  encodeMlDsaPublicKey,
  generateMlDsaKeypair,
  type MlDsaKeypair,
} from "@enclave/pqc-primitives";

const STORAGE_KEY = "enclave.sign.sender-mldsa-v1";

type StoredSenderKeys = {
  publicKey: string;
  secretKey: string;
};

function readStoredKeys(): StoredSenderKeys | null {
  if (typeof localStorage === "undefined") {
    return null;
  }

  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) {
    return null;
  }

  try {
    return JSON.parse(raw) as StoredSenderKeys;
  } catch {
    return null;
  }
}

function writeStoredKeys(keys: StoredSenderKeys): void {
  if (typeof localStorage === "undefined") {
    throw new Error("Sender keys require a browser environment.");
  }

  localStorage.setItem(STORAGE_KEY, JSON.stringify(keys));
}

export function getOrCreateSenderSigningKeys(): MlDsaKeypair {
  const stored = readStoredKeys();
  if (stored?.publicKey && stored.secretKey) {
    return {
      publicKey: base64UrlToBytes(stored.publicKey),
      secretKey: base64UrlToBytes(stored.secretKey),
    };
  }

  const generated = generateMlDsaKeypair();
  writeStoredKeys({
    publicKey: encodeMlDsaPublicKey(generated.publicKey),
    secretKey: bytesToBase64Url(generated.secretKey),
  });

  return generated;
}
