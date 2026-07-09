import {
  bytesToBase64Url,
  bytesToHex,
  hashUtf8,
} from "@enclave/pqc-primitives";

function randomTokenBytes(): Uint8Array {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes;
}

export function generateSigningToken(): string {
  return bytesToBase64Url(randomTokenBytes());
}

export function hashSigningToken(token: string): string {
  const trimmed = token.trim();
  if (!trimmed) {
    throw new Error("Signing token must not be empty");
  }

  return bytesToHex(hashUtf8(trimmed));
}

export function buildSigningUrl(token: string, siteUrl: string): string {
  const trimmed = token.trim();
  if (!trimmed) {
    throw new Error("Signing token must not be empty");
  }
  if (!siteUrl.trim()) {
    throw new Error("Site URL must not be empty");
  }

  const base = siteUrl.replace(/\/+$/, "");
  return `${base}/web/sign?token=${encodeURIComponent(trimmed)}`;
}
