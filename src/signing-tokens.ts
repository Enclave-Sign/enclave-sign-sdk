import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToBase64Url } from "@enclave/pqc-core";

function randomTokenBytes(): Uint8Array {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes;
}

export function generateSigningToken(): string {
  return bytesToBase64Url(randomTokenBytes());
}

export function hashSigningToken(token: string): string {
  const digest = sha256(new TextEncoder().encode(token.trim()));
  return Array.from(digest)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function buildSigningUrl(token: string, siteUrl: string): string {
  const base = siteUrl.replace(/\/+$/, "");
  return `${base}/web/sign?token=${encodeURIComponent(token)}`;
}
