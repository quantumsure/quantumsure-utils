import ChaCha20 from "js-chacha20";
import { Buffer } from "buffer";
import { randomBytes } from "./random";
import { computeMac } from "./mac";
import { toBase64, fromBase64 } from "./encoding";

/**
 * Encrypt an ML-KEM private key with a master password.
 * Format: nonce.encrypted.authTag  (base64, dot-separated)
 */
export async function encryptPrivateKey(
  privateKey: string,
  masterPassword: string
): Promise<string> {
  if (!privateKey) {
    throw new Error("encryptPrivateKey: privateKey is required");
  }
  if (!masterPassword) {
    throw new Error("encryptPrivateKey: masterPassword is required");
  }

  const key = Buffer.from(masterPassword.padEnd(32, "0").slice(0, 32));
  const nonce = randomBytes(12);
  const chacha = new ChaCha20(key, nonce);
  const encrypted = chacha.encrypt(Buffer.from(privateKey));

  const combinedData = new TextEncoder().encode(
    `${toBase64(nonce)}${toBase64(encrypted)}`
  );
  const authTag = await computeMac(combinedData, key);

  return `${toBase64(nonce)}.${toBase64(encrypted)}.${toBase64(authTag)}`;
}

/**
 * Decrypt a private key previously wrapped with encryptPrivateKey.
 */
export async function decryptPrivateKey(
  encryptedPrivateKey: string,
  masterPassword: string
): Promise<string> {
  if (!encryptedPrivateKey) {
    throw new Error("decryptPrivateKey: encryptedPrivateKey is required");
  }
  if (!masterPassword) {
    throw new Error("decryptPrivateKey: masterPassword is required");
  }

  const parts = encryptedPrivateKey.split(".");
  if (parts.length !== 3) {
    throw new Error(
      "decryptPrivateKey: invalid format (expected nonce.encrypted.authTag)"
    );
  }

  const [nonceB64, encryptedB64, authTagB64] = parts;
  const key = Buffer.from(masterPassword.padEnd(32, "0").slice(0, 32));

  const combinedData = new TextEncoder().encode(`${nonceB64}${encryptedB64}`);
  const computedMac = await computeMac(combinedData, key);
  const expectedMac = fromBase64(authTagB64);

  if (!computedMac.equals(expectedMac)) {
    throw new Error("decryptPrivateKey: invalid MAC");
  }

  const nonce = fromBase64(nonceB64);
  const encrypted = fromBase64(encryptedB64);
  const chacha = new ChaCha20(key, nonce);
  const decrypted = chacha.decrypt(encrypted);

  return new TextDecoder().decode(decrypted);
}
