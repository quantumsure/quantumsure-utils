import { MlKem1024 } from "mlkem";
import ChaCha20 from "js-chacha20";
import { Buffer } from "buffer";
import { randomBytes } from "./random";
import { computeMac } from "./mac";
import { toBase64, fromBase64 } from "./encoding";

/**
 * Symmetric encrypt with ChaCha20 + separate MAC.
 * Returns { encrypted, nonce } as base64 strings.
 */
function postQuantumEncrypt(
  data: string | Uint8Array,
  key: Uint8Array
): { encrypted: string; nonce: string } {
  const nonce = randomBytes(12);
  const dataBytes =
    typeof data === "string" ? new TextEncoder().encode(data) : data;

  const chacha = new ChaCha20(key, nonce);
  const encrypted = chacha.encrypt(Buffer.from(dataBytes));

  return {
    encrypted: toBase64(encrypted),
    nonce: toBase64(nonce),
  };
}

/**
 * Symmetric decrypt with ChaCha20 after MAC verification.
 */
async function postQuantumDecrypt(
  encryptedB64: string,
  nonceB64: string,
  key: Uint8Array,
  authTagB64: string
): Promise<string> {
  const encrypted = fromBase64(encryptedB64);
  const nonce = fromBase64(nonceB64);

  const combinedData = new TextEncoder().encode(`${nonceB64}${encryptedB64}`);
  const computedMac = await computeMac(combinedData, key);
  const expectedMac = fromBase64(authTagB64);

  if (!computedMac.equals(expectedMac)) {
    throw new Error("Invalid MAC – data may have been tampered with");
  }

  const chacha = new ChaCha20(key, nonce);
  const decrypted = chacha.decrypt(encrypted);
  return new TextDecoder().decode(decrypted);
}

/**
 * Encrypt arbitrary data with a recipient ML-KEM-1024 public key.
 *
 * Blob format:
 *   kemCiphertext : nonce : ciphertext : authTag
 * (all base64, colon-separated)
 */
export async function quantumResistantEncrypt(
  plaintext: string,
  publicKeyB64: string
): Promise<{ encrypted_data: string }> {
  if (plaintext == null) {
    throw new Error("quantumResistantEncrypt: plaintext is required");
  }
  if (!publicKeyB64) {
    throw new Error("quantumResistantEncrypt: publicKeyB64 is required");
  }

  const publicKey = fromBase64(publicKeyB64);
  const sender = new MlKem1024();
  const [kemCiphertext, sharedSecret] = await sender.encap(publicKey);

  const { encrypted, nonce } = postQuantumEncrypt(plaintext, sharedSecret);

  const combinedData = new TextEncoder().encode(`${nonce}${encrypted}`);
  const authTag = await computeMac(combinedData, sharedSecret);

  return {
    encrypted_data: [
      toBase64(kemCiphertext),
      nonce,
      encrypted,
      toBase64(authTag),
    ].join(":"),
  };
}

/**
 * Decrypt a blob produced by quantumResistantEncrypt.
 */
export async function quantumResistantDecrypt(
  encryptedData: string,
  privateKeyB64: string
): Promise<string> {
  if (!encryptedData) {
    throw new Error("quantumResistantDecrypt: encryptedData is required");
  }
  if (!privateKeyB64) {
    throw new Error("quantumResistantDecrypt: privateKeyB64 is required");
  }

  const parts = encryptedData.split(":");
  if (parts.length !== 4) {
    throw new Error(
      "quantumResistantDecrypt: invalid format (expected 4 parts)"
    );
  }

  const [ciphertextB64, nonceB64, encryptedB64, authTagB64] = parts;

  const privateKey = fromBase64(privateKeyB64);
  const recipient = new MlKem1024();
  const sharedSecret = await recipient.decap(
    fromBase64(ciphertextB64),
    privateKey
  );

  return postQuantumDecrypt(encryptedB64, nonceB64, sharedSecret, authTagB64);
}
