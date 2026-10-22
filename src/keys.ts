import { MlKem1024 } from "mlkem";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { toBase64 } from "./encoding";

/**
 * Generate an ML-KEM-1024 key pair.
 * Returns base64-encoded [publicKey, privateKey].
 */
export async function generateKeyPair(): Promise<[string, string]> {
  const recipient = new MlKem1024();
  const [publicKey, privateKey] = await recipient.generateKeyPair();

  return [toBase64(publicKey), toBase64(privateKey)];
}


/** Returns base64 [publicSignatureKey, privateSignatureKey] */
export async function generateSignatureKeyPair(): Promise<[string, string]> {
  const { publicKey, secretKey } = ml_dsa65.keygen();

  return [toBase64(publicKey), toBase64(secretKey)];
}
