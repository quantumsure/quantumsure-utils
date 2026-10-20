import { Buffer } from "buffer";

/** Cryptographically secure random bytes */
export function randomBytes(length: number): Buffer {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Buffer.from(array);
}
