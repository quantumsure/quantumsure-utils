import { Buffer } from "buffer";

export function toBase64(data: Uint8Array | Buffer): string {
  return Buffer.from(data).toString("base64");
}

export function fromBase64(b64: string): Buffer {
  return Buffer.from(b64, "base64");
}
