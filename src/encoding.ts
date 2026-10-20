import { Buffer } from "buffer";

export function toBase64(data: Uint8Array | Buffer): string {
  return Buffer.from(data).toString("base64");
}

export function fromBase64(b64: string): Buffer {
  return Buffer.from(b64, "base64");
}

export function encode(data: Uint8Array | Buffer): string {
  return toBase64(data);
}

export function decode(b64: string): Uint8Array {
  return new Uint8Array(fromBase64(b64));
}
