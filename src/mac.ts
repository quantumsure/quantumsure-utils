import { Buffer } from "buffer";

/** SHA-256 MAC over data || key */
export async function computeMac(
  data: string | Uint8Array,
  key: string | Uint8Array
): Promise<Buffer> {
  const dataBytes =
    typeof data === "string" ? new TextEncoder().encode(data) : data;
  const keyBytes =
    typeof key === "string" ? new TextEncoder().encode(key) : key;

  const combined = Buffer.concat([
    Buffer.from(dataBytes),
    Buffer.from(keyBytes),
  ]);

  const hash = await crypto.subtle.digest("SHA-256", combined);
  return Buffer.from(hash);
}
