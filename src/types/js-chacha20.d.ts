declare module "js-chacha20" {
  export default class ChaCha20 {
    constructor(key: Uint8Array, nonce: Uint8Array);
    encrypt(data: Uint8Array): Uint8Array;
    decrypt(data: Uint8Array): Uint8Array;
  }
}
