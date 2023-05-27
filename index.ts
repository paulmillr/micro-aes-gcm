// Typescript symbol is present in browsers
declare const globalThis: Record<string, any> | undefined;
declare const TextEncoder: any;
declare const TextDecoder: any;
// We support: 1) browsers 2) node.js 19+
function cr() {
  if (typeof globalThis === 'object' && 'crypto' in globalThis) {
    return globalThis.crypto;
  } else {
    throw new Error('globalThis.crypto is not available: use nodejs 19+ or browser');
  }
}
export const utils = {
  bytesToUtf8(bytes: Uint8Array): string {
    return new TextDecoder().decode(bytes);
  },
  utf8ToBytes(string: string): Uint8Array {
    return new TextEncoder().encode(string);
  },
  /**
   * Concats Uint8Array-s into one; like `Buffer.concat([buf1, buf2])`
   * @example concatBytes(buf1, buf2)
   */
  concatBytes(...arrays: Uint8Array[]): Uint8Array {
    if (!arrays.every((a) => a instanceof Uint8Array)) throw new Error('Uint8Array list expected');
    if (arrays.length === 1) return arrays[0];
    const length = arrays.reduce((a, arr) => a + arr.length, 0);
    const result = new Uint8Array(length);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
      const arr = arrays[i];
      result.set(arr, pad);
      pad += arr.length;
    }
    return result;
  },
  randomBytes: (bytesLength = 32) => {
    return cr().getRandomValues(new Uint8Array(bytesLength));
  },
};

const MD = { e: 'AES-GCM', i: { name: 'AES-GCM', length: 256 } };

function ensureBytes(b: any, len?: number) {
  if (!(b instanceof Uint8Array)) throw new Error('Uint8Array expected');
  if (typeof len === 'number')
    if (b.length !== len) throw new Error(`Uint8Array length ${len} expected`);
}

export async function encrypt(key: Uint8Array, plaintext: Uint8Array, iv = utils.randomBytes(12)) {
  ensureBytes(key, 32);
  ensureBytes(plaintext);
  const iKey = await cr().subtle.importKey('raw', key, MD.i, true, ['encrypt']);
  const cipher = await cr().subtle.encrypt({ name: MD.e, iv }, iKey, plaintext);
  return utils.concatBytes(iv, new Uint8Array(cipher));
}

export async function decrypt(key: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  ensureBytes(key, 32);
  ensureBytes(ciphertext);
  const iv = ciphertext.slice(0, 12);
  const ciphertextWithTag = ciphertext.slice(12);
  const iKey = await cr().subtle.importKey('raw', key, MD.i, true, ['decrypt']);
  const plaintext = await cr().subtle.decrypt({ name: MD.e, iv }, iKey, ciphertextWithTag);
  return new Uint8Array(plaintext);
}

const aes_256_gcm = { encrypt, decrypt };
export default aes_256_gcm;
