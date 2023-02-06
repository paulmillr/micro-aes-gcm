/*! micro-aes-gcm - MIT License (c) 2022 Paul Miller (paulmillr.com) */

/**
 * AES-GCM-SIV: classic AES-GCM with nonce-misuse resistance.
 * RFC 8452, https://datatracker.ietf.org/doc/html/rfc8452
 */

// prettier-ignore
type TypedArray = Int8Array | Uint8ClampedArray | Uint8Array |
  Uint16Array | Int16Array | Uint32Array | Int32Array;

declare const globalThis: Record<string, any> | undefined;
const cr = globalThis?.crypto;

// Cast array to different type
const u8 = (arr: TypedArray) => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
const u32 = (arr: TypedArray) =>
  new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));

// Cast array to view
const createView = (arr: TypedArray) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);

// Polyfill for Safari 14
function setBigUint64(view: DataView, byteOffset: number, value: bigint, isLE: boolean): void {
  if (typeof view.setBigUint64 === 'function') return view.setBigUint64(byteOffset, value, isLE);
  const _32n = BigInt(32);
  const _u32_max = BigInt(0xffffffff);
  const wh = Number((value >> _32n) & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE ? 4 : 0;
  const l = isLE ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE);
  view.setUint32(byteOffset + l, wl, isLE);
}


function ensureCrypto() {
  if (!cr) throw new Error('globalThis.crypto is not available: use nodejs 19+ or browser');
}

// AES stuff (same as ff1)
const BLOCK_LEN = 16;
const IV = new Uint8Array(BLOCK_LEN);
async function encryptBlock(msg: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  ensureCrypto();
  if (key.length !== 16 && key.length !== 32) throw new Error('Invalid key length');
  const mode = { name: `AES-CBC`, length: key.length * 8 };
  const wKey = await cr.subtle.importKey('raw', key, mode, true, ['encrypt']);
  const cipher = await cr.subtle.encrypt(
    { name: `aes-cbc`, iv: IV, counter: IV, length: 64 },
    wKey,
    msg
  );
  return new Uint8Array(cipher).subarray(0, 16);
}

// Polyval
// Reverse bits in u32, constant-time, precompute will be faster, but non-constant time
function rev32(x: number) {
  x = ((x & 0x5555_5555) << 1) | ((x >>> 1) & 0x5555_5555);
  x = ((x & 0x3333_3333) << 2) | ((x >>> 2) & 0x3333_3333);
  x = ((x & 0x0f0f_0f0f) << 4) | ((x >>> 4) & 0x0f0f_0f0f);
  x = ((x & 0x00ff_00ff) << 8) | ((x >>> 8) & 0x00ff_00ff);
  return (x << 16) | (x >>> 16);
}

// wrapped 32 bit multiplication
const wrapMul = (a: number, b: number) => Math.imul(a, b) >>> 0;

// https://timtaubert.de/blog/2017/06/verified-binary-multiplication-for-ghash/
function bmul32(x: number, y: number) {
  const x0 = x & 0x1111_1111;
  const x1 = x & 0x2222_2222;
  const x2 = x & 0x4444_4444;
  const x3 = x & 0x8888_8888;
  const y0 = y & 0x1111_1111;
  const y1 = y & 0x2222_2222;
  const y2 = y & 0x4444_4444;
  const y3 = y & 0x8888_8888;
  let res = (wrapMul(x0, y0) ^ wrapMul(x1, y3) ^ wrapMul(x2, y2) ^ wrapMul(x3, y1)) & 0x1111_1111;
  res |= (wrapMul(x0, y1) ^ wrapMul(x1, y0) ^ wrapMul(x2, y3) ^ wrapMul(x3, y2)) & 0x2222_2222;
  res |= (wrapMul(x0, y2) ^ wrapMul(x1, y1) ^ wrapMul(x2, y0) ^ wrapMul(x3, y3)) & 0x4444_4444;
  res |= (wrapMul(x0, y3) ^ wrapMul(x1, y2) ^ wrapMul(x2, y1) ^ wrapMul(x3, y0)) & 0x8888_8888;
  return res >>> 0;
}

function mulPart(arr: Uint32Array) {
  const a = new Uint32Array(18);
  a[0] = arr[0];
  a[1] = arr[1];
  a[2] = arr[2];
  a[3] = arr[3];
  a[4] = a[0] ^ a[1];
  a[5] = a[2] ^ a[3];
  a[6] = a[0] ^ a[2];
  a[7] = a[1] ^ a[3];
  a[8] = a[6] ^ a[7];
  a[9] = rev32(arr[0]);
  a[10] = rev32(arr[1]);
  a[11] = rev32(arr[2]);
  a[12] = rev32(arr[3]);
  a[13] = a[9] ^ a[10];
  a[14] = a[11] ^ a[12];
  a[15] = a[9] ^ a[11];
  a[16] = a[10] ^ a[12];
  a[17] = a[15] ^ a[16];
  return a;
}

export function polyval(h: Uint8Array, data: Uint8Array) {
  const s = new Uint32Array(4);
  // Precompute for multiplication
  const a = mulPart(u32(h));
  if (data.length % 16) throw new Error('Polyval: data should be padded to 16 bytes');
  const data32 = u32(data);
  for (let i = 0; i < data32.length; i += 4) {
    // Xor
    s[0] ^= data32[i + 0];
    s[1] ^= data32[i + 1];
    s[2] ^= data32[i + 2];
    s[3] ^= data32[i + 3];
    // Dot via Karatsuba multiplication, based on:
    // https://github.com/RustCrypto/universal-hashes/blob/5361f44a1162bd0d84e6560b6e30c7cb445e683f/polyval/src/backend/soft32.rs#L149
    {
      const b = mulPart(s);

      const c = new Uint32Array(18);
      for (let i = 0; i < 18; i++) c[i] = bmul32(a[i], b[i]);
      c[4] ^= c[0] ^ c[1];
      c[5] ^= c[2] ^ c[3];
      c[8] ^= c[6] ^ c[7];
      c[13] ^= c[9] ^ c[10];
      c[14] ^= c[11] ^ c[12];
      c[17] ^= c[15] ^ c[16];

      const zw = new Uint32Array(8);
      zw[0] = c[0];
      zw[1] = c[4] ^ (rev32(c[9]) >>> 1);
      zw[2] = c[1] ^ c[0] ^ c[2] ^ c[6] ^ (rev32(c[13]) >>> 1);
      zw[3] = c[4] ^ c[5] ^ c[8] ^ (rev32(c[10] ^ c[9] ^ c[11] ^ c[15]) >>> 1);
      zw[4] = c[2] ^ c[1] ^ c[3] ^ c[7] ^ (rev32(c[13] ^ c[14] ^ c[17]) >>> 1);
      zw[5] = c[5] ^ (rev32(c[11] ^ c[10] ^ c[12] ^ c[16]) >>> 1);
      zw[6] = c[3] ^ (rev32(c[14]) >>> 1);
      zw[7] = rev32(c[12]) >>> 1;
      for (let i = 0; i < 4; i++) {
        const lw = zw[i];
        zw[i + 4] ^= lw ^ (lw >>> 1) ^ (lw >>> 2) ^ (lw >>> 7);
        zw[i + 3] ^= (lw << 31) ^ (lw << 30) ^ (lw << 25);
      }

      s[0] = zw[4];
      s[1] = zw[5];
      s[2] = zw[6];
      s[3] = zw[7];
    }
  }
  return u8(s);
}

// Kinda constant-time equality
function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  // Should not happen
  if (a.length !== b.length) throw new Error('equalBytes: Different size of Uint8Arrays');
  let flag = true;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) flag &&= false;
  return flag;
}
// Wrap position so it will be in padded to blockSize
const wrapPos = (pos: number, blockSize: number) => Math.ceil(pos / blockSize) * blockSize;

const limit = (name: string, min: number, max: number) => (value: number) => {
  if (!Number.isSafeInteger(value) || min > value || value > max)
    throw new Error(`${name}: invalid value=${value}, should be [${min}..${max}]`);
};

// From RFC 8452: Section 6
const AAD_LIMIT = limit('AAD', 0, 2 ** 36);
const PLAIN_LIMIT = limit('Plaintext', 0, 2 ** 36);
const NONCE_LIMIT = limit('Nonce', 12, 12);
const CIPHER_LIMIT = limit('Ciphertext', 16, 2 ** 36 + 16);

// nodejs api doesn't support 32bit counters, browser does
async function ctr(key: Uint8Array, tag: Uint8Array, input: Uint8Array) {
  // The initial counter block is the tag with the most significant bit of the last byte set to one.
  let block = tag.slice();
  block[15] |= 0x80;
  let view = createView(block);
  let output = new Uint8Array(input.length);
  for (let pos = 0; pos < input.length; ) {
    const encryptedBlock = await encryptBlock(block, key);
    view.setUint32(0, view.getUint32(0, true) + 1, true);
    const take = Math.min(input.length, encryptedBlock.length);
    for (let j = 0; j < take; j++, pos++) output[pos] = encryptedBlock[j] ^ input[pos];
  }
  return new Uint8Array(output);
}

export async function deriveKeys(key: Uint8Array, nonce: Uint8Array) {
  NONCE_LIMIT(nonce.length);
  if (key.length !== 16 && key.length !== 32)
    throw new Error(`Key length should be 16 or 32 bytes, got: ${key.length} bytes.`);
  const encKey = new Uint8Array(key.length);
  const authKey = new Uint8Array(16);
  let counter = 0;
  const deriveBlock = new Uint8Array(nonce.length + 4);
  deriveBlock.set(nonce, 4);
  const view = createView(deriveBlock);
  for (const derivedKey of [authKey, encKey]) {
    for (let i = 0; i < derivedKey.length; i += 8) {
      view.setUint32(0, counter++, true);
      const block = await encryptBlock(deriveBlock, key);
      derivedKey.set(block.subarray(0, 8), i);
    }
  }
  return { authKey, encKey };
}

export async function AES(key: Uint8Array, nonce: Uint8Array) {
  const { encKey, authKey } = await deriveKeys(key, nonce);
  const computeTag = async (data: Uint8Array, AAD: Uint8Array) => {
    const dataPos = wrapPos(AAD.length, 16);
    const lenPos = wrapPos(dataPos + data.length, 16);
    const block = new Uint8Array(lenPos + 16);
    const view = createView(block);
    block.set(AAD);
    block.set(data, dataPos);
    setBigUint64(view, lenPos, BigInt(AAD.length * 8), true);
    setBigUint64(view, lenPos + 8, BigInt(data.length * 8), true);
    // Compute the expected tag by XORing S_s and the nonce, clearing the
    // most significant bit of the last byte and encrypting with the
    // message-encryption key.
    const tag = polyval(authKey, block);
    for (let i = 0; i < 12; i++) tag[i] ^= nonce[i];
    // Clear the highest bit
    tag[15] &= 0x7f;
    return await encryptBlock(tag, encKey);
  };
  return {
    computeTag,
    encrypt: async (plaintext: Uint8Array, AAD: Uint8Array) => {
      AAD_LIMIT(AAD.length);
      PLAIN_LIMIT(plaintext.length);
      const tag = await computeTag(plaintext, AAD);
      const out = new Uint8Array(plaintext.length + 16);
      out.set(tag, plaintext.length);
      out.set(await ctr(encKey, tag, plaintext));
      return out;
    },
    decrypt: async (data: Uint8Array, AAD: Uint8Array) => {
      CIPHER_LIMIT(data.length);
      AAD_LIMIT(AAD.length);
      const tag = data.subarray(-16);
      const plaintext = await ctr(encKey, tag, data.subarray(0, -16));
      const expectedTag = await computeTag(plaintext, AAD);
      if (!equalBytes(tag, expectedTag)) throw new Error('Wrong TAG');
      return plaintext;
    },
  };
}
