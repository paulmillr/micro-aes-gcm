/*! micro-aes-gcm - MIT License (c) 2022 Paul Miller (paulmillr.com) */
const cr = globalThis?.crypto;
const u8 = (arr) => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
const u32 = (arr) => new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
const createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
function setBigUint64(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === 'function')
        return view.setBigUint64(byteOffset, value, isLE);
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
    if (!cr)
        throw new Error('globalThis.crypto is not available: use nodejs 19+ or browser');
}
const BLOCK_LEN = 16;
const IV = new Uint8Array(BLOCK_LEN);
async function encryptBlock(msg, key) {
    ensureCrypto();
    if (key.length !== 16 && key.length !== 32)
        throw new Error('Invalid key length');
    const mode = { name: `AES-CBC`, length: key.length * 8 };
    const wKey = await cr.subtle.importKey('raw', key, mode, true, ['encrypt']);
    const cipher = await cr.subtle.encrypt({ name: `aes-cbc`, iv: IV, counter: IV, length: 64 }, wKey, msg);
    return new Uint8Array(cipher).subarray(0, 16);
}
function rev32(x) {
    x = ((x & 1431655765) << 1) | ((x >>> 1) & 1431655765);
    x = ((x & 858993459) << 2) | ((x >>> 2) & 858993459);
    x = ((x & 252645135) << 4) | ((x >>> 4) & 252645135);
    x = ((x & 16711935) << 8) | ((x >>> 8) & 16711935);
    return (x << 16) | (x >>> 16);
}
const wrapMul = (a, b) => Math.imul(a, b) >>> 0;
function bmul32(x, y) {
    const x0 = x & 286331153;
    const x1 = x & 572662306;
    const x2 = x & 1145324612;
    const x3 = x & 2290649224;
    const y0 = y & 286331153;
    const y1 = y & 572662306;
    const y2 = y & 1145324612;
    const y3 = y & 2290649224;
    let res = (wrapMul(x0, y0) ^ wrapMul(x1, y3) ^ wrapMul(x2, y2) ^ wrapMul(x3, y1)) & 286331153;
    res |= (wrapMul(x0, y1) ^ wrapMul(x1, y0) ^ wrapMul(x2, y3) ^ wrapMul(x3, y2)) & 572662306;
    res |= (wrapMul(x0, y2) ^ wrapMul(x1, y1) ^ wrapMul(x2, y0) ^ wrapMul(x3, y3)) & 1145324612;
    res |= (wrapMul(x0, y3) ^ wrapMul(x1, y2) ^ wrapMul(x2, y1) ^ wrapMul(x3, y0)) & 2290649224;
    return res >>> 0;
}
function mulPart(arr) {
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
export function polyval(h, data) {
    const s = new Uint32Array(4);
    const a = mulPart(u32(h));
    if (data.length % 16)
        throw new Error('Polyval: data should be padded to 16 bytes');
    const data32 = u32(data);
    for (let i = 0; i < data32.length; i += 4) {
        s[0] ^= data32[i + 0];
        s[1] ^= data32[i + 1];
        s[2] ^= data32[i + 2];
        s[3] ^= data32[i + 3];
        {
            const b = mulPart(s);
            const c = new Uint32Array(18);
            for (let i = 0; i < 18; i++)
                c[i] = bmul32(a[i], b[i]);
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
function equalBytes(a, b) {
    if (a.length !== b.length)
        throw new Error('equalBytes: Different size of Uint8Arrays');
    let flag = true;
    for (let i = 0; i < a.length; i++)
        if (a[i] !== b[i])
            flag && (flag = false);
    return flag;
}
const wrapPos = (pos, blockSize) => Math.ceil(pos / blockSize) * blockSize;
const limit = (name, min, max) => (value) => {
    if (!Number.isSafeInteger(value) || min > value || value > max)
        throw new Error(`${name}: invalid value=${value}, should be [${min}..${max}]`);
};
const AAD_LIMIT = limit('AAD', 0, 2 ** 36);
const PLAIN_LIMIT = limit('Plaintext', 0, 2 ** 36);
const NONCE_LIMIT = limit('Nonce', 12, 12);
const CIPHER_LIMIT = limit('Ciphertext', 16, 2 ** 36 + 16);
async function ctr(key, tag, input) {
    let block = tag.slice();
    block[15] |= 0x80;
    let view = createView(block);
    let output = new Uint8Array(input.length);
    for (let pos = 0; pos < input.length;) {
        const encryptedBlock = await encryptBlock(block, key);
        view.setUint32(0, view.getUint32(0, true) + 1, true);
        const take = Math.min(input.length, encryptedBlock.length);
        for (let j = 0; j < take; j++, pos++)
            output[pos] = encryptedBlock[j] ^ input[pos];
    }
    return new Uint8Array(output);
}
export async function deriveKeys(key, nonce) {
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
export async function AES(key, nonce) {
    const { encKey, authKey } = await deriveKeys(key, nonce);
    const computeTag = async (data, AAD) => {
        const dataPos = wrapPos(AAD.length, 16);
        const lenPos = wrapPos(dataPos + data.length, 16);
        const block = new Uint8Array(lenPos + 16);
        const view = createView(block);
        block.set(AAD);
        block.set(data, dataPos);
        setBigUint64(view, lenPos, BigInt(AAD.length * 8), true);
        setBigUint64(view, lenPos + 8, BigInt(data.length * 8), true);
        const tag = polyval(authKey, block);
        for (let i = 0; i < 12; i++)
            tag[i] ^= nonce[i];
        tag[15] &= 0x7f;
        return await encryptBlock(tag, encKey);
    };
    return {
        computeTag,
        encrypt: async (plaintext, AAD) => {
            AAD_LIMIT(AAD.length);
            PLAIN_LIMIT(plaintext.length);
            const tag = await computeTag(plaintext, AAD);
            const out = new Uint8Array(plaintext.length + 16);
            out.set(tag, plaintext.length);
            out.set(await ctr(encKey, tag, plaintext));
            return out;
        },
        decrypt: async (data, AAD) => {
            CIPHER_LIMIT(data.length);
            AAD_LIMIT(AAD.length);
            const tag = data.subarray(-16);
            const plaintext = await ctr(encKey, tag, data.subarray(0, -16));
            const expectedTag = await computeTag(plaintext, AAD);
            if (!equalBytes(tag, expectedTag))
                throw new Error('Wrong TAG');
            return plaintext;
        },
    };
}
