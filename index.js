"use strict";

const AES_MODE_N = "aes-256-gcm";
const AES_MODE_B = "AES-GCM";
const AES_MODE_BB = { name: AES_MODE_B, length: 256 };

const isBrowser = typeof window !== 'undefined' && window.crypto;
const wcryp = isBrowser && window.crypto;
const cryp = !isBrowser && require("crypto");
const secureRandom = wcryp ?
  (length => window.crypto.getRandomValues(new Uint8Array(length))) :
  (length => new Uint8Array(cryp.randomBytes(length).buffer));

function hexToArray(hex) {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  if (hex.length & 1) hex = `0${hex}`;
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    let j = i * 2;
    array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
  }
  return array;
}

/**
 * @param {Uint8Array} sharedKey
 * @param {Uint8Array|string} plaintext
 * @returns {Promise<Uint8Array>}
 */
async function encrypt(sharedKey, plaintext) {
  if (typeof plaintext === "string")
    plaintext = new TextEncoder().encode(plaintext);
  const iv = secureRandom(12);
  if (isBrowser) {
    const bSharedKey = await wcryp.subtle.importKey(
      "raw",
      sharedKey,
      AES_MODE_BB,
      true,
      ["encrypt"]
    );
    const cipher = await wcryp.subtle.encrypt(
      { name: AES_MODE_B, iv },
      bSharedKey,
      plaintext
    );
    const ciphertext = new Uint8Array(cipher);
    const encrypted = new Uint8Array(iv.length + ciphertext.byteLength);
    encrypted.set(iv, 0);
    encrypted.set(ciphertext, iv.length);
    return encrypted;
  } else {
    const cipher = cryp.createCipheriv(AES_MODE_N, sharedKey, iv);
    let ciphertext = cipher.update(plaintext, undefined, "hex");
    ciphertext += cipher.final("hex");
    const ciphertextArray = hexToArray(ciphertext);
    const tag = cipher.getAuthTag();
    const encrypted = new Uint8Array(
      iv.length + ciphertextArray.length + tag.length
    );
    encrypted.set(iv, 0);
    encrypted.set(ciphertextArray, iv.length);
    encrypted.set(tag, iv.length + ciphertextArray.length);
    return encrypted;
  }
}

/**
 * @param {Uint8Array} sharedKey
 * @param {Uint8Array} encoded
 * @returns {Promise<Uint8Array>}
 */
async function decrypt(sharedKey, encoded) {
  if (typeof encoded === "string") encoded = hexToArray(encoded);
  const iv = encoded.slice(0, 12);
  if (isBrowser) {
    const ciphertextWithTag = encoded.slice(12);
    const bSharedKey = await wcryp.subtle.importKey(
      "raw",
      sharedKey,
      AES_MODE_BB,
      true,
      ["decrypt"]
    );
    const plaintext = await wcryp.subtle.decrypt(
      { name: AES_MODE_B, iv },
      bSharedKey,
      ciphertextWithTag
    );
    return new Uint8Array(plaintext);
  } else {
    const ciphertext = encoded.slice(12, -16);
    const authTag = encoded.slice(-16);
    const decipher = cryp.createDecipheriv(AES_MODE_N, sharedKey, iv);
    decipher.setAuthTag(authTag);
    const plaintext = decipher.update(ciphertext);
    const res = Buffer.concat([plaintext, decipher.final()]);
    return Uint8Array.from(res);
  }
}

/**
 * Converts a typed array to unicode string in UTF-8 format.
 * @param {Uint8Array} byteArray
 * @returns {string}
 */
function bytesToUTF8(byteArray) {
  return new TextDecoder().decode(byteArray);
}

if (typeof exports !== "undefined") {
  Object.defineProperty(exports, "__esModule", { value: true });
  exports.decrypt = decrypt;
  exports.encrypt = encrypt;
  exports.bytesToUTF8 = bytesToUTF8;
}
