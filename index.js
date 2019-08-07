/*! noble-secretbox-aes-gcm - MIT License (c) Paul Miller (paulmillr.com) */
"use strict";

const MODE = "aes-256-gcm";
const MODE_B = "AES-GCM";
const MODE_PARAMS = { name: MODE_B, length: 256 };

const isBrowser = typeof window == "object" && "crypto" in window;
const cryp = !isBrowser && require("crypto");
const wcryp = isBrowser && window.crypto;
let secureRandom = bytesLength => new Uint8Array(bytesLength);

const Encoder =
  !isBrowser && typeof TextEncoder === "undefined"
    ? require("util").TextEncoder
    : TextEncoder;
const Decoder =
  !isBrowser && typeof TextDecoder === "undefined"
    ? require("util").TextDecoder
    : TextDecoder;

if (isBrowser) {
  secureRandom = bytesLength => {
    const array = new Uint8Array(bytesLength);
    wcryp.getRandomValues(array);
    return array;
  };
} else if (typeof process === "object" && "node" in process.versions) {
  secureRandom = bytesLength => {
    const b = cryp.randomBytes(bytesLength);
    return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
  };
} else {
  throw new Error(
    "The environment doesn't have cryptographically secure random function"
  );
}
// function ui8aToHex(ui8a) {
//   return Array.from(ui8a)
//     .map(c => c.toString(16).padStart(2, "0"))
//     .join("");
// }
function hexToUi8a(hex) {
  if (hex.length % 2 !== 0) throw new RangeError("hex length is invalid");
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    array[i / 2] = parseInt(hex.substr(i, 2), 16);
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
    plaintext = new Encoder().encode(plaintext);
  const iv = secureRandom(12);
  if (isBrowser) {
    const bSharedKey = await wcryp.subtle.importKey(
      "raw",
      sharedKey,
      MODE_PARAMS,
      true,
      ["encrypt"]
    );
    const cipher = await wcryp.subtle.encrypt(
      { name: MODE_B, iv },
      bSharedKey,
      plaintext
    );
    const ciphertext = new Uint8Array(cipher);
    const encrypted = new Uint8Array(iv.length + ciphertext.byteLength);
    encrypted.set(iv, 0);
    encrypted.set(ciphertext, iv.length);
    return encrypted;
  } else {
    const cipher = cryp.createCipheriv(MODE, sharedKey, iv);
    let ciphertext = cipher.update(plaintext, undefined, "hex");
    ciphertext += cipher.final("hex");
    const ciphertextArray = hexToUi8a(ciphertext);
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
  if (typeof encoded === "string") encoded = hexToUi8a(encoded);
  const iv = encoded.slice(0, 12);
  if (isBrowser) {
    const ciphertextWithTag = encoded.slice(12);
    const bSharedKey = await wcryp.subtle.importKey(
      "raw",
      sharedKey,
      MODE_PARAMS,
      true,
      ["decrypt"]
    );
    const plaintext = await wcryp.subtle.decrypt(
      { name: MODE_B, iv },
      bSharedKey,
      ciphertextWithTag
    );
    return new Uint8Array(plaintext);
  } else {
    const ciphertext = encoded.slice(12, -16);
    const authTag = encoded.slice(-16);
    const decipher = cryp.createDecipheriv(MODE, sharedKey, iv);
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
function toUTF8(byteArray) {
  return new Decoder().decode(byteArray);
}

if (typeof exports !== "undefined") {
  Object.defineProperty(exports, "__esModule", { value: true });
  exports.decrypt = decrypt;
  exports.encrypt = encrypt;
  exports.toUTF8 = toUTF8;
}
