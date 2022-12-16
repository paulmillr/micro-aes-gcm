/*! micro-aes-gcm-siv - MIT License (c) 2022 Paul Miller (paulmillr.com) */
export declare function polyval(h: Uint8Array, data: Uint8Array): Uint8Array;
export declare function deriveKeys(key: Uint8Array, nonce: Uint8Array): Promise<{
    authKey: Uint8Array;
    encKey: Uint8Array;
}>;
export declare function AES(key: Uint8Array, nonce: Uint8Array): Promise<{
    computeTag: (data: Uint8Array, AAD: Uint8Array) => Promise<Uint8Array>;
    encrypt: (plaintext: Uint8Array, AAD: Uint8Array) => Promise<Uint8Array>;
    decrypt: (data: Uint8Array, AAD: Uint8Array) => Promise<Uint8Array>;
}>;
