declare function hexToBytes(hex: string): Uint8Array;
declare function concatBytes(...arrays: Uint8Array[]): Uint8Array;
export declare function encrypt(sharedKey: Uint8Array, plaintext: string | Uint8Array): Promise<Uint8Array>;
export declare function decrypt(sharedKey: Uint8Array, encoded: string | Uint8Array): Promise<Uint8Array>;
export declare const utils: {
    randomBytes: (bytesLength?: number) => any;
    bytesToUtf8(bytes: Uint8Array): string;
    utf8ToBytes(string: string): Uint8Array;
    hexToBytes: typeof hexToBytes;
    concatBytes: typeof concatBytes;
};
declare const aes: {
    encrypt: typeof encrypt;
    decrypt: typeof decrypt;
};
export default aes;
//# sourceMappingURL=index.d.ts.map