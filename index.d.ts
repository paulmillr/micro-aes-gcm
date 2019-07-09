/// <reference types="node" />
export declare function decrypt(sharedKey: Uint8Array, encoded: Uint8Array | string): Promise<Uint8Array>;
export declare function encrypt(sharedKey: Uint8Array, plaintext: Uint8Array | string): Promise<Uint8Array>;
