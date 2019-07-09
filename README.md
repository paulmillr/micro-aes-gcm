# noble-secretbox-aes-gcm

[secretbox](https://nacl.cr.yp.to/secretbox.html) — authenticated data encryption with AES-GCM.

DJB's secretbox uses XSalsa20-Poly1305. We'll use AES-GCM, which is also a good choice. DJB mentioned the AES box in his TODOs.

AES has been selected over Salsa, because it's natively implemented in Node & browsers and doesn't require any 3rd-party libraries.

### This library belongs to *noble* crypto

> **noble-crypto** — high-security, easily auditable set of contained cryptographic libraries and tools.

- No dependencies, one small file
- Easily auditable TypeScript/JS code
- Uses es2019 bigint. Supported in Chrome, Firefox, node 10+
- All releases are signed and trusted
- Check out all libraries:
  [secp256k1](https://github.com/paulmillr/noble-secp256k1),
  [ed25519](https://github.com/paulmillr/noble-ed25519),
  [ripemd160](https://github.com/paulmillr/noble-ripemd160),
  [secretbox-aes-gcm](https://https://github.com/paulmillr/noble-secretbox-aes-gcm)

## Usage

> npm install noble-secretbox-aes-gcm

```js
import {encrypt, decrypt} from "noble-secretbox-aes-gcm";
const key = Uint8Array.from([
  64, 196, 127, 247, 172,   2,  34,
  159,   6, 241,  30, 174, 183, 229,
  41, 114, 253, 122, 119, 168, 177,
  243, 155, 236, 164, 159,  98,  72,
  162, 243, 224, 195
]);
const plaintext = "Hello world";
const ciphertext = await encrypt(key, message);
const plaintext = await decrypt(key, ciphertext);
new TextDecoder().decode(plaintext) === message;
// Also supported in browser.
```

## API

```typescript
function encrypt(key: Uint8Array, plaintext: Uint8Array|string): Promise<Uint8Array>;
```

```typescript
function decrypt(key: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
```

## License

MIT (c) Paul Miller (https://paulmillr.com), see LICENSE file.
