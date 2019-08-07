# noble-secretbox-aes-gcm

[secretbox](https://nacl.cr.yp.to/secretbox.html) — authenticated data encryption with AES-GCM.

Allows to encrypt arbitrary data in a cryptographically secure & modern way.

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
  [secretbox-aes-gcm](https://github.com/paulmillr/noble-secretbox-aes-gcm)

## Usage

> npm install noble-secretbox-aes-gcm

```js
import {encrypt, decrypt, toUTF8} from "noble-secretbox-aes-gcm";
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
console.log(toUTF8(plaintext) === message);
// Also works in browsers
```

## API

```typescript
function encrypt(key: Uint8Array, plaintext: Uint8Array|string): Promise<Uint8Array>;
```

`plaintext` in `encrypt` can be either a Uint8Array, or a string. If it's a string,
`new TextDecoder().encode(plaintext)` would be executed before passing it further.

```typescript
function decrypt(key: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
```

Note that `decrypt` always returns `Uint8Array`. If you've encrypted UTF-8 string,
`toUTF8(result)` should be enough to get it back.

## Internals

Secretbox receives one key, and one plaintext.

The output format is: `iv + ciphertext + mac`:

- `iv` is 12 bytes; it's an initialization vector for AES-GCM mode.
- `ciphertext` length depends on plaintext
- `mac` is 16 bytes; AES-GCM calculates this authentication tag for us.

To slice through IV and MAC, you can use `Uint8Array.prototype.slice()`:

```js
const ciphertext = await encrypt(key, plaintext);
const iv = ciphertext.slice(0, 12);
const mac = ciphertext.slice(-16);
```

## Security

Noble is production-ready & secure. Our goal is to have it audited by a good security expert.

DJB's secretbox uses XSalsa20-Poly1305. We'll use AES-GCM, which is also a good choice. DJB mentioned the AES box in his TODOs.

AES has been selected over Salsa, because it's natively implemented in Node & browsers and doesn't require any 3rd-party libraries.

## License

MIT (c) Paul Miller (https://paulmillr.com), see LICENSE file.
