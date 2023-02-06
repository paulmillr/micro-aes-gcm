# micro-aes-gcm

0-dep wrapper around webcrypto AES-GCM. Has optional RFC 8452 SIV implementation.

Node.js 19 or higher is required. For older node.js, you'll need shim: `globalThis.crypto = require('node.crypto').webcrypto`.

Inserts IV and MAC into the output `iv + ciphertext + mac`:

- `iv` is 12 bytes; it's an CSPRNG-sourced initialization vector for AES-GCM mode.
- `ciphertext` length depends on plaintext
- `mac` is 16 bytes; AES-GCM calculates this authentication tag for us.
- `const c = await encrypt(key, plaintext), iv = c.slice(0, 12), mac = c.slice(-16);`

Has optional implementation of AES-GCM-SIV RFC 8452 nonce-misuse resistance in a separate file.

## Usage

> npm install micro-aes-gcm

```js
import * as aes from 'micro-aes-gcm';
const key = Uint8Array.from([
  64, 196, 127, 247, 172, 2, 34, 159, 6, 241, 30, 174, 183, 229, 41, 114, 253, 122, 119, 168, 177,
  243, 155, 236, 164, 159, 98, 72, 162, 243, 224, 195,
]);
const message = 'Hello world';
const ciphertext = await aes.encrypt(key, aes.utils.utf8ToBytes(message));
const plaintext = await aes.decrypt(key, ciphertext);
console.log(aes.utils.bytesToUtf8(plaintext) === message);
// Also works in browsers
```

API is:

```typescript
function encrypt(key: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
function decrypt(key: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
```

### SIV

```ts
import { AES } from 'micro-aes-gcm/siv.js';
const cr = await aes(KEY, NONCE);
await cr.encrypt(buf, AAD),
```

[AES-GCM-SIV](https://en.wikipedia.org/wiki/AES-GCM-SIV) is designed to preserve both privacy and integrity even if nonces are repeated. To accomplish this, encryption is a function of a nonce, the plaintext message, and optional additional associated data (AAD). In the event a nonce is misused (i.e. used more than once), nothing is revealed except in the case that same message is encrypted multiple times with the same nonce. When that happens, an attacker is able to observe repeat encryptions, since encryption is a deterministic function of the nonce and message. However, beyond that, no additional information is revealed to the attacker. For this reason, AES-GCM-SIV is an ideal choice in cases that unique nonces cannot be guaranteed, such as multiple servers or network devices encrypting messages under the same key without coordination.

AEADs that can withstand nonce duplication are called [“nonce-misuse resistant”](https://www.imperialviolet.org/2017/05/14/aesgcmsiv.html) and that name appears to have caused some people to believe that they are infinitely resistant. I.e. that an unlimited number of messages can be encrypted with a fixed nonce with no loss in security. That is not the case, and the term wasn't defined that way originally by Rogaway and Shrimpton (nor does their SIV mode have that property). So it's important to emphasise that AES-GCM-SIV (and nonce-misuse resistant modes in general) are not a magic invulnerability shield. Figure four and section five of the the paper give precise bounds but, if in doubt, consider AES-GCM-SIV to be a safety net for accidental nonce duplication and otherwise treat it like a traditional AEAD.

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
