import { encrypt, decrypt, utils } from './index.js';
import { should } from 'micro-should';
import assert from 'assert';

should('should encrypt and decrypt', async () => {
  const key = Uint8Array.from([
    64, 196, 127, 247, 172, 2, 34, 159, 6, 241, 30, 174, 183, 229, 41, 114, 253, 122, 119, 168, 177,
    243, 155, 236, 164, 159, 98, 72, 162, 243, 224, 195,
  ]);
  const plaintext = 'Hello world';
  const ciphertext = await encrypt(key, utils.utf8ToBytes(plaintext));
  const plaintext2 = await decrypt(key, ciphertext);
  assert.equal(utils.bytesToUtf8(plaintext2), plaintext);
  return true;
});

should.run();
