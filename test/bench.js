import * as bench from 'micro-bmark';
import * as crypto from 'node:crypto';
import { AES as aes } from '../siv.js';

const KEY16 = new Uint8Array(16);
const KEY32 = new Uint8Array(32);
const NONCE = new Uint8Array(12);
const AAD = new Uint8Array(0);

const TESTS = {
  Encrypt: {
    'node-128-gcm': (buf) => {
      const c = crypto.createCipheriv('aes-128-gcm', KEY16, KEY16);
      c.update(buf);
      return c.final();
    },
    'node-256-gcm': (buf) => {
      const c = crypto.createCipheriv('aes-256-gcm', KEY32, KEY16);
      c.update(buf);
      return c.final();
    },
    'micro-aes-128-gcm-siv': async (buf) => await (await aes(KEY16, NONCE)).encrypt(buf, AAD),
    'micro-aes-256-gcm-siv': async (buf) => await (await aes(KEY32, NONCE)).encrypt(buf, AAD),
  },
};

// buffer title, sample count, data
const buffers = {
  '32B': [20000, new Uint8Array(32).fill(1)],
  '64B': [20000, new Uint8Array(64).fill(1)],
  '1KB': [5000, new Uint8Array(1024).fill(2)],
  '8KB': [625, new Uint8Array(1024 * 8).fill(3)],
  // // Slow, but 100 doesn't show difference, probably opt doesn't happen or something
  '1MB': [25, new Uint8Array(1024 * 1024).fill(4)],
};

const main = () =>
  bench.run(async () => {
    for (let [k, libs] of Object.entries(TESTS)) {
      console.log(`==== ${k} ====`);
      for (const [size, [samples, buf]] of Object.entries(buffers)) {
        for (const [lib, fn] of Object.entries(libs)) {
          let title = `${k} ${size} ${lib}`;
          await bench.mark(title, samples, () => fn(buf));
        }
      }
    }
    // Log current RAM
    bench.utils.logMem();
  });

main();