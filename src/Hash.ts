import * as crypto from 'crypto';

// Interleaved entropy table used by tabulation hash function:
let TABLE = ((): Int32Array => {
  let word = 4;
  let table = new Int32Array(64 * 256 * 2);
  let buffer = crypto.randomBytes(table.length * word);
  for (let index = 0, length = table.length; index < length; index++) {
    table[index] = buffer.readInt32LE(index * word);
  }
  return table;
})();

// Hashes assigned by Hash() instead of using multiple return destructuring:
// We want to avoid allocating millions of objects just to return 2 hashes.
export let H1 = 0;
export let H2 = 0;

export function Hash(
  key: Buffer,
  keyOffset: number,
  keySize: number
): void {
  // Assigning to a local variable is faster than to a global variable:
  let h1 = 0;
  let h2 = 0;
  let i = 0;
  while (i < keySize) {
    // Minimize cache misses by interleaving both tables into a single table:
    // Minimize letiable assignments by reusing k as an index into TABLE:
    // Unrolled to process 4 bytes at a time:
    h1 ^= (
      TABLE[(((i << 1) + 0) << 8) + key[keyOffset + i + 0]] ^
      TABLE[(((i << 1) + 1) << 8) + key[keyOffset + i + 1]] ^
      TABLE[(((i << 1) + 2) << 8) + key[keyOffset + i + 2]] ^
      TABLE[(((i << 1) + 3) << 8) + key[keyOffset + i + 3]]
    );
    h2 ^= (
      TABLE[(((i << 1) + 4) << 8) + key[keyOffset + i + 0]] ^
      TABLE[(((i << 1) + 5) << 8) + key[keyOffset + i + 1]] ^
      TABLE[(((i << 1) + 6) << 8) + key[keyOffset + i + 2]] ^
      TABLE[(((i << 1) + 7) << 8) + key[keyOffset + i + 3]]
    );
    i += 4;
  }
  H1 = h1;
  H2 = h2;
}
